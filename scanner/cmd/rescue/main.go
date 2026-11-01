// Command rescue scans a WordPress site for signs of compromise. It reads
// files, the database, live pages and the access log, and changes nothing.
package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/accesslog"
	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/files"
	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/find"
	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/report"
	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/views"
	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/wpdb"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "plan":
			runPlan(os.Args[2:])
			return
		case "report":
			runReport(os.Args[2:])
			return
		}
	}
	root := flag.String("root", "", "WordPress directory")
	dsn := flag.String("db", os.Getenv("RESCUE_DB"), "MySQL DSN, user:pass@tcp(host:3306)/name")
	site := flag.String("url", "", "site URL for the live checks")
	logPath := flag.String("log", "", "access log in combined format")
	sumsFile := flag.String("checksums", "", "core checksums JSON (default: fetch from wordpress.org)")
	outDir := flag.String("out", ".", "where to write report.md and findings.json")
	pages := flag.String("pages", "/", "comma-separated paths to compare across viewers")
	flag.Parse()
	if *root == "" {
		fmt.Fprintln(os.Stderr, "usage: rescue -root /path/to/wordpress [-db DSN] [-url URL] [-log access.log]")
		os.Exit(2)
	}

	d := report.Data{Site: *site, Scanned: time.Now()}
	if d.Site == "" {
		d.Site = *root
	}
	add := func(fs []find.Finding) { d.Findings = append(d.Findings, fs...) }
	note := func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		d.Notes = append(d.Notes, msg)
		fmt.Fprintln(os.Stderr, "note:", msg)
	}

	// Files.
	if fs, err := files.Scan(*root); err != nil {
		note("file scan incomplete: %v", err)
	} else {
		add(fs)
	}
	if v, err := files.Version(*root); err != nil {
		note("core version unknown, core files not verified: %v", err)
	} else {
		d.Version = v
		sums, err := loadSums(*sumsFile, v)
		if err != nil {
			note("core files not verified: %v", err)
		} else if fs, err := files.VerifyCore(*root, sums); err == nil {
			add(fs)
		}
	}

	// Database.
	var admins []wpdb.Admin
	if *dsn != "" {
		db, err := sql.Open("mysql", *dsn)
		if err == nil {
			err = db.Ping()
		}
		if err != nil {
			note("database not checked: %v", err)
		} else {
			w := wpdb.New(db, tablePrefix(*root))
			if admins, err = w.Admins(); err != nil {
				note("administrators not listed: %v", err)
			}
			if hooks, err := w.CronHooks(); err == nil {
				add(wpdb.UnknownCron(hooks))
			}
			if fs, err := w.SuspiciousOptions(); err == nil {
				add(fs)
			}
			if fs, err := w.HiddenLinks(); err == nil {
				add(fs)
			}
			db.Close()
		}
	} else {
		note("database not checked: no -db given")
	}

	// Live site.
	if *site != "" {
		c, err := views.New(*site)
		if err == nil {
			err = c.Login(os.Getenv("RESCUE_ADMIN_USER"), os.Getenv("RESCUE_ADMIN_PASSWORD"))
		}
		if err != nil {
			note("live checks skipped: %v", err)
		} else {
			fs, seen, err := c.Compare(strings.Split(*pages, ","))
			if err != nil {
				note("page comparison failed: %v", err)
			}
			add(fs)
			d.Views = seen
			if visible, count, err := c.VisibleAdmins(); err == nil && admins != nil {
				add(hiddenAdmins(admins, visible, count))
			}
		}
	} else {
		note("live pages not checked: no -url given")
	}

	// Access log.
	if *logPath != "" {
		f, err := os.Open(*logPath)
		if err != nil {
			note("access log not read: %v", err)
		} else {
			entries, _ := accesslog.Parse(f)
			f.Close()
			fs, tl := accesslog.Analyze(entries)
			add(fs)
			d.Timeline = tl
		}
	}

	find.Sort(d.Findings)
	if err := write(*outDir, d); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	crit := 0
	for _, f := range d.Findings {
		if f.Severity == find.Critical {
			crit++
		}
	}
	fmt.Printf("%d findings (%d critical) → %s\n", len(d.Findings), crit, filepath.Join(*outDir, "report.md"))
	if crit > 0 {
		os.Exit(3)
	}
}

// hiddenAdmins compares administrators in the database with the ones the
// owner can actually see in the dashboard.
func hiddenAdmins(inDB []wpdb.Admin, visible []string, count string) []find.Finding {
	seen := map[string]bool{}
	for _, v := range visible {
		seen[v] = true
	}
	var out []find.Finding
	for _, a := range inDB {
		if seen[a.Login] {
			continue
		}
		ev := []string{fmt.Sprintf("login %s, email %s, registered %s", a.Login, a.Email, a.Registered)}
		if count != "" {
			ev = append(ev, fmt.Sprintf("the Users screen says %s administrators but lists %d", count, len(visible)))
		}
		out = append(out, find.Finding{
			Check:    "hidden-admin",
			Severity: find.Critical,
			Title:    "Administrator account hidden from the dashboard",
			Where:    "user " + a.Login,
			Why:      "The account has full control of the site but does not appear in the owner's list of users, so nobody would think to remove it.",
			Evidence: ev,
		})
	}
	return out
}

var prefixRe = regexp.MustCompile(`\$table_prefix\s*=\s*['"]([A-Za-z0-9_]+)['"]`)

func tablePrefix(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "wp-config.php"))
	if err == nil {
		if m := prefixRe.FindSubmatch(b); m != nil {
			return string(m[1])
		}
	}
	return "wp_"
}

func loadSums(path, version string) (map[string]string, error) {
	if path == "" {
		return files.FetchChecksums(version, "en_US")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var body struct {
		Checksums map[string]string `json:"checksums"`
	}
	err = json.Unmarshal(b, &body)
	return body.Checksums, err
}

func write(dir string, d report.Data) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	md, err := os.Create(filepath.Join(dir, "report.md"))
	if err != nil {
		return err
	}
	report.Markdown(md, d)
	md.Close()
	// The owner report is built later from these files, so it never needs the site again.
	for name, v := range map[string]any{
		"findings.json": d.Findings,
		"scan.json":     d,
	} {
		j, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, name), j, 0o644); err != nil {
			return err
		}
	}
	return nil
}
