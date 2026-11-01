// Package accesslog reads a web server log the way you would after a break-in:
// who guessed passwords, who got in, what they touched first.
package accesslog

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/find"
)

type Entry struct {
	IP     string
	Time   time.Time
	Method string
	Path   string
	Status int
	UA     string
}

// Combined log format, as written by Apache and nginx by default.
var lineRe = regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"`)

func Parse(r io.Reader) ([]Entry, error) {
	var out []Entry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		m := lineRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
		if err != nil {
			continue
		}
		var st int
		fmt.Sscanf(m[5], "%d", &st)
		out = append(out, Entry{IP: m[1], Time: t.UTC(), Method: m[3], Path: m[4], Status: st, UA: m[6]})
	}
	return out, sc.Err()
}

const bruteThreshold = 5

var (
	uploadsPHP = regexp.MustCompile(`(?i)^/wp-content/uploads/.*\.(php\d?|phtml|phar)(\?|$)`)
	ajaxAction = regexp.MustCompile(`^/wp-admin/admin-ajax\.php\?(?:.*&)?action=([^&]+)`)
)

// Analyze looks for the usual sequence of a break-in and returns findings
// plus a timeline of everything the suspicious addresses did.
func Analyze(entries []Entry) ([]find.Finding, []Entry) {
	var out []find.Finding
	suspects := map[string]bool{}

	failed := map[string][]Entry{}
	for _, e := range entries {
		if e.Method == "POST" && strings.HasPrefix(e.Path, "/wp-login.php") && e.Status == 200 {
			failed[e.IP] = append(failed[e.IP], e)
		}
	}
	for ip, fs := range failed {
		if len(fs) < bruteThreshold {
			continue
		}
		suspects[ip] = true
		out = append(out, find.Finding{
			Check:    "log-bruteforce",
			Severity: find.High,
			Title:    fmt.Sprintf("Password guessing from %s", ip),
			Where:    "access log",
			Why:      "Repeated failed logins in a short time from one address is a password-guessing run.",
			Evidence: []string{fmt.Sprintf("%d failed logins between %s and %s", len(fs), stamp(fs[0].Time), stamp(fs[len(fs)-1].Time))},
		})
	}

	for _, e := range entries {
		if uploadsPHP.MatchString(e.Path) && e.Status < 400 {
			suspects[e.IP] = true
			out = append(out, find.Finding{
				Check:    "log-uploads-php",
				Severity: find.Critical,
				Title:    "A PHP file in uploads was requested and answered",
				Where:    "access log",
				Why:      "The server executed a script from the uploads folder. That is the backdoor being used.",
				Evidence: []string{describe(e)},
			})
		}
	}

	for _, e := range entries {
		if !suspects[e.IP] {
			continue
		}
		switch {
		case e.Method == "POST" && strings.HasPrefix(e.Path, "/wp-login.php") && e.Status == 302:
			out = append(out, find.Finding{
				Check: "log-login", Severity: find.Critical,
				Title: "Successful login from an attacking address", Where: "access log",
				Why:      "The same address that guessed passwords or used the backdoor then logged in.",
				Evidence: []string{describe(e)},
			})
		case ajaxAction.MatchString(e.Path) && e.Method == "POST":
			out = append(out, find.Finding{
				Check: "log-entry-point", Severity: find.High,
				Title: "Plugin endpoint called by the attacker just before the backdoor appeared", Where: "access log",
				Why:      "The first request from the attacking address that changed something is the likely way in.",
				Evidence: []string{describe(e), "action: " + ajaxAction.FindStringSubmatch(e.Path)[1]},
			})
		case strings.HasPrefix(e.Path, "/wp-admin/theme-editor.php") || strings.HasPrefix(e.Path, "/wp-admin/plugin-editor.php"):
			if e.Method == "POST" {
				out = append(out, find.Finding{
					Check: "log-file-edit", Severity: find.High,
					Title: "Theme or plugin file edited from the dashboard", Where: "access log",
					Why:      "The built-in file editor was used by the attacking address to change code.",
					Evidence: []string{describe(e)},
				})
			}
		}
	}

	var timeline []Entry
	for _, e := range entries {
		if suspects[e.IP] {
			timeline = append(timeline, e)
		}
	}
	return out, timeline
}

func stamp(t time.Time) string { return t.Format("2006-01-02 15:04:05") + " UTC" }

func describe(e Entry) string {
	return fmt.Sprintf("%s %s %s %s → %d", stamp(e.Time), e.IP, e.Method, e.Path, e.Status)
}
