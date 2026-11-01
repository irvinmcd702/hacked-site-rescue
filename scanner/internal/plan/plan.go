// Package plan turns scan findings into cleanup steps: what to remove, what to
// replace with a clean copy, and what to rotate so the attacker's access ends.
// Each step says why; anything that can't be decided from the evidence is left
// as a manual step instead of a guess.
package plan

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/find"
)

type Step struct {
	Title  string
	Why    string
	Cmds   []string
	Manual bool
}

type Options struct {
	Root     string // WordPress files, for tracing hooks and endpoints back to code
	Version  string // installed core version, to fetch the same release
	Owner    string // login of the real administrator, who keeps the content
	BackupTo string // directory for the backup taken before any change
	// IsPublic reports whether a theme or plugin slug can be reinstalled from
	// wordpress.org. Nil means "unknown", which makes those steps manual.
	IsPublic func(kind, slug string) bool
}

var (
	themeRe  = regexp.MustCompile(`^wp-content/themes/([^/]+)/`)
	pluginRe = regexp.MustCompile(`^wp-content/plugins/([^/]+)/`)
	actionRe = regexp.MustCompile(`^action: (\S+)$`)
	postRe   = regexp.MustCompile(`#(\d+)`)
)

func Build(fs []find.Finding, o Options) []Step {
	var steps []Step
	add := func(s Step) { steps = append(steps, s) }

	add(Step{
		Title: "Back up files and database before touching anything",
		Why:   "If a step removes something the site needed, it can be put back. The backup also preserves the evidence.",
		Cmds: []string{
			fmt.Sprintf(`stamp=$(date +%%Y%%m%%d-%%H%%M%%S); mkdir -p %s/$stamp`, o.BackupTo),
			fmt.Sprintf(`wp db export %s/$stamp/db.sql`, o.BackupTo),
			fmt.Sprintf(`tar -czf %s/$stamp/files.tgz -C /var/www/html .`, o.BackupTo),
		},
	})

	bad := map[string]bool{} // files with malicious code
	for _, f := range fs {
		if strings.HasPrefix(f.Check, "code:") || f.Check == "php-in-uploads" {
			bad[f.Where] = true
		}
	}

	// Files that exist only because of the attacker.
	var del []string
	for _, f := range fs {
		switch {
		case f.Check == "php-in-uploads":
			del = append(del, f.Where)
		case f.Check == "mu-plugin" && bad[f.Where]:
			del = append(del, f.Where)
		case f.Check == "core-extra":
			del = append(del, f.Where)
		}
	}
	if del = uniq(del); len(del) > 0 {
		var cmds []string
		for _, p := range del {
			cmds = append(cmds, "rm -f "+shq(p))
		}
		add(Step{
			Title: "Delete files that the attacker added",
			Why:   "Backdoors, injectors and stray scripts are not part of any release. Deleting them is safe; a clean site does not reference them.",
			Cmds:  cmds,
		})
	}
	for _, f := range fs {
		if f.Check == "mu-plugin" && !bad[f.Where] {
			add(Step{Title: "Identify must-use plugin " + f.Where, Why: "No malicious code was found in it, but somebody has to say what it is for before it stays.", Manual: true})
		}
	}

	// Core.
	for _, f := range fs {
		if f.Check == "core-modified" {
			add(Step{
				Title: "Replace WordPress core with a clean copy of the same version",
				Why:   "Core was edited to load the attacker's code. Downloading the same release over it restores every core file without touching content, themes or plugins.",
				Cmds:  []string{fmt.Sprintf("wp core download --force --skip-content --version=%s", o.Version), "wp core verify-checksums"},
			})
			break
		}
	}

	// Themes and plugins with injected code: reinstall when a clean copy exists.
	reinstall := map[string]map[string]bool{"theme": {}, "plugin": {}}
	for p := range bad {
		if m := themeRe.FindStringSubmatch(p); m != nil {
			reinstall["theme"][m[1]] = true
		}
		if m := pluginRe.FindStringSubmatch(p); m != nil {
			reinstall["plugin"][m[1]] = true
		}
	}
	for _, kind := range []string{"theme", "plugin"} {
		for _, slug := range keys(reinstall[kind]) {
			if o.IsPublic != nil && o.IsPublic(kind, slug) {
				add(Step{
					Title: fmt.Sprintf("Reinstall %s %s from wordpress.org", kind, slug),
					Why:   "Its files were modified. A fresh copy of the same item replaces them all, including changes the scan did not flag.",
					Cmds:  []string{fmt.Sprintf("wp %s install %s --force", kind, slug)},
				})
			} else {
				add(Step{
					Title:  fmt.Sprintf("Clean %s %s by hand", kind, slug),
					Why:    "It is not available from wordpress.org, so there is no clean copy to reinstall. Compare it with the vendor's package or the last good backup.",
					Manual: true,
				})
			}
		}
	}

	// Database.
	var opts []string
	for _, f := range fs {
		if f.Check == "option-code" || f.Check == "option-encoded" {
			opts = append(opts, strings.TrimPrefix(f.Where, "option: "))
		}
	}
	if opts = uniq(opts); len(opts) > 0 {
		var cmds []string
		for _, n := range opts {
			cmds = append(cmds, "wp option delete "+shq(n))
		}
		add(Step{Title: "Delete settings that hold the attacker's payloads", Why: "These are the spare copies used to rebuild the infection.", Cmds: cmds})
	}

	for _, f := range fs {
		if f.Check != "cron-unknown" {
			continue
		}
		hook := strings.TrimPrefix(f.Where, "cron: ")
		if referencedIn(o.Root, bad, hook) {
			add(Step{
				Title: "Unschedule task " + hook,
				Why:   "It is registered by the malicious code and is what brings the infection back after cleanup.",
				Cmds:  []string{"wp cron event delete " + shq(hook)},
			})
		} else {
			add(Step{Title: "Identify scheduled task " + hook, Why: "Not core, and not traced to malicious code. Find the plugin that registers it.", Manual: true})
		}
	}

	for _, f := range fs {
		if f.Check != "hidden-admin" {
			continue
		}
		login := strings.TrimPrefix(f.Where, "user ")
		if o.Owner == "" {
			add(Step{Title: "Delete hidden administrator " + login, Why: "Pass -owner so its content can be reassigned.", Manual: true})
			continue
		}
		add(Step{
			Title: "Delete hidden administrator " + login,
			Why:   "An account the owner never created and could not see. Anything it published is handed to the owner rather than deleted.",
			Cmds:  []string{fmt.Sprintf("wp user delete %s --reassign=$(wp user get %s --field=ID) --yes", shq(login), shq(o.Owner))},
		})
	}

	var posts []string
	for _, f := range fs {
		if f.Check == "post-hidden-links" {
			if m := postRe.FindStringSubmatch(f.Where); m != nil {
				posts = append(posts, m[1])
			}
		}
	}
	if posts = uniq(posts); len(posts) > 0 {
		var cmds []string
		for _, id := range posts {
			cmds = append(cmds, fmt.Sprintf(`wp eval '$p = get_post(%s); $c = preg_replace("~<(div|span|p)[^>]*style\\s*=\\s*[\"\x27][^\"\x27]*(display\\s*:\\s*none|visibility\\s*:\\s*hidden|left\\s*:\\s*-\\d{3,}px)[^\"\x27]*[\"\x27][^>]*>.*?</(div|span|p)>~is", "", $p->post_content); wp_update_post(["ID" => %s, "post_content" => $c]); echo "post %s cleaned\n";'`, id, id, id))
		}
		add(Step{Title: "Remove invisible links from content", Why: "Only the hidden blocks are removed; the visible text of each post stays as it was.", Cmds: cmds})
	}

	// The way in.
	for _, f := range fs {
		if f.Check != "log-entry-point" {
			continue
		}
		for _, e := range f.Evidence {
			m := actionRe.FindStringSubmatch(e)
			if m == nil {
				continue
			}
			if slug := pluginForAction(o.Root, m[1]); slug != "" {
				add(Step{
					Title: "Remove plugin " + slug + ", the way in",
					Why:   fmt.Sprintf("The attacker's first change came through its %q endpoint, which accepts requests without a login. Until a fixed version exists it stays off the site.", m[1]),
					Cmds:  []string{"wp plugin deactivate " + shq(slug), "wp plugin delete " + shq(slug)},
				})
			} else {
				add(Step{Title: "Find what handles " + m[1], Why: "The attacker's first change came through this endpoint.", Manual: true})
			}
		}
	}

	add(Step{
		Title: "End every session and lock the doors that were used",
		Why:   "New salts sign everyone out, including the attacker. File editing from the dashboard is switched off, and PHP can no longer run from uploads.",
		Cmds: []string{
			"wp config shuffle-salts",
			"wp config set DISALLOW_FILE_EDIT true --raw",
			`printf '<FilesMatch "\\.(php|phtml|phar|php[0-9])$">\n  Require all denied\n</FilesMatch>\n' > wp-content/uploads/.htaccess`,
		},
	})
	add(Step{
		Title:  "Owner sets a new password; change hosting, database and email passwords",
		Why:    "The attacker had administrator access and could have read anything stored in WordPress.",
		Manual: true,
	})
	return steps
}

// Script renders the automatic steps as a shell script to run inside the
// WordPress directory with WP-CLI available.
func Script(steps []Step) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n# Generated by rescue plan. Review before running.\nset -eu\ncd /var/www/html\n\n")
	n := 0
	for _, s := range steps {
		n++
		if s.Manual {
			fmt.Fprintf(&b, "# %d. MANUAL: %s\n#    %s\n\n", n, s.Title, s.Why)
			continue
		}
		fmt.Fprintf(&b, "# %d. %s\n#    %s\necho '== %d. %s'\n", n, s.Title, s.Why, n, strings.ReplaceAll(s.Title, "'", ""))
		for _, c := range s.Cmds {
			b.WriteString(c + "\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}

// Markdown renders the plan for the owner.
func Markdown(steps []Step) string {
	var b strings.Builder
	b.WriteString("# Cleanup plan\n\n")
	for i, s := range steps {
		tag := ""
		if s.Manual {
			tag = " *(manual)*"
		}
		fmt.Fprintf(&b, "%d. **%s**%s — %s\n", i+1, s.Title, tag, s.Why)
	}
	return b.String()
}

func referencedIn(root string, files map[string]bool, needle string) bool {
	for p := range files {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if err == nil && strings.Contains(string(b), needle) {
			return true
		}
	}
	return false
}

func pluginForAction(root, action string) string {
	dir := filepath.Join(root, "wp-content", "plugins")
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		found := false
		filepath.WalkDir(filepath.Join(dir, e.Name()), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".php") || found {
				return nil
			}
			if b, err := os.ReadFile(p); err == nil && strings.Contains(string(b), "wp_ajax_nopriv_"+action) {
				found = true
			}
			return nil
		})
		if found {
			return e.Name()
		}
	}
	return ""
}

// shq quotes a value for a POSIX shell.
func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
