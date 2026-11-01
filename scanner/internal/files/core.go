package files

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/find"
)

var versionRe = regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`)

// Version reads the installed WordPress version from wp-includes/version.php.
func Version(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "wp-includes", "version.php"))
	if err != nil {
		return "", err
	}
	m := versionRe.FindSubmatch(b)
	if m == nil {
		return "", fmt.Errorf("no $wp_version in version.php")
	}
	return string(m[1]), nil
}

// FetchChecksums asks wordpress.org for the md5 of every file in a release.
func FetchChecksums(version, locale string) (map[string]string, error) {
	url := fmt.Sprintf("https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s", version, locale)
	c := http.Client{Timeout: 20 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var body struct {
		Checksums map[string]string `json:"checksums"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("checksums for %s: %w", version, err)
	}
	if len(body.Checksums) == 0 {
		return nil, fmt.Errorf("wordpress.org has no checksums for %s/%s", version, locale)
	}
	return body.Checksums, nil
}

// knownExtra are files the official package does not ship but which are
// normal on a working site.
var knownExtra = map[string]bool{
	"wp-config.php":        true,
	"wp-config-docker.php": true, // the official Docker image adds it
	".htaccess":            true,
}

// VerifyCore compares core files with the release checksums: changed files,
// and files nobody shipped inside wp-admin and wp-includes.
func VerifyCore(root string, sums map[string]string) ([]find.Finding, error) {
	var out []find.Finding
	paths := make([]string, 0, len(sums))
	for p := range sums {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, rel := range paths {
		if strings.HasPrefix(rel, "wp-content/") {
			continue // themes and plugins bundled with core get updated separately
		}
		got, err := md5File(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			continue // a missing core file breaks the site loudly; not our concern here
		}
		if got != sums[rel] {
			out = append(out, find.Finding{
				Check:    "core-modified",
				Severity: find.Critical,
				Title:    "WordPress core file differs from the official release",
				Where:    rel,
				Why:      "Core files are identical on every site running the same version. A changed one means someone edited WordPress itself, usually to load their code on every request.",
				Evidence: append([]string{"md5 " + got + ", expected " + sums[rel]}, changedHint(rel, filepath.Join(root, filepath.FromSlash(rel)))...),
			})
		}
	}

	for _, dir := range []string{"wp-admin", "wp-includes"} {
		filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel := relPath(root, p)
			if _, ok := sums[rel]; !ok {
				out = append(out, find.Finding{
					Check:    "core-extra",
					Severity: find.High,
					Title:    "File inside WordPress core folders that the release does not contain",
					Where:    rel,
					Why:      "Nothing but WordPress itself should live in wp-admin and wp-includes; extra files there are hidden in plain sight.",
				})
			}
			return nil
		})
	}

	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || knownExtra[name] || !phpExt[strings.ToLower(filepath.Ext(name))] {
			continue
		}
		if _, ok := sums[name]; !ok {
			out = append(out, find.Finding{
				Check:    "core-extra",
				Severity: find.High,
				Title:    "Unknown PHP file in the site root",
				Where:    name,
				Why:      "The site root holds a fixed set of WordPress files; an extra PHP file there can be called directly from the web.",
			})
		}
	}
	return out, nil
}

// changedHint points at the suspicious lines of a modified core file, or at
// its last lines when no rule matches: injected code is most often appended.
func changedHint(rel, p string) []string {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var out []string
	for _, f := range matchRules(rel, b) {
		out = append(out, f.Evidence...)
	}
	if len(out) > 0 {
		return out
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i := len(lines) - 1; i >= 0 && len(out) < 2; i-- {
		if s := strings.TrimSpace(lines[i]); s != "" {
			out = append([]string{lineRef(i+1, s)}, out...)
		}
	}
	return out
}

func md5File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
