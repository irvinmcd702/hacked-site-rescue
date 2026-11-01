// Package files checks the WordPress tree on disk: core integrity, code where
// it should not be, and code that looks like it was written to hide.
package files

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/find"
)

var phpExt = map[string]bool{".php": true, ".phtml": true, ".php5": true, ".php7": true, ".phar": true, ".inc": true}

// Scan walks wp-content. Core files are checked separately against the
// official checksums, so they are skipped here.
func Scan(root string) ([]find.Finding, error) {
	var out []find.Finding
	content := filepath.Join(root, "wp-content")

	err := filepath.WalkDir(content, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are not evidence either way
		}
		if d.IsDir() {
			return nil
		}
		rel := relPath(root, p)
		if !phpExt[strings.ToLower(filepath.Ext(p))] {
			return nil
		}
		info, _ := d.Info()

		if strings.HasPrefix(rel, "wp-content/uploads/") {
			out = append(out, find.Finding{
				Check:    "php-in-uploads",
				Severity: find.Critical,
				Title:    "PHP file in the uploads folder",
				Where:    rel,
				Why:      "Uploads should only hold media and documents. A PHP file there runs as code when requested, which is the classic place to leave a backdoor.",
				Evidence: []string{"modified " + mtime(info)},
			})
		}
		if strings.HasPrefix(rel, "wp-content/mu-plugins/") {
			out = append(out, find.Finding{
				Check:    "mu-plugin",
				Severity: find.Medium,
				Title:    "Must-use plugin present",
				Where:    rel,
				Why:      "Must-use plugins load on every request and do not appear in the normal plugins list, so the owner rarely knows they exist. Each one needs an owner who can say what it is.",
				Evidence: []string{"modified " + mtime(info)},
			})
		}

		src, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		out = append(out, matchRules(rel, src)...)
		return nil
	})
	return out, err
}

// relPath gives a forward-slash path relative to the site root on any OS.
func relPath(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return filepath.ToSlash(p)
	}
	return filepath.ToSlash(rel)
}

func mtime(info fs.FileInfo) string {
	if info == nil {
		return "unknown"
	}
	return info.ModTime().UTC().Format(time.DateTime) + " UTC"
}
