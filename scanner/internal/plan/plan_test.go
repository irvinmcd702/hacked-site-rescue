package plan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/find"
)

func TestBuildFromLabFindings(t *testing.T) {
	root := t.TempDir()
	put := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
	}
	put("wp-content/themes/twentytwentyfive/functions.php", "add_action('wp_update_plugins_check', ...)")
	put("wp-content/plugins/simple-gallery-lite/simple-gallery-lite.php", "add_action('wp_ajax_nopriv_sgl_upload_image', 'x');")

	fs := []find.Finding{
		{Check: "php-in-uploads", Where: "wp-content/uploads/2025/03/thumb-cache.php"},
		{Check: "code:request-gated", Where: "wp-content/uploads/2025/03/thumb-cache.php"},
		{Check: "mu-plugin", Where: "wp-content/mu-plugins/wp-cache-helper.php"},
		{Check: "code:cloaking", Where: "wp-content/mu-plugins/wp-cache-helper.php"},
		{Check: "mu-plugin", Where: "wp-content/mu-plugins/host-object-cache.php"},
		{Check: "code:self-restore", Where: "wp-content/themes/twentytwentyfive/functions.php"},
		{Check: "core-modified", Where: "wp-includes/general-template.php"},
		{Check: "option-encoded", Where: "option: wpch_blocks"},
		{Check: "option-code", Where: "option: wpch_core"},
		{Check: "cron-unknown", Where: "cron: wp_update_plugins_check"},
		{Check: "cron-unknown", Where: "cron: some_plugin_daily"},
		{Check: "hidden-admin", Where: "user wpsupport"},
		{Check: "post-hidden-links", Where: "post #7 (whitening-myths)"},
		{Check: "log-entry-point", Where: "access log", Evidence: []string{"...", "action: sgl_upload_image"}},
	}
	steps := Build(fs, Options{
		Root: root, Version: "7.1.4", Owner: "brightline", BackupTo: "/backups",
		IsPublic: func(kind, slug string) bool { return kind == "theme" && slug == "twentytwentyfive" },
	})
	script := Script(steps)

	for _, want := range []string{
		"wp db export /backups/",
		"rm -f 'wp-content/uploads/2025/03/thumb-cache.php'",
		"rm -f 'wp-content/mu-plugins/wp-cache-helper.php'",
		"wp core download --force --skip-content --version=7.1.4",
		"wp theme install twentytwentyfive --force",
		"wp option delete 'wpch_blocks'",
		"wp option delete 'wpch_core'",
		"wp cron event delete 'wp_update_plugins_check'",
		"wp user delete 'wpsupport' --reassign=$(wp user get 'brightline' --field=ID) --yes",
		"get_post(7)",
		"wp plugin delete 'simple-gallery-lite'",
		"wp config shuffle-salts",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("script lacks %q", want)
		}
	}
	// What can't be decided from the evidence must not be automated.
	for _, never := range []string{"host-object-cache.php'", "'some_plugin_daily'"} {
		if strings.Contains(script, "rm -f 'wp-content/mu-plugins/"+never) || strings.Contains(script, "cron event delete "+never) {
			t.Errorf("script acts on %s without evidence", never)
		}
	}
	if !strings.Contains(script, "MANUAL: Identify must-use plugin wp-content/mu-plugins/host-object-cache.php") ||
		!strings.Contains(script, "MANUAL: Identify scheduled task some_plugin_daily") {
		t.Errorf("unproven items should be manual steps:\n%s", script)
	}
	// Backup comes before any change.
	if strings.Index(script, "wp db export") > strings.Index(script, "rm -f") {
		t.Error("backup must be the first step")
	}
}
