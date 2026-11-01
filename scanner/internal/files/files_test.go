package files

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func checks(t *testing.T, path string) map[string]bool {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range matchRules(filepath.Base(path), src) {
		got[strings.TrimPrefix(f.Check, "code:")] = true
	}
	return got
}

// The lab payloads are the ground truth: each must trip the rules it was built to show.
func TestLabPayloads(t *testing.T) {
	dir := "../../../lab/infect/payloads"
	cases := map[string][]string{
		"cache-helper.php":  {"cloaking", "obfuscated-decoder"},
		"thumb-cache.php":   {"obfuscated-decoder", "request-gated"},
		"theme-snippet.php": {"hidden-user", "self-restore"},
	}
	for file, want := range cases {
		got := checks(t, filepath.Join(dir, file))
		for _, w := range want {
			if !got[w] {
				t.Errorf("%s: rule %s did not fire (got %v)", file, w, got)
			}
		}
	}
}

func TestOrdinaryPluginIsQuiet(t *testing.T) {
	src := []byte(`<?php
add_shortcode('simple_gallery', function ($atts) {
    $ids = array_filter(array_map('absint', explode(',', $_GET['ids'] ?? '')));
    if (is_user_logged_in()) { echo esc_html(wp_get_current_user()->display_name); }
    return wp_get_attachment_image($ids[0], 'medium');
});`)
	if fs := matchRules("plugin.php", src); len(fs) != 0 {
		t.Fatalf("false positives: %+v", fs)
	}
}

func TestIncludeFromUploads(t *testing.T) {
	src := []byte("<?php\nif (defined('ABSPATH')) { @include_once ABSPATH . 'wp-content/uploads/2025/03/thumb-cache.php'; }\n")
	fs := matchRules("general-template.php", src)
	if len(fs) != 1 || fs[0].Check != "code:include-from-uploads" {
		t.Fatalf("got %+v", fs)
	}
	if !strings.Contains(fs[0].Evidence[0], "line 2") {
		t.Fatalf("evidence should point at the line: %v", fs[0].Evidence)
	}
}

func TestVerifyCore(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) string {
		p := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(body), 0o644)
		h := md5.Sum([]byte(body))
		return hex.EncodeToString(h[:])
	}
	sums := map[string]string{
		"index.php":                        write("index.php", "<?php // index"),
		"wp-includes/general-template.php": write("wp-includes/general-template.php", "<?php // original"),
	}
	// Tamper after recording the checksum, and drop extras where they don't belong.
	write("wp-includes/general-template.php", "<?php // original\n@include 'x.php';\n")
	write("wp-includes/class-wp-cache.php", "<?php // not shipped")
	write("wp-config.php", "<?php // fine")
	write("shell.php", "<?php // not fine")

	fs, err := VerifyCore(root, sums)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range fs {
		got[f.Where] = f.Check
	}
	want := map[string]string{
		"wp-includes/general-template.php": "core-modified",
		"wp-includes/class-wp-cache.php":   "core-extra",
		"shell.php":                        "core-extra",
	}
	for where, check := range want {
		if got[where] != check {
			t.Errorf("%s: want %s, got %q", where, check, got[where])
		}
	}
	if len(got) != len(want) {
		t.Errorf("unexpected findings: %v", got)
	}
}
