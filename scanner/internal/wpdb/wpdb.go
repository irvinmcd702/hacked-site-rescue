// Package wpdb reads what an attacker leaves in the WordPress database:
// administrators, scheduled tasks, stashed code and hidden links.
package wpdb

import (
	"database/sql"
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/find"
)

type DB struct {
	db     *sql.DB
	prefix string
}

func New(db *sql.DB, prefix string) *DB { return &DB{db: db, prefix: prefix} }

func (d *DB) t(name string) string { return d.prefix + name }

type Admin struct {
	Login      string
	Email      string
	Registered string
}

// Admins lists every account that holds the administrator role in the database,
// whatever the admin screens choose to show.
func (d *DB) Admins() ([]Admin, error) {
	rows, err := d.db.Query(fmt.Sprintf(
		`SELECT u.user_login, u.user_email, u.user_registered FROM %s u
		 JOIN %s m ON m.user_id = u.ID AND m.meta_key = ?
		 WHERE m.meta_value LIKE '%%"administrator"%%' ORDER BY u.user_registered`,
		d.t("users"), d.t("usermeta")), d.t("capabilities"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Admin
	for rows.Next() {
		var a Admin
		if err := rows.Scan(&a.Login, &a.Email, &a.Registered); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// coreHooks are cron events WordPress core schedules by itself.
var coreHooks = map[string]bool{
	"wp_version_check": true, "wp_update_plugins": true, "wp_update_themes": true,
	"wp_scheduled_delete": true, "wp_scheduled_auto_draft_delete": true,
	"delete_expired_transients": true, "wp_privacy_delete_old_export_files": true,
	"recovery_mode_clean_expired_keys": true, "wp_site_health_scheduled_check": true,
	"wp_https_detection": true, "wp_update_user_counts": true,
	"wp_delete_temp_updater_backups": true, "wp_batch_split_terms": true,
	"wp_split_shared_term_batch": true, "wp_maybe_auto_update": true,
	"do_pings": true, "publish_future_post": true, "importer_scheduled_cleanup": true,
	"upgrader_scheduled_cleanup": true, "wp_privacy_personal_data_cleanup_requests": true,
	"wp_update_comment_type_batch": true,
}

// Hook names are the keys whose values are maps of 32-char event signatures.
var cronHookRe = regexp.MustCompile(`s:\d+:"([A-Za-z0-9_\-\.]+)";a:\d+:\{s:32:"`)

// CronHooks returns the hooks scheduled in the cron option.
func (d *DB) CronHooks() ([]string, error) {
	var v string
	err := d.db.QueryRow(fmt.Sprintf("SELECT option_value FROM %s WHERE option_name = 'cron'", d.t("options"))).Scan(&v)
	if err != nil {
		return nil, err
	}
	return ParseCronHooks(v), nil
}

func ParseCronHooks(serialized string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range cronHookRe.FindAllStringSubmatch(serialized, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// UnknownCron reports scheduled hooks that core does not use. Plugins add
// their own, so this is a prompt to identify each, not proof of infection.
func UnknownCron(hooks []string) []find.Finding {
	var out []find.Finding
	for _, h := range hooks {
		if coreHooks[h] {
			continue
		}
		out = append(out, find.Finding{
			Check:    "cron-unknown",
			Severity: find.Medium,
			Title:    "Scheduled task that WordPress core does not create",
			Where:    "cron: " + h,
			Why:      "Infections often schedule themselves to come back after cleanup. Every non-core task should be traced to the plugin or theme that registers it.",
		})
	}
	return out
}

var (
	longB64  = regexp.MustCompile(`^[A-Za-z0-9+/=\s]{80,}$`)
	badInB64 = regexp.MustCompile(`(?i)<\?php|<script|<a\s+href|eval\s*\(|base64_decode|casino|bahis|bonus`)
)

// SuspiciousOptions finds settings that hold code or encoded markup.
func (d *DB) SuspiciousOptions() ([]find.Finding, error) {
	rows, err := d.db.Query(fmt.Sprintf(
		`SELECT option_name, option_value FROM %s
		 WHERE option_name NOT IN ('cron','rewrite_rules') AND LENGTH(option_value) > 60`, d.t("options")))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []find.Finding
	for rows.Next() {
		var name, val string
		if err := rows.Scan(&name, &val); err != nil {
			return nil, err
		}
		if f, ok := CheckOption(name, val); ok {
			out = append(out, f)
		}
	}
	return out, rows.Err()
}

func CheckOption(name, val string) (find.Finding, bool) {
	trimmed := strings.TrimSpace(val)
	if strings.Contains(trimmed, "<?php") {
		return find.Finding{
			Check: "option-code", Severity: find.Critical,
			Title: "PHP code stored in a setting", Where: "option: " + name,
			Why:      "Settings hold configuration, not code. PHP in an option is a spare copy kept for reinstalling the infection.",
			Evidence: []string{clip(trimmed, 120)},
		}, true
	}
	if longB64.MatchString(trimmed) {
		dec, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(trimmed), ""))
		if err == nil && badInB64.Match(dec) {
			return find.Finding{
				Check: "option-encoded", Severity: find.Critical,
				Title: "Encoded code or spam stored in a setting", Where: "option: " + name,
				Why:      "The value is base64 that decodes to code or links. Nothing legitimate needs to hide this way.",
				Evidence: []string{"decodes to: " + clip(strings.Join(strings.Fields(string(dec)), " "), 160)},
			}, true
		}
	}
	return find.Finding{}, false
}

var (
	hiddenBlock = regexp.MustCompile(`(?is)<(div|span|p)[^>]*style\s*=\s*["'][^"']*(display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-\d{3,}px)[^"']*["'][^>]*>(.*?)</(div|span|p)>`)
	hrefRe      = regexp.MustCompile(`(?i)href\s*=\s*["']([^"']+)["']`)
)

// HiddenLinks finds links in post content that visitors cannot see but
// search engines read.
func (d *DB) HiddenLinks() ([]find.Finding, error) {
	rows, err := d.db.Query(fmt.Sprintf(
		`SELECT ID, post_type, post_name, post_content FROM %s
		 WHERE post_status IN ('publish','private','draft','future') AND post_content LIKE '%%href%%'`, d.t("posts")))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []find.Finding
	for rows.Next() {
		var id int
		var typ, slug, content string
		if err := rows.Scan(&id, &typ, &slug, &content); err != nil {
			return nil, err
		}
		if links := HiddenHrefs(content); len(links) > 0 {
			out = append(out, find.Finding{
				Check: "post-hidden-links", Severity: find.High,
				Title: "Invisible links inside content", Where: fmt.Sprintf("%s #%d (%s)", typ, id, slug),
				Why:      "Links wrapped in a hidden block are not for readers; they are planted to pass search ranking to someone else's site.",
				Evidence: links,
			})
		}
	}
	return out, rows.Err()
}

func HiddenHrefs(content string) []string {
	var out []string
	for _, b := range hiddenBlock.FindAllStringSubmatch(content, -1) {
		for _, h := range hrefRe.FindAllStringSubmatch(b[3], -1) {
			out = append(out, h[1])
		}
	}
	return out
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
