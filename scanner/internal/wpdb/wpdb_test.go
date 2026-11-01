package wpdb

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestParseCronHooks(t *testing.T) {
	v := `a:3:{i:1730000000;a:1:{s:16:"wp_version_check";a:1:{s:32:"40cd750bba9870f18aada2478b24840a";a:3:{s:8:"schedule";s:10:"twicedaily";s:4:"args";a:0:{}s:8:"interval";i:43200;}}}i:1730003600;a:1:{s:23:"wp_update_plugins_check";a:1:{s:32:"40cd750bba9870f18aada2478b24840a";a:3:{s:8:"schedule";s:6:"hourly";s:4:"args";a:0:{}s:8:"interval";i:3600;}}}s:7:"version";i:2;}`
	got := ParseCronHooks(v)
	want := []string{"wp_update_plugins_check", "wp_version_check"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if fs := UnknownCron(got); len(fs) != 1 || fs[0].Where != "cron: wp_update_plugins_check" {
		t.Fatalf("unknown cron: %+v", fs)
	}
}

func TestCheckOption(t *testing.T) {
	spam := base64.StdEncoding.EncodeToString([]byte(`<div style="position:absolute;left:-9999px"><a href="https://royal-spin-casino.example/">casino</a></div>`))
	if f, ok := CheckOption("wpch_blocks", spam); !ok || f.Check != "option-encoded" {
		t.Fatalf("encoded spam not caught: %+v", f)
	}
	if f, ok := CheckOption("wpch_core", "<?php echo 1;"); !ok || f.Check != "option-code" {
		t.Fatalf("plain php not caught: %+v", f)
	}
	// Serialized widget settings are long but harmless.
	if _, ok := CheckOption("widget_block", `a:2:{i:2;a:1:{s:7:"content";s:40:"<!-- wp:search /--> <p>Search the site</p>";}s:12:"_multiwidget";i:1;}`); ok {
		t.Fatal("false positive on widget settings")
	}
}

func TestHiddenHrefs(t *testing.T) {
	c := `<p>Visible <a href="https://dentist.example/">ok</a></p>
<div style="display:none"><a href="https://royal-spin-casino.example/">canli casino</a></div>`
	got := HiddenHrefs(c)
	if !reflect.DeepEqual(got, []string{"https://royal-spin-casino.example/"}) {
		t.Fatalf("got %v", got)
	}
}
