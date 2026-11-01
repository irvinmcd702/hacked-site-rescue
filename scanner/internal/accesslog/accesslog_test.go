package accesslog

import (
	"os"
	"testing"
)

func TestLabLog(t *testing.T) {
	f, err := os.Open("../../../lab/infect/access.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	entries, err := Parse(f)
	if err != nil || len(entries) != 19 {
		t.Fatalf("parsed %d entries, err %v", len(entries), err)
	}
	fs, timeline := Analyze(entries)
	got := map[string]int{}
	for _, f := range fs {
		got[f.Check]++
	}
	want := map[string]int{"log-bruteforce": 1, "log-uploads-php": 2, "log-login": 1, "log-entry-point": 1, "log-file-edit": 1}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: want %d, got %d (all: %v)", k, v, got[k], got)
		}
	}
	for _, e := range timeline {
		if e.IP != "203.0.113.77" {
			t.Errorf("innocent address in timeline: %s", e.IP)
		}
	}
	if len(timeline) != 14 {
		t.Errorf("timeline has %d entries, want 14", len(timeline))
	}
}
