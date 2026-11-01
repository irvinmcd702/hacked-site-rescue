package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/files"
	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/find"
	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/plan"
)

// runPlan reads findings.json from a scan and writes plan.sh and plan.md.
func runPlan(args []string) {
	fl := flag.NewFlagSet("plan", flag.ExitOnError)
	findingsPath := fl.String("findings", "findings.json", "findings from a scan")
	root := fl.String("root", "", "WordPress directory the scan looked at")
	owner := fl.String("owner", "", "login of the real administrator")
	backup := fl.String("backup", "/backups", "backup directory as seen where the script runs")
	out := fl.String("out", ".", "where to write plan.sh and plan.md")
	fl.Parse(args)

	b, err := os.ReadFile(*findingsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var fs []find.Finding
	if err := json.Unmarshal(b, &fs); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	version, _ := files.Version(*root)

	steps := plan.Build(fs, plan.Options{
		Root: *root, Version: version, Owner: *owner, BackupTo: *backup,
		IsPublic: onWordPressOrg,
	})
	os.MkdirAll(*out, 0o755)
	os.WriteFile(filepath.Join(*out, "plan.sh"), []byte(plan.Script(steps)), 0o755)
	os.WriteFile(filepath.Join(*out, "plan.md"), []byte(plan.Markdown(steps)), 0o644)
	if j, err := json.MarshalIndent(steps, "", "  "); err == nil {
		os.WriteFile(filepath.Join(*out, "plan.json"), j, 0o644)
	}
	manual := 0
	for _, s := range steps {
		if s.Manual {
			manual++
		}
	}
	fmt.Printf("%d steps (%d manual) → %s\n", len(steps), manual, filepath.Join(*out, "plan.sh"))
}

// onWordPressOrg asks the directory whether a slug exists there.
func onWordPressOrg(kind, slug string) bool {
	api := map[string]string{
		"theme":  "https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]=",
		"plugin": "https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=",
	}[kind]
	c := http.Client{Timeout: 15 * time.Second}
	resp, err := c.Get(api + url.QueryEscape(slug))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var body struct {
		Slug  string `json:"slug"`
		Error string `json:"error"`
	}
	if json.NewDecoder(resp.Body).Decode(&body) != nil {
		return false
	}
	return body.Error == "" && body.Slug == slug
}
