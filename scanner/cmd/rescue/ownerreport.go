package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/owner"
)

// runReport builds the owner's HTML report from the saved scans and the plan.
func runReport(args []string) {
	fl := flag.NewFlagSet("report", flag.ExitOnError)
	name := fl.String("site", "Your website", "site name for the title")
	before := fl.String("before", "", "scan directory before cleanup (holds plan.json too)")
	after := fl.String("after", "", "scan directory right after cleanup")
	later := fl.String("later", "", "scan directory after scheduled tasks ran")
	out := fl.String("out", "owner-report.html", "output file")
	fl.Parse(args)

	in := owner.Input{SiteName: *name}
	must(readJSON(filepath.Join(*before, "scan.json"), &in.Before))
	must(readJSON(filepath.Join(*after, "scan.json"), &in.After))
	must(readJSON(filepath.Join(*later, "scan.json"), &in.Later))
	must(readJSON(filepath.Join(*before, "plan.json"), &in.Plan))

	f, err := os.Create(*out)
	must(err)
	defer f.Close()
	must(owner.Render(f, in))
	fmt.Println("owner report →", *out)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
