// Package report turns findings into something a site owner can read.
package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/accesslog"
	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/find"
	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/views"
)

type Data struct {
	Site     string
	Scanned  time.Time
	Version  string
	Findings []find.Finding
	Views    map[string][]views.Seen
	Timeline []accesslog.Entry
	Notes    []string // checks that could not run, so absence of findings is not misread
}

func Markdown(w io.Writer, d Data) {
	counts := map[find.Severity]int{}
	for _, f := range d.Findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "# Security scan: %s\n\n", d.Site)
	fmt.Fprintf(w, "Scanned %s · WordPress %s\n\n", d.Scanned.UTC().Format("2006-01-02 15:04 UTC"), d.Version)
	fmt.Fprintf(w, "**%d critical · %d high · %d medium · %d info**\n\n",
		counts[find.Critical], counts[find.High], counts[find.Medium], counts[find.Info])
	for _, n := range d.Notes {
		fmt.Fprintf(w, "> %s\n", n)
	}
	if len(d.Notes) > 0 {
		fmt.Fprintln(w)
	}

	if len(d.Views) > 0 {
		fmt.Fprintf(w, "## The same page, seen by different people\n\n")
		for page, seen := range d.Views {
			fmt.Fprintf(w, "Page `%s`:\n\n| Who | External links |\n|---|---|\n", page)
			for _, s := range seen {
				links := "none"
				if len(s.Links) > 0 {
					links = strings.Join(s.Links, "<br>")
				}
				fmt.Fprintf(w, "| %s | %s |\n", s.Viewer, links)
			}
			fmt.Fprintln(w)
		}
	}

	fmt.Fprintf(w, "## Findings\n\n")
	if len(d.Findings) == 0 {
		fmt.Fprintf(w, "Nothing suspicious found by the checks that ran.\n\n")
	}
	for i, f := range d.Findings {
		fmt.Fprintf(w, "### %d. [%s] %s\n\n", i+1, strings.ToUpper(f.Severity.String()), f.Title)
		fmt.Fprintf(w, "- **Where:** `%s`\n- **Why it matters:** %s\n", f.Where, f.Why)
		if len(f.Evidence) > 0 {
			fmt.Fprintf(w, "- **Evidence:**\n")
			for _, e := range f.Evidence {
				fmt.Fprintf(w, "  - `%s`\n", strings.ReplaceAll(e, "`", "'"))
			}
		}
		fmt.Fprintln(w)
	}

	if len(d.Timeline) > 0 {
		fmt.Fprintf(w, "## What the attacking addresses did\n\n| Time (UTC) | Address | Request | Status |\n|---|---|---|---|\n")
		for _, e := range d.Timeline {
			fmt.Fprintf(w, "| %s | %s | `%s %s` | %d |\n", e.Time.Format("2006-01-02 15:04:05"), e.IP, e.Method, e.Path, e.Status)
		}
		fmt.Fprintln(w)
	}
}
