// Package owner writes the incident report for the site owner: what happened,
// how, what was done and proof that it held, in plain words. The technical
// evidence is there too, folded away for whoever needs it.
package owner

import (
	_ "embed"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/accesslog"
	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/find"
	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/plan"
	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/report"
)

//go:embed owner.html
var page string

type Input struct {
	SiteName string
	Before   report.Data
	After    report.Data
	Later    report.Data
	Plan     []plan.Step
}

// plain explains each kind of finding without jargon.
var plain = map[string]string{
	"cloaked-links":             "Spam links shown only to some visitors and to Google, never to you",
	"code:cloaking":             "Hidden code deciding who gets to see the spam",
	"code:obfuscated-decoder":   "Code deliberately written so nobody can read what it does",
	"code:hidden-user":          "Code hiding an account from your list of users",
	"code:self-restore":         "Code that reinstalls the infection after someone deletes it",
	"code:include-from-uploads": "WordPress forced to run a file from the images folder",
	"code:request-gated":        "A secret back door that opens with a password in the web address",
	"core-modified":             "A WordPress system file was edited",
	"core-extra":                "An extra file hidden among WordPress system files",
	"php-in-uploads":            "A program hidden among your images and documents",
	"mu-plugin":                 "A hidden plugin that does not show in your plugin list",
	"hidden-admin":              "An administrator account you could not see",
	"option-code":               "A spare copy of the infection kept in the database",
	"option-encoded":            "A spare copy of the infection kept in the database",
	"post-hidden-links":         "Invisible links added to your blog posts",
	"cron-unknown":              "A scheduled task that brings the infection back",
	"log-bruteforce":            "Someone tried to guess the admin password",
	"log-uploads-php":           "The hidden program was used from outside",
	"log-login":                 "The attacker logged in to your dashboard",
	"log-entry-point":           "The way in: an outdated plugin that accepted uploads from anyone",
	"log-file-edit":             "Theme files were edited from the dashboard",
}

var viewers = map[string]string{
	"owner (logged in)": "You, logged in",
	"visitor (US)":      "A visitor from the US",
	"visitor (TR)":      "A visitor from Turkey",
	"visitor (DE)":      "A visitor from Germany",
	"Googlebot":         "Google's crawler",
}

type Group struct {
	Severity string
	Plain    string
	Findings []find.Finding
}

type Row struct {
	Viewer string
	Spam   []string
}

type Event struct {
	When string
	What string
}

type view struct {
	Input
	Generated  string
	Groups     []Group
	Views      []Row
	ViewsPage  string
	Timeline   []Event
	Auto       []plan.Step
	Manual     []plan.Step
	BeforeCrit int
	BeforeAll  int
	AfterAll   int
	LaterAll   int
	Clean      bool
}

func Render(w io.Writer, in Input) error {
	v := view{Input: in, Generated: time.Now().UTC().Format("2 January 2006")}
	v.BeforeAll = len(in.Before.Findings)
	for _, f := range in.Before.Findings {
		if f.Severity == find.Critical {
			v.BeforeCrit++
		}
	}
	v.AfterAll, v.LaterAll = len(in.After.Findings), len(in.Later.Findings)
	v.Clean = v.AfterAll == 0 && v.LaterAll == 0

	// One line per kind of problem, worst first.
	byCheck := map[string]*Group{}
	var order []string
	for _, f := range in.Before.Findings {
		if strings.HasPrefix(f.Check, "log-") {
			continue // those become the timeline
		}
		key := plain[f.Check]
		if key == "" {
			key = f.Title
		}
		g, ok := byCheck[key]
		if !ok {
			g = &Group{Severity: f.Severity.String(), Plain: key}
			byCheck[key] = g
			order = append(order, key)
		}
		g.Findings = append(g.Findings, f)
	}
	for _, k := range order {
		v.Groups = append(v.Groups, *byCheck[k])
	}

	// The home page as each kind of visitor saw it.
	for page := range in.Before.Views {
		if v.ViewsPage == "" || page == "/" {
			v.ViewsPage = page
		}
	}
	for _, s := range in.Before.Views[v.ViewsPage] {
		name := viewers[s.Viewer]
		if name == "" {
			name = s.Viewer
		}
		v.Views = append(v.Views, Row{Viewer: name, Spam: s.Links})
	}
	if v.ViewsPage == "/" {
		v.ViewsPage = "your home page"
	}

	v.Timeline = timeline(in.Before.Timeline)

	for _, s := range in.Plan {
		if s.Manual {
			v.Manual = append(v.Manual, s)
		} else {
			v.Auto = append(v.Auto, s)
		}
	}

	t := template.Must(template.New("owner").Funcs(template.FuncMap{
		"lower": strings.ToLower,
	}).Parse(page))
	return t.Execute(w, v)
}

// timeline condenses the attacker's requests into the few moments that matter.
func timeline(es []accesslog.Entry) []Event {
	sort.SliceStable(es, func(i, j int) bool { return es[i].Time.Before(es[j].Time) })
	var out []Event
	guesses := 0
	for _, e := range es {
		when := e.Time.Format("2 Jan, 15:04 UTC")
		switch {
		case e.Method == "GET" && strings.Contains(e.Path, "readme.txt"):
			out = append(out, Event{when, "Checked which plugin versions the site runs"})
		case strings.HasPrefix(e.Path, "/wp-json/wp/v2/users"):
			out = append(out, Event{when, "Listed the site's user names"})
		case e.Method == "POST" && strings.HasPrefix(e.Path, "/wp-login.php") && e.Status == 200:
			if guesses == 0 {
				out = append(out, Event{when, "Started guessing the admin password"})
			}
			guesses++
		case strings.Contains(e.Path, "admin-ajax.php"):
			out = append(out, Event{when, "Sent a file through a plugin endpoint that needs no login"})
		case strings.Contains(e.Path, "/wp-content/uploads/") && e.Method == "GET":
			out = append(out, Event{when, "Checked that the hidden program works"})
		case strings.Contains(e.Path, "/wp-content/uploads/") && e.Method == "POST":
			out = append(out, Event{when, "Sent commands to the hidden program"})
		case e.Method == "POST" && strings.HasPrefix(e.Path, "/wp-login.php") && e.Status == 302:
			out = append(out, Event{when, "Logged in to the dashboard"})
		case strings.Contains(e.Path, "theme-editor.php") && e.Method == "POST":
			out = append(out, Event{when, "Edited theme files from the dashboard"})
		}
	}
	return out
}
