// Package views looks at the site the way different people see it: the
// logged-in owner, ordinary visitors from different countries, and a search
// engine. Cloaked spam only shows up in the difference.
package views

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/find"
)

const googlebotUA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
const browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"

// Viewer is one pair of eyes.
type Viewer struct {
	Name    string
	UA      string
	Country string // sent as CF-IPCountry, the header Cloudflare adds
	owner   bool
}

var Visitors = []Viewer{
	{Name: "visitor (US)", UA: browserUA, Country: "US"},
	{Name: "visitor (TR)", UA: browserUA, Country: "TR"},
	{Name: "visitor (DE)", UA: browserUA, Country: "DE"},
	{Name: "Googlebot", UA: googlebotUA},
}

type Seen struct {
	Viewer string
	Status int
	Links  []string // external link hosts+paths
}

type Client struct {
	Base  *url.URL
	owner *http.Client
	anon  *http.Client
}

func New(base string) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(base, "/") + "/")
	if err != nil {
		return nil, err
	}
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		Base: u,
		anon: &http.Client{Timeout: 20 * time.Second, CheckRedirect: noRedirect},
	}, nil
}

// Login signs in as the owner so the scan sees what the owner sees.
func (c *Client) Login(user, pass string) error {
	jar, _ := cookiejar.New(nil)
	c.owner = &http.Client{Timeout: 20 * time.Second, Jar: jar}
	login := c.Base.ResolveReference(&url.URL{Path: "wp-login.php"})
	jar.SetCookies(login, []*http.Cookie{{Name: "wordpress_test_cookie", Value: "WP Cookie check"}})
	resp, err := c.owner.PostForm(login.String(), url.Values{
		"log": {user}, "pwd": {pass}, "wp-submit": {"Log In"}, "testcookie": {"1"},
	})
	if err != nil {
		return err
	}
	resp.Body.Close()
	for _, ck := range jar.Cookies(c.Base) {
		if strings.HasPrefix(ck.Name, "wordpress_logged_in_") {
			return nil
		}
	}
	return fmt.Errorf("owner login failed")
}

func (c *Client) get(hc *http.Client, path string, v Viewer) (int, string, error) {
	ref, err := url.Parse(path)
	if err != nil {
		return 0, "", err
	}
	req, _ := http.NewRequest("GET", c.Base.ResolveReference(ref).String(), nil)
	ua := v.UA
	if ua == "" {
		ua = browserUA
	}
	req.Header.Set("User-Agent", ua)
	if v.Country != "" {
		req.Header.Set("CF-IPCountry", v.Country)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	return resp.StatusCode, string(b), nil
}

var hrefRe = regexp.MustCompile(`(?i)href\s*=\s*["'](https?://[^"'#\s]+)[^"']*["']`)

// ExternalLinks lists links that leave the site, the only kind spam needs.
func ExternalLinks(html, siteHost string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range hrefRe.FindAllStringSubmatch(html, -1) {
		u, err := url.Parse(m[1])
		if err != nil || u.Hostname() == siteHost || strings.HasSuffix(u.Hostname(), "wordpress.org") || u.Hostname() == "gmpg.org" {
			continue
		}
		key := u.Hostname() + u.EscapedPath()
		if !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// Compare fetches each path as the owner and as every visitor, and reports
// links that some visitors get and the owner does not.
func (c *Client) Compare(paths []string) ([]find.Finding, map[string][]Seen, error) {
	if c.owner == nil {
		return nil, nil, fmt.Errorf("log in as the owner first")
	}
	host := c.Base.Hostname()
	var out []find.Finding
	all := map[string][]Seen{}
	for _, p := range paths {
		st, body, err := c.get(c.owner, p, Viewer{})
		if err != nil {
			return nil, nil, err
		}
		ownerLinks := ExternalLinks(body, host)
		all[p] = append(all[p], Seen{Viewer: "owner (logged in)", Status: st, Links: ownerLinks})
		ownerSet := map[string]bool{}
		for _, l := range ownerLinks {
			ownerSet[l] = true
		}
		for _, v := range Visitors {
			st, body, err := c.get(c.anon, p, v)
			if err != nil {
				return nil, nil, err
			}
			links := ExternalLinks(body, host)
			all[p] = append(all[p], Seen{Viewer: v.Name, Status: st, Links: links})
			var extra []string
			for _, l := range links {
				if !ownerSet[l] {
					extra = append(extra, l)
				}
			}
			if len(extra) > 0 {
				out = append(out, find.Finding{
					Check:    "cloaked-links",
					Severity: find.Critical,
					Title:    "Links shown to " + v.Name + " but not to the logged-in owner",
					Where:    "page " + p,
					Why:      "The same page serves different links depending on who asks. This is why the owner sees a clean site while search results and some visitors see spam.",
					Evidence: extra,
				})
			}
		}
	}
	return out, all, nil
}

// The username cell is a <th scope="row"> with the login in aria-label on
// current WordPress, and a <td> with the login inside <strong> on older ones.
var loginCell = regexp.MustCompile(`(?s)class=['"]username column-username[^'"]*['"][^>]*?(?:aria-label="([^"]+)"[^>]*>|>.*?<strong>(?:<a [^>]*>)?([^<]+)</)`)

// VisibleAdmins returns the logins the owner sees on the Users screen, filtered
// to administrators, plus the count WordPress prints next to the role tab.
func (c *Client) VisibleAdmins() ([]string, string, error) {
	if c.owner == nil {
		return nil, "", fmt.Errorf("log in as the owner first")
	}
	_, body, err := c.get(c.owner, "wp-admin/users.php", Viewer{})
	if err != nil {
		return nil, "", err
	}
	_, adm, err := c.get(c.owner, "wp-admin/users.php?role=administrator", Viewer{})
	if err != nil {
		return nil, "", err
	}
	var logins []string
	for _, m := range loginCell.FindAllStringSubmatch(adm, -1) {
		login := m[1]
		if login == "" {
			login = m[2]
		}
		logins = append(logins, strings.TrimSpace(login))
	}
	count := ""
	if m := regexp.MustCompile(`Administrator\s*<span class="count">\((\d+)\)`).FindStringSubmatch(body); m != nil {
		count = m[1]
	}
	return logins, count, nil
}
