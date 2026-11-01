package files

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/irvinmcd702/hacked-site-rescue/scanner/internal/find"
)

// rule is one sign of malicious code. A rule matches when every regexp in
// all matches; requiring several signs together keeps ordinary plugins quiet.
type rule struct {
	id       string
	severity find.Severity
	title    string
	why      string
	all      []*regexp.Regexp
}

var rules = []rule{
	{
		id:       "obfuscated-decoder",
		severity: find.High,
		title:    "Decoder function name hidden from search",
		why:      "The code builds the name of a decoding function by reversing a string, which only makes sense if someone wanted to avoid simple searches.",
		all:      []*regexp.Regexp{regexp.MustCompile(`(?i)strrev\(\s*['"]edoced_46esab['"]\s*\)`)},
	},
	{
		id:       "cloaking",
		severity: find.Critical,
		title:    "Content depends on visitor country and search-engine bots",
		why:      "Checking the visitor's country and whether the visitor is Googlebot in the same code path is how spam is shown to search engines and foreign visitors while the owner sees a clean site.",
		all: []*regexp.Regexp{
			regexp.MustCompile(`HTTP_CF_IPCOUNTRY|GEOIP_COUNTRY|geoip_country_code`),
			regexp.MustCompile(`(?i)googlebot|bingbot|HTTP_USER_AGENT`),
			regexp.MustCompile(`is_user_logged_in\(\)`),
		},
	},
	{
		id:       "hidden-user",
		severity: find.Critical,
		title:    "A user is removed from the admin users list",
		why:      "Filtering the users query by login name hides an account from the site owner while it keeps working.",
		all: []*regexp.Regexp{
			regexp.MustCompile(`pre_user_query`),
			regexp.MustCompile(`user_login\s*!=`),
		},
	},
	{
		id:       "self-restore",
		severity: find.Critical,
		title:    "Code rewrites a file from data stored in the database",
		why:      "Writing a decoded database value back to disk is how an infection comes back after the visible file was deleted.",
		all: []*regexp.Regexp{
			regexp.MustCompile(`file_put_contents\s*\(`),
			regexp.MustCompile(`base64_decode\s*\(\s*\$`),
			regexp.MustCompile(`get_option\s*\(`),
		},
	},
	{
		id:       "include-from-uploads",
		severity: find.Critical,
		title:    "PHP is loaded from the uploads folder",
		why:      "Uploads hold images and documents; code that includes a PHP file from there is loading something an attacker dropped in.",
		all:      []*regexp.Regexp{regexp.MustCompile(`(?i)(include|require)(_once)?\s*\(?[^;]*uploads/[^;]*\.php`)},
	},
	{
		id:       "request-gated",
		severity: find.High,
		title:    "Hidden behaviour unlocked by a secret request parameter",
		why:      "Comparing a request parameter with an encoded constant and then doing something different is the usual shape of a backdoor key.",
		all: []*regexp.Regexp{
			regexp.MustCompile(`\$_(REQUEST|POST|GET|COOKIE)\[`),
			regexp.MustCompile(`===?\s*\$\w+\(\s*\$\w+\s*\)`),
		},
	},
}

// matchRules returns findings for one file. Evidence is the matching lines,
// trimmed, so the report shows the code without anyone opening the file.
func matchRules(path string, src []byte) []find.Finding {
	text := string(src)
	var out []find.Finding
	for _, r := range rules {
		ok := true
		for _, re := range r.all {
			if !re.MatchString(text) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		out = append(out, find.Finding{
			Check:    "code:" + r.id,
			Severity: r.severity,
			Title:    r.title,
			Where:    path,
			Why:      r.why,
			Evidence: evidenceLines(text, r.all, 4),
		})
	}
	return out
}

func evidenceLines(text string, res []*regexp.Regexp, max int) []string {
	var out []string
	for i, line := range strings.Split(text, "\n") {
		for _, re := range res {
			if re.MatchString(line) {
				out = append(out, lineRef(i+1, line))
				break
			}
		}
		if len(out) == max {
			break
		}
	}
	return out
}

func lineRef(n int, line string) string {
	line = strings.TrimSpace(line)
	if len(line) > 160 {
		line = line[:160] + "…"
	}
	return fmt.Sprintf("line %d: %s", n, line)
}
