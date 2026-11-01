// Package find holds the shape every check reports in.
package find

import (
	"fmt"
	"sort"
)

type Severity int

const (
	Info Severity = iota
	Medium
	High
	Critical
)

func (s Severity) String() string {
	return [...]string{"info", "medium", "high", "critical"}[s]
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	for i, name := range []string{"info", "medium", "high", "critical"} {
		if string(b) == name {
			*s = Severity(i)
			return nil
		}
	}
	return fmt.Errorf("unknown severity %q", b)
}

// Finding is one thing a person should look at, with enough evidence to
// decide without rerunning the scan.
type Finding struct {
	Check    string   `json:"check"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Where    string   `json:"where"`
	Why      string   `json:"why"`
	Evidence []string `json:"evidence,omitempty"`
}

// Sort puts the worst first, then groups by check so the report reads in order.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].Check != fs[j].Check {
			return fs[i].Check < fs[j].Check
		}
		return fs[i].Where < fs[j].Where
	})
}
