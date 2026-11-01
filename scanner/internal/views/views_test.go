package views

import (
	"reflect"
	"testing"
)

func TestExternalLinks(t *testing.T) {
	html := `<a href="http://localhost:8090/about/">About</a>
<a href="https://wordpress.org/">WP</a>
<a href="https://royal-spin-casino.example/">x</a><a href='https://royal-spin-casino.example/'>dup</a>
<a href="https://maps.example/place#pin">map</a>`
	got := ExternalLinks(html, "localhost")
	want := []string{"maps.example/place", "royal-spin-casino.example/"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestLoginCellBothMarkups(t *testing.T) {
	current := `<th class='username column-username has-row-actions column-primary' data-colname="Username" scope="row" aria-label="brightline"><img src="x"> <strong><a href="user-edit.php">brightline</a></strong>`
	older := `<td class='username column-username has-row-actions column-primary' data-colname="Username"><img src="x"> <strong><a href="user-edit.php?user_id=2">owner</a></strong>`
	header := `<th scope="col" id='username' class='manage-column column-username column-primary sorted asc'  aria-sort="ascending"  abbr="Username">`
	var got []string
	for _, m := range loginCell.FindAllStringSubmatch(header+current+older, -1) {
		if m[1] != "" {
			got = append(got, m[1])
		} else {
			got = append(got, m[2])
		}
	}
	if !reflect.DeepEqual(got, []string{"brightline", "owner"}) {
		t.Fatalf("got %v", got)
	}
}
