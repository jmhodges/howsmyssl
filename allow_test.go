package main

import (
	"expvar"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

type oaTest struct {
	origin   string
	referrer string

	detectedDomain string
	ok             bool
}

func TestOriginAllowerWithLocalhost(t *testing.T) {
	am := &allowMaps{
		AllowTheseDomains: make(map[string]bool),
		AllowSubdomainsOn: make(map[string]bool),
		BlockedDomains:    map[string]bool{"localhost": true, "example.com": true},
	}
	ama := &atomic.Pointer[allowMaps]{}
	ama.Store(am)
	oa := newOriginAllower(ama, "testhostname", nullLogClient{}, new(expvar.Map).Init(), newTestLogger(t))

	tests := []oaTest{
		{"", "", "", true},
		{"http://example.com/", "", "example.com", false},
		{"", "http://example.com/foobar", "example.com", false},
		{"https://foo.example.com/", "", "example.com", false},
		{"", "http://foo.example.com/yeahyeah", "example.com", false},
		{"https://foo.example.com", "http://foo.example.com/okay", "example.com", false},
		{"http://foo.example.com", "https://foo.example.com/letsbe", "example.com", false},

		{"http://notexample.com", "", "notexample.com", true},
		{"", "http://notexample.com/quix", "notexample.com", true},
		{"http://example.com.notreallyexample.com/", "", "notreallyexample.com", true},
		{"", "http://example.com.notreallyexample.com/kk", "notreallyexample.com", true},
		{"https://foo.notexample.com", "https://foo.example.com/quix", "notexample.com", true},

		{"http://example.com", "http://nope.notexample.com/foobar", "example.com", false},

		// Origin not matching causes a short-circuit to failure because we
		// trust it more and check it first to avoid doing extra work.
		{"http://bar.notexample.com", "http://example.com/quix", "notexample.com", true},

		{"https://localhost:3634", "", "localhost", false},
		{"", "http://localhost:3634/afda", "localhost", false},

		// Origins and Referrers that are ill-formed should cause failure.
		{"", "garbage", "", false},
		{"garbage", "", "", false},
		{"garbage", "garbage", "", false},
		{"garbage", "https://example.com/", "", false},

		{"localhost", "https://localhost:8080", "localhost", false},
		// Since we check Origin first, this will be banned, even though Referer
		// is a bogus URL.
		{"https://example.com", "garbage", "example.com", false},

		{"https://example.com/", "http://localhost:3333", "example.com", false},
		{"https://localhost:3336/", "http://example.com/afda", "localhost", false},

		{"https://example.com:3336/", "", "example.com", false},
		{"", "http://example.com:4444/asdf", "example.com", false},
		{"https://eXampLe.com", "", "example.com", false},
		{"", "https://eXaMPle.com/foobar", "example.com", false},
		{"https://144.23.35.33", "", "144.23.35.33", true},
		{"https://144.23.35.33:334", "", "144.23.35.33", true},
		{"", "http://[1fff:0:a88:85a3::ac1f]:8001/index.html", "1fff:0:a88:85a3::ac1f", true},
	}

	r, err := http.NewRequest("GET", "/whatever", nil)
	if err != nil {
		t.Fatalf("unable to make request: %s", err)
	}
	for i, ot := range tests {
		t.Run(fmt.Sprintf("%02d", i), func(t *testing.T) {
			r.Header.Set("Origin", ot.origin)
			r.Header.Set("Referer", ot.referrer)
			domain, ok := oa.Allow(r)
			if domain != ot.detectedDomain {
				t.Errorf("Origin: %#v; Referer: %#v: want detectedDomain %#v, got %#v", ot.origin, ot.referrer, ot.detectedDomain, domain)
			}
			if ok != ot.ok {
				t.Errorf("Origin: %#v; Referer: %#v: want %t, got %t", ot.origin, ot.referrer, ot.ok, ok)
			}
		})
	}
}

func TestOriginAllowerNoLocalhost(t *testing.T) {
	am := &allowMaps{
		AllowTheseDomains: make(map[string]bool),
		AllowSubdomainsOn: make(map[string]bool),
		BlockedDomains:    map[string]bool{"example.com": true},
	}
	ama := &atomic.Pointer[allowMaps]{}
	ama.Store(am)
	oa := newOriginAllower(ama, "testhostname", nullLogClient{}, new(expvar.Map).Init(), newTestLogger(t))

	tests := []oaTest{
		{"https://localhost:3634", "", "localhost", true},
		{"", "http://localhost:3634/afda", "localhost", true},
		{"", "http://example.com/afda", "example.com", false},
		{"localhost", "https://localhost:8080", "localhost", true},
		{"http://example.com", "http://localhost:3564/afda", "example.com", false},
	}

	r, err := http.NewRequest("GET", "/whatever", nil)
	if err != nil {
		t.Fatalf("unable to make request: %s", err)
	}

	for i, ot := range tests {
		r.Header.Set("Origin", ot.origin)
		r.Header.Set("Referer", ot.referrer)
		t.Run(fmt.Sprintf("#%02d", i), func(t *testing.T) {
			domain, ok := oa.Allow(r)
			if domain != ot.detectedDomain {
				t.Errorf("Origin: %s; Referer: %s: want detectedDomain %#v, got %#v", ot.origin, ot.referrer, ot.detectedDomain, domain)
			}
			if ok != ot.ok {
				t.Errorf("Origin: %s; Referer: %s: want ok %t, got %t", ot.origin, ot.referrer, ot.ok, ok)
			}
		})
	}

}

func TestReloadAllowMapsKeepsPreviousOnFailure(t *testing.T) {
	fp := filepath.Join(t.TempDir(), "allowlists.json")
	writeFile := func(content string) {
		t.Helper()
		if err := os.WriteFile(fp, []byte(content), 0o600); err != nil {
			t.Fatalf("unable to write allowlists file: %s", err)
		}
	}
	writeFile(`{"blocked_domains": ["example.com"]}`)

	ama := &atomic.Pointer[allowMaps]{}
	reloadAllowMaps(fp, ama)
	if ama.Load() == nil {
		t.Fatalf("allowMaps not stored after a successful load")
	}
	oa := newOriginAllower(ama, "testhostname", nullLogClient{}, new(expvar.Map).Init(), newTestLogger(t))

	check := func(when string) {
		t.Helper()
		tests := []oaTest{
			{"https://example.com", "", "example.com", false},
			{"", "https://example.com/foo", "example.com", false},
			{"https://notexample.com", "", "notexample.com", true},
		}
		for _, d := range tests {
			r, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatalf("%s: unable to make request: %s", when, err)
			}
			r.RemoteAddr = "127.0.0.1:1234"
			if d.origin != "" {
				r.Header.Set("Origin", d.origin)
			}
			if d.referrer != "" {
				r.Header.Set("Referer", d.referrer)
			}
			domain, ok := oa.Allow(r)
			if domain != d.detectedDomain || ok != d.ok {
				t.Errorf("%s: Origin %#v, Referer %#v: want domain %#v, ok %t; got domain %#v, ok %t", when, d.origin, d.referrer, d.detectedDomain, d.ok, domain, ok)
			}
		}
	}
	check("after the first load")

	// A reload that fails must leave the previously loaded lists in place.
	// Storing its nil result would make the next request with an Origin or
	// Referer header panic.
	before := ama.Load()
	writeFile(`{"blocked_domains": [`)
	reloadAllowMaps(fp, ama)
	if got := ama.Load(); got != before {
		t.Fatalf("after an unparsable file: allowMaps changed from %p to %p", before, got)
	}
	check("after an unparsable file")

	if err := os.Remove(fp); err != nil {
		t.Fatalf("unable to remove allowlists file: %s", err)
	}
	reloadAllowMaps(fp, ama)
	if got := ama.Load(); got != before {
		t.Fatalf("after a missing file: allowMaps changed from %p to %p", before, got)
	}
	check("after a missing file")

	// A later good reload is picked up again.
	writeFile(`{"blocked_domains": ["notexample.com"]}`)
	reloadAllowMaps(fp, ama)
	if got := ama.Load(); got == before || !got.BlockedDomains["notexample.com"] || got.BlockedDomains["example.com"] {
		t.Errorf("after a good reload: new lists were not stored, got %#v", got)
	}
}
