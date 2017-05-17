package main

import (
	"expvar"
	"net/http"
	"testing"
)

type oaTest struct {
	origin   string
	referrer string

	detectedDomain string
	ok             bool
}

func TestOriginAllowerWithLocalhost(t *testing.T) {
	oa := newOriginAllower([]string{"localhost", "example.com"}, "testhostname", nullLogClient{}, false, new(expvar.Map).Init())

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

		// Since we check Origin first, this will be banned, even though Referer
		// is a bogus URL.
		{"https://example.com", "garbage", "example.com", false},

		{"https://example.com/", "http://localhost:3333", "example.com", false},
		{"https://localhost:3336/", "http://example.com/afda", "localhost", false},

		{"https://example.com:3336/", "", "example.com", false},
		{"", "http://example.com:4444/asdf", "example.com", false},
	}

	r, err := http.NewRequest("GET", "/whatever", nil)
	if err != nil {
		t.Fatalf("unable to make request: %s", err)
	}
	for i, ot := range tests {
		r.Header.Set("Origin", ot.origin)
		r.Header.Set("Referer", ot.referrer)
		domain, ok := oa.Allow(r)
		if domain != ot.detectedDomain {
			t.Errorf("#%d, Origin: %#v; Referer: %#v: want detectedDomain %#v, got %#v", i, ot.origin, ot.referrer, ot.detectedDomain, domain)
		}
		if ok != ot.ok {
			t.Errorf("#%d, Origin: %#v; Referer: %#v: want ok %t, got %t", i, ot.origin, ot.referrer, ot.ok, ok)
		}
	}
}

func TestOriginAllowerNoLocalhost(t *testing.T) {
	oa := newOriginAllower([]string{"example.com"}, "testhostname", nullLogClient{}, false, new(expvar.Map).Init())

	tests := []oaTest{
		{"https://localhost:3634", "", "localhost", true},
		{"", "http://localhost:3634/afda", "localhost", true},
		{"", "http://example.com/afda", "example.com", false},
		{"http://example.com", "http://localhost:3564/afda", "example.com", false},
	}

	r, err := http.NewRequest("GET", "/whatever", nil)
	if err != nil {
		t.Fatalf("unable to make request: %s", err)
	}

	for i, ot := range tests {
		r.Header.Set("Origin", ot.origin)
		r.Header.Set("Referer", ot.referrer)
		domain, ok := oa.Allow(r)
		if domain != ot.detectedDomain {
			t.Errorf("#%d, Origin: %s; Referer: %s: want detectedDomain %#v, got %#v", i, ot.origin, ot.referrer, ot.detectedDomain, domain)
		}
		if ok != ot.ok {
			t.Errorf("#%d, Origin: %s; Referer: %s: want ok %t, got %t", i, ot.origin, ot.referrer, ot.ok, ok)
		}
	}

}

func TestEmptyOriginAllowerAllowsAll(t *testing.T) {
	oa := newOriginAllower([]string{}, "testhostname", nullLogClient{}, false, new(expvar.Map).Init())

	r, err := http.NewRequest("GET", "/whatever", nil)
	if err != nil {
		t.Fatalf("unable to make request: %s", err)
	}

	tests := []string{"localhost", "http://example.com", "https://notreallyexample.com", "garbage"}
	for _, d := range tests {
		r.Header.Set("Origin", d)
		_, ok := oa.Allow(r)
		if !ok {
			t.Errorf("%#v was not okay", d)
		}
	}
}
