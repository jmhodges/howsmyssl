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
	rej            rejectionReason
}

func TestOriginAllowerWithLocalhost(t *testing.T) {
	oa := newOriginAllower([]string{"localhost", "example.com"}, "testhostname", nullLogClient{}, new(expvar.Map).Init())

	tests := []oaTest{
		{"", "", "", rejectionNil},
		{"http://example.com/", "", "example.com", rejectionConfig},
		{"", "http://example.com/foobar", "example.com", rejectionConfig},
		{"https://foo.example.com/", "", "example.com", rejectionConfig},
		{"", "http://foo.example.com/yeahyeah", "example.com", rejectionConfig},
		{"https://foo.example.com", "http://foo.example.com/okay", "example.com", rejectionConfig},
		{"http://foo.example.com", "https://foo.example.com/letsbe", "example.com", rejectionConfig},

		{"http://notexample.com", "", "notexample.com", rejectionNil},
		{"", "http://notexample.com/quix", "notexample.com", rejectionNil},
		{"http://example.com.notreallyexample.com/", "", "notreallyexample.com", rejectionNil},
		{"", "http://example.com.notreallyexample.com/kk", "notreallyexample.com", rejectionNil},
		{"https://foo.notexample.com", "https://foo.example.com/quix", "notexample.com", rejectionNil},

		{"http://example.com", "http://nope.notexample.com/foobar", "example.com", rejectionConfig},

		// Origin not matching causes a short-circuit to failure because we
		// trust it more and check it first to avoid doing extra work.
		{"http://bar.notexample.com", "http://example.com/quix", "notexample.com", rejectionNil},

		{"https://localhost:3634", "", "localhost", rejectionConfig},
		{"", "http://localhost:3634/afda", "localhost", rejectionConfig},

		// Origins and Referrers that are ill-formed should cause failure.
		{"", "garbage", "", rejectionConfig},
		{"garbage", "", "", rejectionConfig},
		{"garbage", "garbage", "", rejectionConfig},
		{"garbage", "https://example.com/", "", rejectionConfig},

		// Since we check Origin first, this will be banned, even though Referer
		// is a bogus URL.
		{"https://example.com", "garbage", "example.com", rejectionConfig},

		{"https://example.com/", "http://localhost:3333", "example.com", rejectionConfig},
		{"https://localhost:3336/", "http://example.com/afda", "localhost", rejectionConfig},

		{"https://example.com:3336/", "", "example.com", rejectionConfig},
		{"", "http://example.com:4444/asdf", "example.com", rejectionConfig},
	}

	r, err := http.NewRequest("GET", "/whatever", nil)
	if err != nil {
		t.Fatalf("unable to make request: %s", err)
	}
	r.Header.Set("User-Agent", "something")

	for i, ot := range tests {
		r.Header.Set("Origin", ot.origin)
		r.Header.Set("Referer", ot.referrer)
		domain, rej := oa.Allow(r)
		if domain != ot.detectedDomain {
			t.Errorf("#%d, Origin: %#v; Referer: %#v: want detectedDomain %#v, got %#v", i, ot.origin, ot.referrer, ot.detectedDomain, domain)
		}
		if rej != ot.rej {
			t.Errorf("#%d, Origin: %#v; Referer: %#v: want ok %s, got %s", i, ot.origin, ot.referrer, ot.rej, rej)
		}
	}
}

func TestOriginAllowerNoLocalhost(t *testing.T) {
	oa := newOriginAllower([]string{"example.com"}, "testhostname", nullLogClient{}, new(expvar.Map).Init())

	tests := []oaTest{
		{"https://localhost:3634", "", "localhost", rejectionNil},
		{"", "http://localhost:3634/afda", "localhost", rejectionNil},
		{"", "http://example.com/afda", "example.com", rejectionConfig},
		{"http://example.com", "http://localhost:3564/afda", "example.com", rejectionConfig},
	}

	r, err := http.NewRequest("GET", "/whatever", nil)
	if err != nil {
		t.Fatalf("unable to make request: %s", err)
	}
	r.Header.Set("User-Agent", "something")

	for i, ot := range tests {
		r.Header.Set("Origin", ot.origin)
		r.Header.Set("Referer", ot.referrer)
		domain, rej := oa.Allow(r)
		if domain != ot.detectedDomain {
			t.Errorf("#%d, Origin: %s; Referer: %s: want detectedDomain %#v, got %#v", i, ot.origin, ot.referrer, ot.detectedDomain, domain)
		}
		if rej != ot.rej {
			t.Errorf("#%d, Origin: %s; Referer: %s: want ok %s, got %s", i, ot.origin, ot.referrer, ot.rej, rej)
		}
	}

}

func TestEmptyOriginAllowerAllowsAll(t *testing.T) {
	oa := newOriginAllower([]string{}, "testhostname", nullLogClient{}, new(expvar.Map).Init())

	r, err := http.NewRequest("GET", "/whatever", nil)
	if err != nil {
		t.Fatalf("unable to make request: %s", err)
	}
	r.Header.Set("User-Agent", "something")

	tests := []string{"localhost", "http://example.com", "https://notreallyexample.com", "garbage"}
	for _, d := range tests {
		r.Header.Set("Origin", d)
		_, rej := oa.Allow(r)
		if rej != rejectionNil {
			t.Errorf("%#v was not okay", d)
		}
	}
}
