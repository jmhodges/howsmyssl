package main

import (
	"bytes"
	"expvar"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDumbNilishIndex(t *testing.T) {
	tmpl := loadIndex()
	buf := new(bytes.Buffer)
	err := tmpl.Execute(buf, &clientInfo{})
	if err != nil {
		t.Errorf("index execution blew up with nilish clientInfo: %#v", err)
	}
	if len(buf.Bytes()) == 0 {
		t.Errorf("index execution did not write anything")
	}
}

type acmeTest struct {
	challPath       string
	acmeRedirectURL string
	expected        string
	code            int
}

func TestACMERedirect(t *testing.T) {
	staticVars := new(expvar.Map).Init()
	staticHandler := makeStaticHandler("/static", staticVars)
	tests := []acmeTest{
		// same domain redirect, acmeRedirectURL leads with "/"
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "/example.com",
			expected:        "/example.com/.well-known/acme-challenge/foobar",
		},
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "http://example.com",
			expected:        "http://example.com/.well-known/acme-challenge/foobar",
		},
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "http://example.com/",
			expected:        "http://example.com/.well-known/acme-challenge/foobar",
		},
		// Busted acmeRedirectURL. Meant to be a domain, but was not.
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "example.com",
			expected:        "/.well-known/acme-challenge/example.com/.well-known/acme-challenge/foobar",
		},
		// same domain redirect, acmeRedirectURL leads and trails with "/"
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "/okay/",
			expected:        "/okay/.well-known/acme-challenge/foobar",
		},
		// same domain redirect, acmeRedirectURL leads and trails with "/"
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "/okay/",
			expected:        "/okay/.well-known/acme-challenge/foobar",
		},
		// same domain redirect, acmeRedirectURL leads with "/"
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "/okay",
			expected:        "/okay/.well-known/acme-challenge/foobar",
		},
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge",
			acmeRedirectURL: "http://example.com",
			expected:        "/.well-known/acme-challenge/",
			code:            http.StatusMovedPermanently,
		},
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/",
			acmeRedirectURL: "http://example.com",
			expected:        "",
			code:            http.StatusOK,
		},
		{
			challPath:       "https://www.howsmyssl.com/.well-known/acme-challenge/foobar",
			acmeRedirectURL: "http://example.com",
			expected:        "http://example.com/.well-known/acme-challenge/foobar",
		},
	}
	for i, tt := range tests {
		tm := tlsMux("www.howsmyssl.com", "www.howsmyssl.com", tt.acmeRedirectURL, staticHandler, nil)
		r, err := http.NewRequest("GET", tt.challPath, nil)
		if err != nil {
			t.Fatalf("borked request for %#v: %s", tt.challPath, err)
		}
		w := httptest.NewRecorder()
		tm.ServeHTTP(w, r)

		location := w.Header().Get("Location")
		if tt.code == 0 {
			tt.code = http.StatusFound
		}
		if w.Code != tt.code {
			t.Errorf("#%d, want %d, got %d", i, tt.code, w.Code)
		}
		if location != tt.expected {
			t.Errorf("#%d, %q, want %#v, got %#v", i, tt.acmeRedirectURL, tt.expected, location)
		}
	}
}

type vhostTest struct {
	rawVHost  string
	httpsAddr string

	expectedRouteHost    string
	expectedRedirectHost string
}

func TestVHostCalculation(t *testing.T) {
	tests := []vhostTest{
		vhostTest{
			rawVHost:             "www.howsmyssl.com",
			httpsAddr:            "0:10443",
			expectedRouteHost:    "www.howsmyssl.com",
			expectedRedirectHost: "www.howsmyssl.com",
		},
		vhostTest{
			rawVHost:             "localhost:10443",
			httpsAddr:            "localhost:10443",
			expectedRouteHost:    "localhost",
			expectedRedirectHost: "localhost:10443",
		},
		vhostTest{
			rawVHost:             "example.com:10443",
			httpsAddr:            "localhost:10443",
			expectedRouteHost:    "example.com",
			expectedRedirectHost: "example.com:10443",
		},
		vhostTest{
			rawVHost:             "example.com:443",
			httpsAddr:            "0:443",
			expectedRouteHost:    "example.com",
			expectedRedirectHost: "example.com",
		},
	}
	staticVars := new(expvar.Map).Init()
	staticHandler := makeStaticHandler("/static", staticVars)

	for i, vt := range tests {
		routeHost, redirectHost := calculateDomains(vt.rawVHost, vt.httpsAddr)
		if routeHost != vt.expectedRouteHost {
			t.Errorf("#%d vhost %#v, httpsAddr %#v: want routeHost %#v, got %s", i, vt.rawVHost, vt.httpsAddr, vt.expectedRouteHost, routeHost)
		}
		if redirectHost != vt.expectedRedirectHost {
			t.Errorf("#%d vhost %#v, httpsAddr %#v: want redirectHost %#v, got %#v", i, vt.rawVHost, vt.httpsAddr, vt.expectedRedirectHost, redirectHost)
		}

		tm := tlsMux(vt.expectedRouteHost, vt.expectedRedirectHost, "http://otherexample.com", staticHandler, nil)
		r, err := http.NewRequest("GET", "https://howsmyssl.com/", nil)
		if err != nil {
			t.Fatalf("borked request")
		}
		w := httptest.NewRecorder()
		tm.ServeHTTP(w, r)
		expectedLocation := "https://" + vt.expectedRedirectHost + "/"
		location := w.Header()["Location"][0]
		if w.Code != http.StatusMovedPermanently {
			t.Errorf("#%d vhost %#v, httpsAddr %#v: want Code %d, got %d", i, vt.rawVHost, vt.httpsAddr, http.StatusMovedPermanently, w.Code)
		}
		if location != expectedLocation {
			t.Errorf("#%d vhost %#v, httpsAddr %#v: want Location %s, got %s", i, vt.rawVHost, vt.httpsAddr, expectedLocation, location)
		}
	}
}
