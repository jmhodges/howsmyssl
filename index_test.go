package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"expvar"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tls110 "github.com/jmhodges/howsmyssl/tls120"
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
	webHandleFunc := http.NotFound
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
		tm := tlsMux("www.howsmyssl.com", "www.howsmyssl.com", tt.acmeRedirectURL, staticHandler, webHandleFunc, nil)
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
	webHandleFunc := http.NotFound

	for i, vt := range tests {
		routeHost, redirectHost := calculateDomains(vt.rawVHost, vt.httpsAddr)
		if routeHost != vt.expectedRouteHost {
			t.Errorf("#%d vhost %#v, httpsAddr %#v: want routeHost %#v, got %s", i, vt.rawVHost, vt.httpsAddr, vt.expectedRouteHost, routeHost)
		}
		if redirectHost != vt.expectedRedirectHost {
			t.Errorf("#%d vhost %#v, httpsAddr %#v: want redirectHost %#v, got %#v", i, vt.rawVHost, vt.httpsAddr, vt.expectedRedirectHost, redirectHost)
		}

		tm := tlsMux(vt.expectedRouteHost, vt.expectedRedirectHost, "http://otherexample.com", staticHandler, webHandleFunc, nil)
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

func TestDisallowedBodyParses(t *testing.T) {
	e := &struct {
		Error      string `json:"error"`
		TLSVersion string `json:"tls_version"`
	}{}
	err := json.Unmarshal(disallowedOriginBody, e)
	if err != nil {
		t.Errorf("disallowedOriginBody did not parse: %s", err)
	}
}

func TestJSONAPI(t *testing.T) {
	staticVars := new(expvar.Map).Init()
	staticHandler := makeStaticHandler("/static", staticVars)
	webHandleFunc := http.NotFound
	am := &allowMaps{
		AllowTheseDomains: make(map[string]bool),
		AllowSubdomainsOn: make(map[string]bool),
		BlockedDomains:    map[string]bool{"blocked.com": true},
	}
	ama := &allowMapsAtomic{}
	ama.Store(am)
	oa := newOriginAllower(ama, "testhostname", nullLogClient{}, new(expvar.Map).Init())
	tm := tlsMux("", "www.howsmyssl.com", "www.howsmyssl.com", staticHandler, webHandleFunc, oa)

	tl, err := tls110.Listen("tcp", "127.0.0.1:0", serverConf)
	if err != nil {
		t.Fatalf("NewListener: %s", err)
	}
	li := newListener(tl, new(expvar.Map).Init())

	srv := httptest.NewUnstartedServer(tm)
	srv.Listener = li
	// Intentionally not using StartTLS to avoid stomping on our special listener.
	srv.Start()
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("no redirects should be seen")
		},
	}

	type apiTest struct {
		path        string
		origin      string
		status      int
		contentType string
		body        string
	}
	tests := []apiTest{
		{
			path:        "/a/check",
			status:      http.StatusOK,
			contentType: "application/json",
			body:        expectedJSONBody,
		},
		{
			path:        "/a/check?callback=parseTLS",
			status:      http.StatusOK,
			contentType: "application/javascript",
			body:        "parseTLS(" + expectedJSONBody + ");",
		},
		{
			path:        "/a/check",
			origin:      "https://blocked.com",
			status:      http.StatusBadRequest,
			contentType: "application/json",
			body:        string(disallowedOriginBody),
		},
		{
			path:        "/a/check?callback=foobarParse",
			origin:      "https://blocked.com",
			status:      http.StatusOK,
			contentType: "application/javascript",
			body:        "foobarParse(" + string(disallowedOriginBody) + ");",
		},
	}
	u := strings.Replace(srv.URL, "http://", "https://", -1)
	for _, at := range tests {
		t.Run(at.path, func(t *testing.T) {
			r, err := http.NewRequest("GET", u+at.path, nil)
			if err != nil {
				t.Fatalf("NewRequest: %s", err)
			}
			r = r.WithContext(ctx)
			r.Header.Set("Origin", at.origin)
			resp, err := c.Do(r)
			if err != nil {
				t.Fatalf("Get: %s", err)
			}
			b, err := ioutil.ReadAll(resp.Body)
			defer resp.Body.Close()
			if err != nil {
				t.Fatalf("ReadAll: %s", err)
			}
			if resp.StatusCode != at.status {
				t.Errorf("status code, want: %d, got: %d", at.status, resp.StatusCode)
			}
			if string(b) != at.body {
				t.Errorf("body, want:\n%#v\ngot:%#v\n", at.body, string(b))
			}
			ct := resp.Header.Get("Content-Type")
			if ct != at.contentType {
				t.Errorf("Content-Type, want %s, got %s", at.contentType, ct)
			}
		})
	}
}

const (
	expectedJSONBody = `{"given_cipher_suites":["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256","TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA","TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA","TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA","TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA","TLS_RSA_WITH_AES_128_GCM_SHA256","TLS_RSA_WITH_AES_256_GCM_SHA384","TLS_RSA_WITH_AES_128_CBC_SHA","TLS_RSA_WITH_AES_256_CBC_SHA","TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA","TLS_RSA_WITH_3DES_EDE_CBC_SHA","TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256"],"ephemeral_keys_supported":true,"session_ticket_supported":false,"tls_compression_supported":false,"unknown_cipher_suite_supported":false,"beast_vuln":false,"able_to_detect_n_minus_one_splitting":false,"insecure_cipher_suites":{},"tls_version":"TLS 1.3","rating":"Probably Okay"}`
)
