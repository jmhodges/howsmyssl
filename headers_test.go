package main

import (
	"context"
	"expvar"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	howhttptest "github.com/jmhodges/howsmyssl/howhttp/httptest"
)

// TestResponseHeaders checks the headers that tell a browser, or a cache in
// between, how to treat our responses: that none of them should have its
// content type guessed, and that the ones describing the client's own
// connection should not be stored.
func TestResponseHeaders(t *testing.T) {
	index = loadIndex()

	stats := newStatusStats(new(expvar.Map).Init())
	staticHandler := makeStaticHandler(stats)
	am := &allowMaps{
		AllowTheseDomains: make(map[string]bool),
		AllowSubdomainsOn: make(map[string]bool),
		BlockedDomains:    map[string]bool{"blocked.com": true},
	}
	ama := &atomic.Pointer[allowMaps]{}
	ama.Store(am)
	oa := newOriginAllower(ama, "testhostname", nullLogClient{}, new(expvar.Map).Init(), newTestLogger(t))
	tm := tlsMux("", "www.howsmyssl.com", "/s/", staticHandler, handleWeb, oa, newTestLogger(t), newTestLogger(t))

	srv := howhttptest.NewServer(tm)
	defer srv.Close()

	tests := []struct {
		name         string
		path         string
		origin       string
		status       int
		cacheControl string
	}{
		{name: "page", path: "/", status: http.StatusOK, cacheControl: "no-store"},
		{name: "api", path: "/a/check", status: http.StatusOK, cacheControl: "no-store"},
		{name: "api with callback", path: "/a/check?callback=parseTLS", status: http.StatusOK, cacheControl: "no-store"},
		{name: "api, blocked", path: "/a/check", origin: "https://blocked.com", status: http.StatusBadRequest, cacheControl: "no-store"},
		{name: "api with callback, blocked", path: "/a/check?callback=parseTLS", origin: "https://blocked.com", status: http.StatusOK, cacheControl: "no-store"},
		// These are the same for every client, so they may be cached.
		{name: "static html", path: "/s/about.html", status: http.StatusOK},
		{name: "static css", path: "/s/css/site.css", status: http.StatusOK},
		{name: "llms.txt", path: "/llms.txt", status: http.StatusOK},
		{name: "healthcheck", path: "/healthcheck", status: http.StatusOK},
		{name: "not found", path: "/nope", status: http.StatusNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			r, err := http.NewRequestWithContext(ctx, "GET", srv.URL+tc.path, nil)
			if err != nil {
				t.Fatalf("NewRequest: %s", err)
			}
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			resp, err := srv.Client().Do(r)
			if err != nil {
				t.Fatalf("Do: %s", err)
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body)

			if resp.StatusCode != tc.status {
				t.Errorf("status code, want: %d, got: %d", tc.status, resp.StatusCode)
			}
			if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options, want %#v, got %#v", "nosniff", got)
			}
			if got := resp.Header.Get("Cache-Control"); got != tc.cacheControl {
				t.Errorf("Cache-Control, want %#v, got %#v", tc.cacheControl, got)
			}
			if got := resp.Header.Get("Content-Type"); got == "" {
				t.Errorf("Content-Type, want one, since we ask browsers not to guess, got none")
			}
		})
	}
}
