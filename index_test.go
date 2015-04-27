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
			rawVHost:             "",
			httpsAddr:            "localhost:10443",
			expectedRouteHost:    "localhost",
			expectedRedirectHost: "localhost:10443",
		},
	}
	staticVars := expvar.NewMap("testStatic")
	staticHandler := makeStaticHandler("/static", staticVars)

	for i, vt := range tests {
		routeHost, redirectHost := calculateDomains(vt.rawVHost, vt.httpsAddr)
		if routeHost != vt.expectedRouteHost {
			t.Errorf("#%d vhost %s, httpsAddr %s: want routeHost %s, got %s", i, vt.rawVHost, vt.httpsAddr, vt.expectedRouteHost, routeHost)
		}
		if redirectHost != vt.expectedRedirectHost {
			t.Errorf("#%d vhost %s, httpsAddr %s: want redirectHost %s, got %s", i, vt.rawVHost, vt.httpsAddr, vt.expectedRedirectHost, redirectHost)
		}

		tm := tlsMux(vt.expectedRouteHost, vt.expectedRedirectHost, staticHandler)
		r, err := http.NewRequest("GET", "https://howsmyssl.com/", nil)
		if err != nil {
			t.Fatalf("borked request")
		}
		w := httptest.NewRecorder()
		tm.ServeHTTP(w, r)
		expectedLocation := "https://" + vt.expectedRedirectHost + "/"
		location := w.Header()["Location"][0]
		if w.Code != http.StatusMovedPermanently {
			t.Errorf("#%d vhost %s, httpsAddr %s: want Code %s, got %s", i, vt.rawVHost, vt.httpsAddr, http.StatusMovedPermanently, w.Code)
		}
		if location != expectedLocation {
			t.Errorf("#%d vhost %s, httpsAddr %s: want Location %s, got %s", i, vt.rawVHost, vt.httpsAddr, expectedLocation, location)
		}
	}
}
