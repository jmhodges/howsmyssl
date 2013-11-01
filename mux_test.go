package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type redir struct {
	url string
	loc string
}

var routeTests = []struct {
	port   string
	redirs []redir
}{
	{
		"443",
		[]redir{
			// requests with port 443 over HTTPs will always be stripped of their port
			{"https://www.example.com/", ""},
			{"https://example.com/", "https://www.example.com/"},
			{"https://redirectexample.com/", "https://www.example.com/"},
			{"https://www.redirectexample.com/", "https://www.example.com/"},
			{"https://redirectexample.com/", "https://www.example.com/"},
			{"https://www.redirectexample.com/", "https://www.example.com/"},
		},
	},
	{
		"10443",
		[]redir{
			{"https://www.example.com:10443/", ""},
			{"https://example.com:10443/", "https://www.example.com:10443/"},
			{"https://redirectexample.com:10443/", "https://www.example.com:10443/"},
			{"https://www.redirectexample.com:10443/", "https://www.example.com:10443/"},
		},
	},
}

func TestRouteSemiSmart(t *testing.T) {
	for _, rt := range routeTests {
		m := boot(rt.port)
		for _, u := range rt.redirs {
			get(t, m, u)
		}
	}
}

func boot(port string) *http.ServeMux {
	var empty http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
	return tlsMux("www.example.com", port, empty, empty, empty)
}

func get(t *testing.T, m *http.ServeMux, u redir) {
	uu, err := url.Parse(u.url)
	if err != nil {
		t.Errorf("Input url broken: %s", u.url)
		return
	}
	r := &http.Request{
		Method: "GET",
		Host:   uu.Host,
		URL:    uu,
	}
	rr := httptest.NewRecorder()
	m.ServeHTTP(rr, r)
	actual := rr.HeaderMap.Get("Location")
	if u.loc != actual {
		t.Errorf("req: %v, wanted redirect: %#v, got: %#v", u.url, u.loc, actual)
	}
}
