package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"io/ioutil"
)

type redir struct {
	url string
	loc string
}

var (
	web = "web"
	api = "api"
	static = "static"
)

var redirTests = []struct {
	port   string
	redirs []redir
}{
	{
		"443",
		[]redir{
			// requests with port 443 over HTTPs will always be stripped of their port
			{"https://www.example.com/", "",},
			{"https://example.com/", "https://www.example.com/"},
			{"https://example.com/a/check", "https://www.example.com/a/check"},
			{"https://redirectexample.com/", "https://www.example.com/"},
			{"https://redirectexample.com/a/check", "https://www.example.com/a/check"},
			{"https://www.redirectexample.com/", "https://www.example.com/"},
			{"https://www.redirectexample.com/a/check", "https://www.example.com/a/check"},
		},
	},
	{
		"10443",
		[]redir{
			{"https://www.example.com:10443/", ""},
			{"https://www.example.com:10443/a/check", ""},
			{"https://example.com:10443/", "https://www.example.com:10443/"},
			{"https://example.com:10443/a/check", "https://www.example.com:10443/a/check"},
			{"https://redirectexample.com/", "https://www.example.com:10443/"},
			{"https://redirectexample.com/a/check", "https://www.example.com:10443/a/check"},
			{"https://redirectexample.com:10443/", "https://www.example.com:10443/"},
			{"https://redirectexample.com:10443/a/check", "https://www.example.com:10443/a/check"},
			{"https://www.redirectexample.com:10443/", "https://www.example.com:10443/"},
			{"https://www.redirectexample.com:10443/a/check", "https://www.example.com:10443/a/check"},
		},
	},
}

type route struct {
	url, body string
	code int
}

func TestRedirects(t *testing.T) {
	for _, rt := range redirTests {
		m := boot(rt.port)
		for _, u := range rt.redirs {
			checkRedir(t, m, u)
		}
	}
}

func TestRouting(t *testing.T) {
	port := "10443"
	tests := []route{
		// {"https://www.example.com:10443/", web, 200},
		{"https://www.example.com:10443/a/check", api, 200},
		// {"https://www.example.com:10443/a/check2", "", 404},
		// {"https://www.example.com:10443/static/", static, 200},
		// {"https://www.example.com:10443/static/foobar", static, 200},
		// {"https://www.example.com:10443/static", "", 301},
		// {"https://example.com:10443/", "", 301},
		// {"https://example.com:10443/a/check", "", 301},
		// {"https://example.com:10443/static", "", 301},
	}
	m := boot(port)
	for _, rt := range tests {
		checkRoute(t, m, rt)
	}
}

type webIt struct{}
func (i webIt) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(web))
}
type apiIt struct{}
func (i apiIt) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(api))
}
type staticIt struct{}
func (i staticIt) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(static))
}

func boot(port string) *http.ServeMux {
	return tlsMux("www.example.com", port, webIt{}, apiIt{}, staticIt{})
}

func checkRedir(t *testing.T, m *http.ServeMux, u redir) {
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
	if u.loc == "" && rr.Code != 200 {
		t.Errorf("wanted 200, got: %d", rr.Code)
	}
}

func checkRoute(t *testing.T, m *http.ServeMux, u route) {
	uu, err := url.Parse(u.url)
	if err != nil {
		t.Errorf("Input url broken: %s", u.url)
		return
	}
	host := uu.Host
	uu.Scheme = ""
	uu.Host = ""
	hd := make(http.Header)
	hd.Set("Accept", "*/*")
	r := &http.Request{
		Method: "GET",
		Host:   host,
		URL:    uu,
		RequestURI: uu.Path,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Proto: "HTTP/1.1",
		Header: hd,
		RemoteAddr: "[::1]:64331",
	}
	rr := httptest.NewRecorder()
	h, patt := m.Handler(r)
	t.Logf("Wtf is this %#v and %#v", h, patt)
	m.ServeHTTP(rr, r)
	bs, err := ioutil.ReadAll(rr.Body)
	actualBody := string(bs)
	if u.body != actualBody {
		t.Errorf("url: %s; wanted body %#v, got %#v", u.url, u.body, actualBody)
	}
	if u.code != rr.Code {
		t.Errorf("url: %s; wanted %d, got: %d", u.url, u.code, rr.Code)
	}
}
