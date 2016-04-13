package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"expvar"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jmhodges/howsmyssl/gzip"
	"github.com/jmhodges/howsmyssl/tls"
)

const (
	resp500Format = `HTTP/1.%d 500 Internal Server Error
Content-Length: 26
Connection: close
Content-Type: text/plain; charset="utf-8"
Strict-Transport-Security: max-age=631138519; includeSubdomains; preload
Date: %s

500 Internal Server Error
`
	hstsHeaderValue = "max-age=631138519; includeSubdomains; preload"
	xForwardedProto = "X-Forwarded-Proto"
)

var (
	httpsAddr = flag.String("httpsAddr", "localhost:10443", "address to boot the HTTPS server on")
	httpAddr  = flag.String("httpAddr", "localhost:10080", "address to boot the HTTP server on")
	rawVHost  = flag.String("vhost", "localhost:10443", "public domain to use in redirects and templates")
	certPath  = flag.String("cert", "./config/development.crt", "file path to the TLS certificate to serve with")
	keyPath   = flag.String("key", "./config/development.key", "file path to the TLS key to serve with")
	acmeURL   = flag.String("acmeRedirect", "/s/", "URL to join with .well-known/acme paths and redirect to")
	staticDir = flag.String("staticDir", "./static", "file path to the directory of static files to serve")
	tmplDir   = flag.String("templateDir", "./templates", "file path to the directory of templates")
	adminPort = flag.String("adminPort", "4567", "localhost port to boot the admin server on")

	apiVars         = expvar.NewMap("api")
	staticVars      = expvar.NewMap("static")
	webVars         = expvar.NewMap("web")
	apiRequests     = new(expvar.Int)
	staticRequests  = new(expvar.Int)
	webRequests     = new(expvar.Int)
	apiStatuses     = NewStatusStats(apiVars)
	staticStatuses  = NewStatusStats(staticVars)
	webStatuses     = NewStatusStats(webVars)
	commonRedirects = expvar.NewInt("common_redirects")

	nonAlphaNumeric = regexp.MustCompile("[^[:alnum:]]")

	index *template.Template
)

func main() {
	flag.Parse()

	routeHost, redirectHost := calculateDomains(*rawVHost, *httpsAddr)

	apiVars.Set("requests", apiRequests)
	staticVars.Set("requests", staticRequests)
	webVars.Set("requests", webRequests)

	index = loadIndex()
	tlsConf := makeTLSConfig(*certPath, *keyPath)

	tlsListener, err := tls.Listen("tcp", *httpsAddr, tlsConf)
	if err != nil {
		log.Fatalf("unable to listen for the HTTPS server on %s: %s", *httpsAddr, err)
	}
	plaintextListener, err := net.Listen("tcp", *httpAddr)
	if err != nil {
		log.Fatalf("unable to listen for the HTTP server on %s: %s", *httpAddr, err)
	}
	l := &listener{tlsListener}

	if *acmeURL != "" {
		if !strings.HasPrefix(*acmeURL, "/") &&
			!strings.HasPrefix(*acmeURL, "https://") &&
			!strings.HasPrefix(*acmeURL, "http://") {
			fmt.Fprintf(os.Stderr, "acmeRedirect must start with 'http://', 'https://', or '/' but does not: %#v\n", *acmeURL)
			os.Exit(1)
		}
	}

	m := tlsMux(
		routeHost,
		redirectHost,
		*acmeURL,
		makeStaticHandler(*staticDir, staticVars))

	adminAddr := net.JoinHostPort("localhost", *adminPort)
	go func() {
		err := http.ListenAndServe(adminAddr, nil)
		if err != nil {
			log.Fatalf("unable to open admin server: %s", err)
		}
	}()

	log.Printf("Booting HTTPS on %s and HTTP on %s", *httpsAddr, *httpAddr)
	go func() {
		err := http.Serve(l, m)
		if err != nil {
			log.Fatalf("https server error: %s", err)
		}
	}()
	err = http.Serve(plaintextListener, plaintextMux(redirectHost))
	if err != nil {
		log.Fatalf("http server error: %s", err)
	}
}

// Returns routeHost, redirectHost
func calculateDomains(vhost, httpsAddr string) (string, string) {
	var routeHost, redirectHost string
	// Use cases to support:
	//   * Redirect to non-standard HTTPS port (that is, not 443) that is the same as the port we're booting the HTTPS server on.
	//   * Redirect to non-standard HTTPS port (not 443) that is not the same as the one the HTTPS server is booted on. (We are behind a proxy, or using a linux container, etc.)
	//   * Redirect to a host on the standard HTTPS port, 443, without including the port as it might mix up certain clients, or, at least, look uncool.
	//   * Do all of the above knowing that the host we are booting on with httpsAddr might not be the one we want to use in redirects and templates.
	if strings.Contains(vhost, ":") {
		var err error
		vport := ""
		// We can drop port in routeHost here because http.ServeMux
		// doesn't currently know how to match against ports (see
		// https://golang.org/issue/10463) and we strip ports inside
		// protoHandler to accommodate that fact. If ServeMux learns
		// how to handle ports, we can choose to use *rawVHost for it
		// then.
		routeHost, vport, err = net.SplitHostPort(vhost)
		if err != nil {
			log.Fatalf("unable to parse httpsAddr: %s", err)
		}
		if routeHost == "" {
			routeHost, _, _ = net.SplitHostPort(httpsAddr)
			if routeHost == "" {
				routeHost = "localhost"
			}
		}
		// Don't commonRedirect to https://example.com:443, just https://example.com
		if vport == "443" {
			redirectHost = routeHost
		} else {
			redirectHost = vhost
		}
	} else {
		routeHost = vhost
		if routeHost == "" {
			routeHost, _, _ = net.SplitHostPort(httpsAddr)
			if routeHost == "" {
				routeHost = "localhost"
			}
		}
		redirectHost = routeHost
	}
	return routeHost, redirectHost
}

func tlsMux(routeHost, redirectHost, acmeRedirectURL string, staticHandler http.Handler) http.Handler {
	acmeRedirectURL = strings.TrimRight(acmeRedirectURL, "/")
	m := http.NewServeMux()
	m.Handle(routeHost+"/s/", staticHandler)
	m.HandleFunc(routeHost+"/a/check", handleAPI)
	m.HandleFunc(routeHost+"/", handleWeb)
	m.HandleFunc(routeHost+"/healthcheck", healthcheck)
	m.HandleFunc("/healthcheck", healthcheck)
	m.Handle(routeHost+"/.well-known/acme-challenge/", acmeRedirect(acmeRedirectURL))
	m.Handle("/", commonRedirect(redirectHost))
	return protoHandler{logHandler{m}, "https"}
}

func plaintextMux(redirectHost string) http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/healthcheck", healthcheck)
	m.Handle("/", commonRedirect(redirectHost))
	return protoHandler{logHandler{m}, "http"}
}

func renderHTML(r *http.Request, data *clientInfo) ([]byte, error) {
	b := new(bytes.Buffer)
	err := index.Execute(b, data)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func renderJSON(r *http.Request, data *clientInfo) ([]byte, error) {
	marshalled, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	callback := r.FormValue("callback")
	sanitizedCallback := nonAlphaNumeric.ReplaceAll([]byte(callback), []byte(""))

	if len(sanitizedCallback) > 0 {
		return []byte(fmt.Sprintf("%s(%s)", sanitizedCallback, marshalled)), nil
	} else {
		return marshalled, nil
	}
}

func handleWeb(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	webRequests.Add(1)
	hijackHandle(w, r, "text/html;charset=utf-8", webStatuses, renderHTML)
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	apiRequests.Add(1)
	hijackHandle(w, r, "application/json", apiStatuses, renderJSON)
}

func hijackHandle(w http.ResponseWriter, r *http.Request, contentType string, statuses *statusStats, render func(*http.Request, *clientInfo) ([]byte, error)) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Printf("server not hijackable\n")
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}

	c, brw, err := hj.Hijack()
	if err != nil {
		log.Printf("server errored during hijack: %s\n", err)
		return
	}
	defer c.Close()
	tc, ok := c.(*conn)
	if !ok {
		log.Printf("Unable to convert net.Conn to *conn: %s\n", err)
		hijacked500(brw, r.ProtoMinor, statuses)
	}
	data := ClientInfo(tc)
	bs, err := render(r, data)
	if err != nil {
		log.Printf("Unable to execute index template: %s\n", err)
		hijacked500(brw, r.ProtoMinor, statuses)
		return
	}
	contentLength := int64(len(bs))
	h := make(http.Header)
	h.Set("Date", time.Now().Format(http.TimeFormat))
	h.Set("Content-Type", contentType)
	if r.ProtoMinor == 1 { // Assumes HTTP/1.x
		h.Set("Connection", "close")
	}
	h.Set("Strict-Transport-Security", hstsHeaderValue)
	h.Set("Content-Length", strconv.FormatInt(contentLength, 10))
	// Allow CORS requests from any domain, for easy API access
	h.Set("Access-Control-Allow-Origin", "*")
	resp := &http.Response{
		StatusCode:    200,
		ContentLength: contentLength,
		Header:        h,
		Body:          ioutil.NopCloser(bytes.NewBuffer(bs)),
		ProtoMajor:    1, // Assumes HTTP/1.x
		ProtoMinor:    r.ProtoMinor,
	}
	bs, err = httputil.DumpResponse(resp, true)
	if err != nil {
		log.Printf("unable to write response: %s\n", err)
		hijacked500(brw, r.ProtoMinor, statuses)
		return
	}
	statuses.status2xx.Add(1)
	brw.Write(bs)
	brw.Flush()
}

func hijacked500(brw *bufio.ReadWriter, protoMinor int, statuses *statusStats) {
	statuses.status5xx.Add(1)
	// Assumes HTTP/1.x
	s := fmt.Sprintf(resp500Format, protoMinor, time.Now().Format(http.TimeFormat))
	brw.WriteString(s)
	brw.Flush()
}

func healthcheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("ok"))
}

func commonRedirect(redirectHost string) http.Handler {
	hf := func(w http.ResponseWriter, r *http.Request) {
		commonRedirects.Add(1)
		if r.Header.Get(xForwardedProto) == "https" {
			w.Header().Set("Strict-Transport-Security", hstsHeaderValue)
		}
		u := r.URL
		// Never set by the Go HTTP library.
		u.Scheme = "https"
		u.Host = redirectHost
		http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
	}
	return http.HandlerFunc(hf)
}

func loadIndex() *template.Template {
	return template.Must(template.New("index.html").
		Funcs(template.FuncMap{"sentence": sentence, "ratingSpan": ratingSpan}).
		ParseFiles(*tmplDir + "/index.html"))
}

func makeTLSConfig(certPath, keyPath string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("unable to load TLS key cert pair %s: %s", certPath, err)
	}

	tlsConf := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		NextProtos:               []string{"https"},
		PreferServerCipherSuites: true,
	}
	tlsConf.BuildNameToCertificate()
	return tlsConf
}

func makeStaticHandler(dir string, vars *expvar.Map) http.HandlerFunc {
	stats := NewStatusStats(vars)
	h := http.StripPrefix("/s/", http.FileServer(http.Dir(dir)))
	h = gzip.GZIPHandler(h, nil)
	return func(w http.ResponseWriter, r *http.Request) {
		staticRequests.Add(1)
		w = &statWriter{w: w, stats: stats}
		h.ServeHTTP(w, r)
	}
}

func ratingSpan(rating Rating) template.HTML {
	class := ""
	switch rating {
	case okay:
		class = "okay"
	case improvable:
		class = "improvable"
	case bad:
		class = "bad"
	}
	return template.HTML(class)
}

func sentence(parts []string) string {
	if len(parts) == 1 {
		return parts[0] + "."
	}
	commaed := parts[:len(parts)-1]
	return strings.Join(commaed, ", ") + ", and " + parts[len(parts)-1] + "."
}

type logHandler struct {
	inner http.Handler
}

// Since we have a Hijack in our code, this simple writer will suffice for
// now.
func (h logHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = "0.0.0.0"
	}
	proto := r.Header.Get(xForwardedProto)
	if proto == "" {
		proto = "unknown"
	}
	referrer := r.Header.Get("Referer")
	if referrer == "" {
		referrer = "noreferrer"
	}
	fmt.Printf("request: %s %s %s %s\n", host, proto, r.URL, referrer)
	h.inner.ServeHTTP(w, r)
}

type protoHandler struct {
	inner http.Handler
	proto string
}

func (h protoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Set(xForwardedProto, h.proto)
	// TODO(jmhodges): gross hack in order to get ServeMux to match ports
	// See https://golang.org/issue/10463
	host, _, err := net.SplitHostPort(r.Host)
	if err == nil {
		r.Host = host
	}
	h.inner.ServeHTTP(w, r)
}

type acmeRedirect string

func (a acmeRedirect) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if string(a) == "" {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNotFound)
	}
	if p == "/.well-known/acme-challenge/" {
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.RawQuery != "" {
		p += "?" + r.URL.RawQuery
	}
	http.Redirect(w, r, string(a)+p, http.StatusFound)
}
