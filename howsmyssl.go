package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"expvar"
	"flag"
	"fmt"
	"github.com/jmhodges/howsmyssl/tls"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	resp500Format = `HTTP/1.%d 500 Internal Server Error
Content-Length: 26
Connection: close
Content-Type: text/plain; charset="utf-8"
Date: %s

500 Internal Server Error
`
)

var (
	httpsAddr = flag.String("httpsAddr", "localhost:10443", "address to boot the HTTPS server on")
	httpAddr  = flag.String("httpAddr", "localhost:10080", "address to boot the HTTP server on")
	vhost     = flag.String("vhost", "localhost:10443", "public domain to use in redirects and templates")
	certPath  = flag.String("cert", "./config/development.crt", "file path to the TLS certificate to serve with")
	keyPath   = flag.String("key", "./config/development.key", "file path to the TLS key to serve with")
	staticDir = flag.String("staticDir", "./static", "file path to the directory of static files to serve")
	tmplDir   = flag.String("templateDir", "./templates", "file path to the directory of templates")

	apiVars        = expvar.NewMap("api")
	staticVars     = expvar.NewMap("static")
	webVars        = expvar.NewMap("web")
	apiRequests    = new(expvar.Int)
	staticRequests = new(expvar.Int)
	webRequests    = new(expvar.Int)
	apiStatuses    = NewStatusStats(apiVars)
	staticStatuses = NewStatusStats(staticVars)
	webStatuses    = NewStatusStats(webVars)

	index *template.Template
)

func main() {
	flag.Parse()

	host := *vhost
	if strings.Contains(*vhost, ":") {
		var err error
		shost, port, err := net.SplitHostPort(*vhost)
		if err != nil {
			log.Fatalf("unable to parse httpsAddr: %s", err)
		}
		host = shost
		if port != "443" {
			host = *vhost
		}
	}

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

	m := tlsMux(
		host,
		makeStaticHandler())

	go func() {
		err := http.ListenAndServe("localhost:4567", nil)
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
	err = http.Serve(plaintextListener, plaintextMux(host))
	if err != nil {
		log.Fatalf("http server error: %s", err)
	}
}

func tlsMux(vhost string, staticHandler http.Handler) http.Handler {
	m := http.NewServeMux()
	m.Handle(vhost+"/s/", staticHandler)
	m.HandleFunc(vhost+"/a/check", handleAPI)
	m.HandleFunc(vhost+"/", handleWeb)
	m.HandleFunc(vhost+"/healthcheck", healthcheck)
	m.HandleFunc("/healthcheck", healthcheck)
	m.Handle("/", commonRedirect(vhost))
	return logHandler{inner: m, proto: "https"}
}

func plaintextMux(vhost string) http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/healthcheck", healthcheck)
	m.Handle("/", commonRedirect(vhost))
	return logHandler{inner: m, proto: "http"}
}

func renderHTML(data *clientInfo) ([]byte, error) {
	b := new(bytes.Buffer)
	err := index.Execute(b, data)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func renderJSON(data *clientInfo) ([]byte, error) {
	return json.Marshal(data)
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

func hijackHandle(w http.ResponseWriter, r *http.Request, contentType string, statuses *statusStats, render func(*clientInfo) ([]byte, error)) {
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
	bs, err := render(data)
	if err != nil {
		log.Printf("Unable to excute index template: %s\n", err)
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
	h.Set("Content-Length", strconv.FormatInt(contentLength, 10))
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

func commonRedirect(vhost string) http.Handler {
	hf := func(w http.ResponseWriter, r *http.Request) {
		var u url.URL
		u = *r.URL
		u.Scheme = "https"
		u.Host = vhost
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
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"https"},
	}
	tlsConf.BuildNameToCertificate()
	return tlsConf
}

func makeStaticHandler() http.HandlerFunc {
	stats := NewStatusStats(staticVars)
	h := http.StripPrefix("/s/", http.FileServer(http.Dir(*staticDir)))
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
	return template.HTML(fmt.Sprintf(`<span class="%s">%s</span>`, class, rating))
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
	proto string
}

// Since we have a Hijack in our code, this simple writer will suffice for
// now.
func (h logHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = "0.0.0.0"
	}
	fmt.Printf("%s %s %s\n", host, h.proto, r.URL)
	h.inner.ServeHTTP(w, r)
}
