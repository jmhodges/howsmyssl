package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/jmhodges/howsmyssl/tls"
	"html/template"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
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
	vhost     = flag.String("vhost", "localhost", "public domain to use in redirects and templates")
	certPath  = flag.String("cert", "./config/development.crt", "file path to the TLS certificate to serve with")
	keyPath   = flag.String("key", "./config/development.key", "file path to the TLS key to serve with")
	staticDir = flag.String("staticDir", "./static", "file path to the directory of static files to serve")
	tmplDir   = flag.String("templateDir", "./templates", "file path to the directory of templates")

	index *template.Template
)

func main() {
	flag.Parse()
	index = loadIndex()
	_, httpsPort, err := net.SplitHostPort(*httpsAddr)
	if err != nil {
		log.Fatalf("unable to parse httpsAddr: %s", err)
	}
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		log.Fatalf("unable to load TLS key cert pair %s: %s", certPath, err)
	}

	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"https"},
	}
	tlsConf.BuildNameToCertificate()

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
		*vhost,
		httpsPort,
		http.HandlerFunc(handleWeb),
		http.HandlerFunc(handleAPI),
		http.StripPrefix("/s/", http.FileServer(http.Dir(*staticDir))))

	log.Printf("Booting HTTPS on %s and HTTP on %s", *httpsAddr, *httpAddr)
	go func() {
		err := http.Serve(l, m)
		if err != nil {
			log.Fatalf("https server error: %s", err)
		}
	}()
	err = http.Serve(plaintextListener, plaintextRedirect(*vhost, httpsPort))
	if err != nil {
		log.Fatalf("http server error: %s", err)
	}
}

func tlsMux(vhost, port string, webHandler, apiHandler, staticHandler http.Handler) *http.ServeMux {
	m := http.NewServeMux()
	prefix := vhost
	if port != "443" {
		prefix = net.JoinHostPort(vhost, port)
	}
	m.Handle(prefix+"/s/", logHandler{staticHandler})
	m.Handle(prefix+"/a/check", logHandler{apiHandler})
	m.Handle(prefix+"/", logHandler{webHandler})
	m.Handle("/", logHandler{tlsRedirect(vhost, port, webHandler)})
	return m
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

	hijackHandle(w, r, "text/html;charset=utf-8", renderHTML)
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	hijackHandle(w, r, "application/json", renderJSON)
}

func hijackHandle(w http.ResponseWriter, r *http.Request, contentType string, render func(*clientInfo) ([]byte, error)) {
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
		hijacked500(brw, r.ProtoMinor)
	}
	data := ClientInfo(tc)
	bs, err := render(data)
	if err != nil {
		log.Printf("Unable to excute index template: %s\n", err)
		hijacked500(brw, r.ProtoMinor)
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
		hijacked500(brw, r.ProtoMinor)
		return
	}
	brw.Write(bs)
	brw.Flush()
}

func hijacked500(brw *bufio.ReadWriter, protoMinor int) {
	// Assumes HTTP/1.x
	s := fmt.Sprintf(resp500Format, protoMinor, time.Now().Format(http.TimeFormat))
	brw.WriteString(s)
	brw.Flush()
}

func commonRedirect(w http.ResponseWriter, r *http.Request, vhostWithPort string) {
	if r.URL.Path == "/healthcheck" {
		w.WriteHeader(200)
		return
	}
	var u url.URL
	u = *r.URL
	u.Scheme = "https"
	u.Host = vhostWithPort
	http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
}

func plaintextRedirect(vhost, port string) http.Handler {
	if port != "443" {
		vhost = net.JoinHostPort(vhost, port)
	}
	var h http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		commonRedirect(w, r, vhost)
	}
	return h
}

func tlsRedirect(vhost, port string, webHandler http.Handler) http.Handler {
	vhostWithPort := vhost
	if port != "443" {
		vhostWithPort = net.JoinHostPort(vhost, port)
	}
	var h http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if vhost == host {
			webHandler.ServeHTTP(w, r)
			return
		}
		commonRedirect(w, r, vhostWithPort)
	}
	return h
}

func loadIndex() *template.Template {
	return template.Must(template.New("index.html").
		Funcs(template.FuncMap{"sentence": sentence, "ratingSpan": ratingSpan}).
		ParseFiles(*tmplDir + "/index.html"))

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
}

// Since we have a Hijack in our code, this simple writer will suffice for
// now.
func (h logHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = "0.0.0.0"
	}
	fmt.Printf("%s %s\n", host, r.URL)
	h.inner.ServeHTTP(w, r)
}
