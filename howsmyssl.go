package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
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

var (
	httpsAddr = flag.String("httpsAddr", "localhost:10443", "address to boot the HTTPS server on")
	httpAddr  = flag.String("httpAddr", "localhost:10080", "address to boot the HTTP server on")
	vhost     = flag.String("vhost", "localhost", "public domain to use in redirects and templates")
	certPath  = flag.String("cert", "./config/development.crt", "file path to the TLS certificate to serve with")
	keyPath   = flag.String("key", "./config/development.key", "file path to the TLS key to serve with")
	staticDir = flag.String("staticDir", "./static", "file path to the directory of static files to serve")
	tmplDir   = flag.String("templateDir", "./template", "file path to the directory of templates")

	index *template.Template
)

func main() {
	flag.Parse()
	index = template.Must(template.New("index.html").
		Funcs(template.FuncMap{"sentence": sentence}).
		ParseFiles(*tmplDir + "/index.html"))

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
	m.Handle(vhost+"/s/", staticHandler)
	m.Handle(vhost+"/a/check", apiHandler)
	m.Handle(vhost+"/", webHandler)
	m.Handle("/", tlsRedirect(vhost, port, webHandler))
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
	h := make(http.Header)
	h.Set("Date", time.Now().Format(http.TimeFormat))
	h.Set("Content-Type", contentType)
	h.Set("Connection", "close")
	tc, ok := c.(*conn)
	if !ok {
		log.Printf("Unable to convert net.Connn to *conn: %s\n", err)
		hijacked500(h, brw)
	}
	data := ClientInfo(tc)
	bs, err := render(data)
	if err != nil {
		log.Printf("Unable to excute index template: %s\n", err)
		hijacked500(h, brw)
		return
	}
	contentLength := int64(len(bs))
	h.Set("Content-Length", strconv.FormatInt(contentLength, 10))
	resp := &http.Response{
		StatusCode:    200,
		ContentLength: contentLength,
		Header:        h,
		Body:          ioutil.NopCloser(bytes.NewBuffer(bs)),
		ProtoMajor:    1,
		ProtoMinor:    1, // TODO(jmhodges): respond to HTTP/1.0 correctly
	}
	bs, err = httputil.DumpResponse(resp, true)
	if err != nil {
		log.Printf("unable to write response: %s\n", err)
		hijacked500(h, brw)
		return
	}
	brw.Write(bs)
	brw.Flush()
}

func hijacked500(h http.Header, brw *bufio.ReadWriter) {
	msg := []byte("500 Internal Server Error")
	h.Set("Content-Length", strconv.FormatInt(int64(len(msg)), 10))
	resp := &http.Response{
		StatusCode:    500,
		ContentLength: int64(len(msg)),
		Header:        h,
		Body:          ioutil.NopCloser(bytes.NewBuffer(msg)),
		ProtoMajor:    1,
		ProtoMinor:    1,
	}
	bs, _ := httputil.DumpResponse(resp, true)
	if bs != nil {
		brw.Write(bs)
	}
	brw.Flush()
}

func commonRedirect(w http.ResponseWriter, r *http.Request, vhostWithPort string) {
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
		if err == nil && vhost == host {
			webHandler.ServeHTTP(w, r)
			return
		}
		commonRedirect(w, r, vhostWithPort)
	}
	return h
}

func sentence(parts []string) string {
	if len(parts) == 1 {
		return parts[0] + "."
	}
	commaed := parts[:len(parts)-1]
	return strings.Join(commaed, ", ") + ", and " + parts[len(parts)-1] + "."
}
