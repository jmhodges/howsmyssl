package main

import (
	"bytes"
	"context"
	"encoding/json"
	"expvar"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"cloud.google.com/go/logging"
	"github.com/jmhodges/howsmyssl/gzip"
	tls "github.com/jmhodges/howsmyssl/tls110"
	"golang.org/x/exp/slog"
	"google.golang.org/api/option"
)

const (
	hstsHeaderValue = "max-age=631138519; includeSubdomains; preload"
	xForwardedProto = "X-Forwarded-Proto"
)

var (
	httpsAddr      = flag.String("httpsAddr", "localhost:10443", "address to boot the HTTPS server on")
	httpAddr       = flag.String("httpAddr", "localhost:10080", "address to boot the HTTP server on")
	rawVHost       = flag.String("vhost", "localhost:10443", "public domain to use in redirects and templates")
	certPath       = flag.String("cert", "./config/development_cert.pem", "file path to the TLS certificate to serve with")
	keyPath        = flag.String("key", "./config/development_key.pem", "file path to the TLS key to serve with")
	acmeURL        = flag.String("acmeRedirect", "/s/", "URL to join with .well-known/acme paths and redirect to")
	allowListsFile = flag.String("allowListsFile", "", "file path to find the allowlists JSON file")
	googAcctConf   = flag.String("googAcctConf", "", "file path to a Google service account JSON configuration")
	allowLogName   = flag.String("allowLogName", "test_howsmyssl_allowance_checks", "the name to Google Cloud Logging log to send API allowance check data to")
	staticDir      = flag.String("staticDir", "./static", "file path to the directory of static files to serve")
	tmplDir        = flag.String("templateDir", "./templates", "file path to the directory of templates")
	adminAddr      = flag.String("adminAddr", "localhost:4567", "address to boot the admin server on")
	headless       = flag.Bool("headless", false, "Run without templates")

	apiVars         = expvar.NewMap("api")
	staticVars      = expvar.NewMap("static")
	webVars         = expvar.NewMap("web")
	apiRequests     = new(expvar.Int)
	staticRequests  = new(expvar.Int)
	webRequests     = new(expvar.Int)
	apiStatuses     = newStatusStats(apiVars)
	staticStatuses  = newStatusStats(staticVars)
	webStatuses     = newStatusStats(webVars)
	commonRedirects = expvar.NewInt("common_redirects")

	nonAlphaNumeric = regexp.MustCompile("[^[:alnum:]]")

	index *template.Template
)

type contextKey struct{ name string }

func (k *contextKey) String() string { return "howsmyssl context value " + k.name }

// smuggledConnKey is for smuggling our wrapping *conn to the apiHandler that
// needs its conn.Conn.ConnectionState to investigate the client's TLS settings.
var smuggledConnKey = &contextKey{"smuggledConn"}

func main() {
	flag.Parse()
	t := time.Now()
	expvar.NewInt("start_time_epoch_secs").Set(t.Unix())
	expvar.NewString("start_time_timestamp").Set(t.Format(time.RFC3339))
	expvar.Publish("uptime_secs", expvar.Func(func() interface{} {
		return int64(time.Since(t) / time.Second)
	}))
	expvar.Publish("uptime_dur", expvar.Func(func() interface{} {
		return time.Since(t).String()
	}))

	routeHost, redirectHost := calculateDomains(*rawVHost, *httpsAddr)

	apiVars.Set("requests", apiRequests)
	staticVars.Set("requests", staticRequests)
	webVars.Set("requests", webRequests)

	tlsConf := makeTLSConfig(*certPath, *keyPath)

	tlsListener, err := tls.Listen("tcp", *httpsAddr, tlsConf)
	if err != nil {
		log.Fatalf("unable to listen for the HTTPS server on %s: %s", *httpsAddr, err)
	}
	plaintextListener, err := net.Listen("tcp", *httpAddr)
	if err != nil {
		log.Fatalf("unable to listen for the HTTP server on %s: %s", *httpAddr, err)
	}
	ns := expvar.NewMap("tls")
	l := newListener(tlsListener, ns)

	if *acmeURL != "" {
		if !strings.HasPrefix(*acmeURL, "/") &&
			!strings.HasPrefix(*acmeURL, "https://") &&
			!strings.HasPrefix(*acmeURL, "http://") {
			fmt.Fprintf(os.Stderr, "acmeRedirect must start with 'http://', 'https://', or '/' but does not: %#v\n", *acmeURL)
			os.Exit(1)
		}
	}

	am := &allowMaps{
		AllowTheseDomains: make(map[string]bool),
		AllowSubdomainsOn: make(map[string]bool),
		BlockedDomains:    make(map[string]bool),
	}
	ama := &atomic.Pointer[allowMaps]{}
	ama.Store(am)
	if *allowListsFile != "" {
		am, err := loadAllowMaps(*allowListsFile)
		if err != nil {
			log.Fatal(err)
		}
		ama.Store(am)
		alTick := time.NewTicker(20 * time.Second)
		go reloadAllowMapsForever(*allowListsFile, ama, alTick)
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("unable to get hostname of local machine: %s", err)
	}

	var gclog logClient
	if *googAcctConf != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		googConf := loadGoogleServiceAccount(*googAcctConf)
		client, err := logging.NewClient(ctx,
			googConf.ProjectID,
			option.WithCredentialsFile(*googAcctConf),
		)
		if err != nil {
			log.Fatalf("unable to make Google Cloud Logging client: %s", err)
		}
		client.OnError = func(err error) {
			log.Printf("goog logging error: %s", err)
		}
		err = client.Ping(ctx)
		if err != nil {
			// Requiring a working connection to Google Cloud Logging at boot
			// assumes that the uptime of Cloud Logging is better than our
			// uptime of configuration for this service. We're choosing to
			// believe we'll screw up our configuration more than that service
			// will be down. We may be wrong, but our deploys are fast when we
			// are.
			log.Fatalf("unable to ping Google Cloud Logging at boot time: %s", err)
		}
		gclog = client.Logger(*allowLogName)
	} else {
		gclog = nullLogClient{}
	}

	allowErrLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{AddSource: true})).WithGroup("originAllower.errors")
	oa := newOriginAllower(ama, hostname, gclog, expvar.NewMap("origins"), allowErrLogger)

	staticHandler := http.NotFoundHandler()
	webHandleFunc := http.NotFound
	if !*headless {
		index = loadIndex()
		staticHandler = makeStaticHandler(*staticDir, staticStatuses)
		webHandleFunc = handleWeb
	}

	stdoutLogger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	requestLogger := stdoutLogger.WithGroup("requests")
	m := tlsMux(
		routeHost,
		redirectHost,
		*acmeURL,
		staticHandler,
		webHandleFunc,
		oa,
		requestLogger,
		stdoutLogger.WithGroup("originAllower"),
	)

	go func() {
		err := http.ListenAndServe(*adminAddr, nil)
		if err != nil {
			log.Fatalf("unable to open admin server: %s", err)
		}
	}()

	httpsSrv := &http.Server{Handler: m}
	configureHTTPSServer(httpsSrv)

	httpSrv := &http.Server{
		Handler:      plaintextMux(redirectHost, requestLogger),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	log.Printf("Booting HTTPS on %s and HTTP on %s", *httpsAddr, *httpAddr)
	go func() {
		err := httpsSrv.Serve(l)
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("https server error: %s", err)
		}
	}()
	go func() {
		err := httpSrv.Serve(plaintextListener)
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("http server error: %s", err)
		}
	}()

	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := httpsSrv.Shutdown(ctx)
		if err != nil {
			log.Printf("error shutting down HTTPS: %s", err)
		}
	}()
	go func() {
		defer wg.Done()
		err := httpSrv.Shutdown(ctx)
		if err != nil {
			log.Printf("error shutting down HTTP: %s", err)
		}
	}()
	wg.Wait()
	cancel()
	gclog.Flush()
}

func configureHTTPSServer(srv *http.Server) {
	// If you add HTTP/2 or HTTP/3 support here, be sure that the Connection:
	// close header is being set properly elsewhere
	srv.ReadTimeout = 10 * time.Second
	srv.WriteTimeout = 15 * time.Second
	srv.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		tc, ok := c.(*conn)
		if !ok {
			log.Printf("Server.ConnContext: unable to convert net.Conn to *conn: %#v\n", c)
			return ctx
		}
		// We do this smuggling instead of using http.Hijcker.Hijack to avoid
		// needing to do a bunch of connection management and HTTP response
		// formatting ourselves. We smuggle the whole *conn into the context
		// instead of just its ConnectionState because the handshake may not yet
		// be performed, and I don't want to lock here waiting for the handshake
		// to finish. It might be fine, but I've not verified there's nothing
		// that would be delayed by doing so.
		ctx = context.WithValue(ctx, smuggledConnKey, tc)
		return ctx
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

func tlsMux(routeHost, redirectHost, acmeRedirectURL string, staticHandler http.Handler, webHandleFunc http.HandlerFunc, oa *originAllower, requestLogger *slog.Logger, allowLogger *slog.Logger) http.Handler {
	acmeRedirectURL = strings.TrimRight(acmeRedirectURL, "/")
	m := http.NewServeMux()
	m.Handle(routeHost+"/s/", staticHandler)
	m.Handle(routeHost+"/a/check", &apiHandler{oa: oa, allowLogger: allowLogger})
	m.HandleFunc(routeHost+"/", webHandleFunc)
	m.HandleFunc(routeHost+"/healthcheck", healthcheck)
	if routeHost != "" {
		m.HandleFunc("/healthcheck", healthcheck)
	}
	m.Handle(routeHost+"/.well-known/acme-challenge/", acmeRedirect(acmeRedirectURL))
	if routeHost != "" {
		m.Handle("/", commonRedirect(redirectHost))
	}

	gzippedM := gzip.GZIPHandler(m, func(w http.ResponseWriter, r *http.Request) bool {
		return !strings.Contains(r.URL.Path, "/img/")
	})
	wrapper := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", hstsHeaderValue)
		if r.ProtoMajor == 1 && r.ProtoMinor == 1 {
			// We always disconnect folks after their request is done to ensure
			// we don't keep our tls.Conn fork with it's extra large memory
			// needs (including the `clientHelloMsg`) around for too long. This
			// also helps prevent any TLS resumptions from happening and
			// breaking our vuln detection. We do this on all requests to avoid
			// races.
			w.Header().Set("Connection", "close")
		}
		gzippedM.ServeHTTP(w, r)
	})
	return protoHandler{logHandler{wrapper, requestLogger}, "https"}
}

func plaintextMux(redirectHost string, requestLogger *slog.Logger) http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/healthcheck", healthcheck)
	m.Handle("/", commonRedirect(redirectHost))
	return protoHandler{logHandler{m, requestLogger}, "http"}
}

const htmlContentType = "text/html;charset=utf-8"

func renderHTML(r *http.Request, data *clientInfo) ([]byte, int, string, error) {
	b := new(bytes.Buffer)
	err := index.Execute(b, data)
	if err != nil {
		return nil, 0, "", err
	}
	return b.Bytes(), http.StatusOK, htmlContentType, nil
}

func disallowedRenderJSON(r *http.Request, data *clientInfo) ([]byte, int, string, error) {
	callback := r.FormValue("callback")
	sanitizedCallback := nonAlphaNumeric.ReplaceAll([]byte(callback), []byte(""))

	if len(sanitizedCallback) != 0 {
		body := []byte(fmt.Sprintf("%s(%s);", sanitizedCallback, disallowedOriginBody))
		// Browsers won't run this code unless the status is OK.
		return body, http.StatusOK, "application/javascript", nil

	}
	return disallowedOriginBody, http.StatusBadRequest, "application/json", nil
}

func allowedRenderJSON(r *http.Request, data *clientInfo) ([]byte, int, string, error) {
	callback := r.FormValue("callback")
	sanitizedCallback := nonAlphaNumeric.ReplaceAll([]byte(callback), []byte(""))

	marshalled, err := json.Marshal(data)
	if err != nil {
		return nil, 0, htmlContentType, err
	}
	if len(sanitizedCallback) > 0 {
		return []byte(fmt.Sprintf("%s(%s);", sanitizedCallback, marshalled)), http.StatusOK, "application/javascript", nil
	}

	return marshalled, http.StatusOK, "application/json", nil
}

func handleWeb(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	webRequests.Add(1)
	handleTLSClientInfo(w, r, webStatuses, renderHTML)
}

var (
	// disallowedOriginBody's tls_version has a special format in order to
	// ensure that folks with weird JavaScript parsing conditions show their
	// users a failure. We've seen `tls_version.split(' ')[1] < 1.2` without any
	// other checks, so we have that 0 in there. The "Err" is intentionally 3
	// characters long to avoid anyone parsing it by character count. (We've not
	// seen that 3 char check, but I can imagine it.)
	disallowedOriginBody = []byte(`{"error": "See tls_version for the sign up link", "tls_version": "Err 0 The website calling howsmyssl.com's API has been making many calls and does not have a subscription. See https://subscriptions.howsmyssl.com/signup for how to get one."}`)
)

type apiHandler struct {
	oa          *originAllower
	allowLogger *slog.Logger
}

func (ah *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	apiRequests.Add(1)

	detectedDomain, ok := ah.oa.Allow(r)

	renderJSON := allowedRenderJSON
	if !ok {
		renderJSON = disallowedRenderJSON
	}

	ah.allowLogger.InfoContext(r.Context(), "API allowance decision", "detectedDomain", detectedDomain, "allowed", ok, "originHeader", r.Header.Get("Origin"), "referrerHeader", r.Header.Get("Referer"))
	handleTLSClientInfo(w, r, apiStatuses, renderJSON)
}

func handleTLSClientInfo(w http.ResponseWriter, r *http.Request, statuses *statusStats, render func(*http.Request, *clientInfo) ([]byte, int, string, error)) {
	// Instead of using w.(http.Hijacker).Hijack to pull the underlying
	// connection, we grab the one we smuggled into the context for this
	// request. We do this smuggling instead of using http.Hijcker.Hijack to
	// avoid needing to do a bunch of connection management and HTTP response
	// formatting ourselves.
	w = &statWriter{w: w, stats: statuses}
	c := r.Context().Value(smuggledConnKey)
	tc, ok := c.(*conn)
	if !ok {
		log.Printf("handleTLSClientInfo: unable to convert smuggledConnKey to *conn: %#v", c)
		response500(w, r)
		return
	}
	data := pullClientInfo(tc)
	bs, status, contentType, err := render(r, data)
	if err != nil {
		log.Printf("handleTLSClientInfo: unable to execute render: %s\n", err)
		response500(w, r)
		return
	}
	defaultResponseHeaders(w.Header(), r, contentType)
	contentLength := int64(len(bs))
	// We set Content-Length here to stay backwards compatiable with some
	// clients who wouldn't be able to handle a `Transfer-Encoding: chunked`
	// response. The Go http server won't automatically add it over a few KB.
	w.Header().Set("Content-Length", strconv.FormatInt(contentLength, 10))
	w.WriteHeader(status)
	w.Write(bs)
}

func defaultResponseHeaders(h http.Header, r *http.Request, contentType string) {
	h.Set("Content-Type", contentType)
	// Allow CORS requests from any domain, for easy API access
	h.Set("Access-Control-Allow-Origin", "*")
}

func response500(w http.ResponseWriter, r *http.Request) {
	defaultResponseHeaders(w.Header(), r, "text/plain")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte("500 Internal Server Error"))
}

func healthcheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Write([]byte("ok"))
}

func commonRedirect(redirectHost string) http.Handler {
	hf := func(w http.ResponseWriter, r *http.Request) {
		commonRedirects.Add(1)
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
	kpr, err := newKeypairReloader(certPath, keyPath)
	if err != nil {
		log.Fatalf("unable to load TLS key cert pair %s: %s", certPath, err)
	}
	go reloadKeypairForever(kpr, time.NewTicker(1*time.Hour))
	tlsConf := &tls.Config{
		GetCertificate:           kpr.GetCertificate,
		NextProtos:               []string{"https"},
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionSSL30,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	}
	tlsConf.BuildNameToCertificate()
	return tlsConf
}

func makeStaticHandler(dir string, stats *statusStats) http.HandlerFunc {
	h := http.StripPrefix("/s/", http.FileServer(http.Dir(dir)))
	return func(w http.ResponseWriter, r *http.Request) {
		staticRequests.Add(1)
		w = &statWriter{w: w, stats: stats}
		h.ServeHTTP(w, r)
	}
}

func ratingSpan(r rating) template.HTML {
	class := ""
	switch r {
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
	inner         http.Handler
	requestLogger *slog.Logger
}

// TODO(#537): use a real logging handler. This simple writer was made because
// the Hijack we previously had in our handlers wouldn't let us use the typical
// logging ones.
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
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "noorigin"
	}
	userAgent := r.Header.Get("User-Agent")
	if userAgent == "" {
		userAgent = "nouseragent"
	}
	tlsConn, ok := r.Context().Value(smuggledConnKey).(*conn)
	tlsVersion := "none"
	if ok && tlsConn != nil {
		version := tlsConn.ConnectionState().Version
		tlsVersion = actualSupportedVersions[version]
	}
	h.requestLogger.InfoContext(r.Context(), "request", "host", host, "proto", proto, "requestURL", r.URL, "referrerHeader", referrer, "originHeader", origin, "userAgent", userAgent, "tlsVersion", tlsVersion)
	h.inner.ServeHTTP(w, r)
}

type protoHandler struct {
	inner http.Handler
	proto string
}

func (h protoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Header.Set(xForwardedProto, h.proto)
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
