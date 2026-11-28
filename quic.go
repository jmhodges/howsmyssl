package main

// HTTP/3 over QUIC. None of this runs unless -quicAddr is set.
//
// The TLS fork in tls1274/ can't carry QUIC here: golang.org/x/net/quic, like
// every other Go QUIC stack, is built on the standard crypto/tls. So a QUIC
// connection's handshake is done by crypto/tls, and we read the client's
// hello from the crypto/tls ClientHelloInfo that GetConfigForClient gets.
// The fields the rating uses are parsed there by the same upstream code that
// tls1274/ copies.
//
// GetConfigForClient isn't told which QUIC connection it's for, so we tie
// the two together with a value both sides of the finished handshake can
// compute and nobody else can: keying material exported under our own label
// (RFC 5705, RFC 8446 Section 7.5). The handshake records the hello under it,
// and the HTTP/3 server takes it back out when it accepts the connection.

import (
	"context"
	origtls "crypto/tls"
	"errors"
	"expvar"
	"flag"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/jmhodges/howsmyssl/h3"
	tls "github.com/jmhodges/howsmyssl/tls1274"
	"golang.org/x/net/quic"
)

const (
	// quicHelloLabel is the exporter label that keys a recorded hello.
	quicHelloLabel = "EXPORTER-howsmyssl-quic-client-hello"
	// quicHelloTTL is how long a recorded hello waits for its connection to
	// be accepted. It is longer than the QUIC handshake timeout.
	quicHelloTTL = time.Minute
)

var (
	quicAddr = flag.String("quicAddr", "", "UDP address to boot the HTTP/3 (QUIC) server on, like localhost:10443; HTTP/3 is off without it")

	quicVars          = expvar.NewMap("quic")
	quicConns         = new(expvar.Int)
	quicHellosMissing = new(expvar.Int)
	errNoQUICHello    = errors.New("no recorded ClientHello for this QUIC connection")
)

func init() {
	quicVars.Set("connections", quicConns)
	quicVars.Set("hellos_missing", quicHellosMissing)
}

// quicHello is what we keep of a client's hello on a QUIC connection.
type quicHello struct {
	CipherSuites      []uint16
	SupportedCurves   []origtls.CurveID
	SignatureSchemes  []origtls.SignatureScheme
	SupportedVersions []uint16
	Extensions        []uint16
	// Version is the TLS version the handshake negotiated.
	Version uint16
}

func newQUICHello(chi *origtls.ClientHelloInfo) *quicHello {
	return &quicHello{
		CipherSuites:      append([]uint16(nil), chi.CipherSuites...),
		SupportedCurves:   append([]origtls.CurveID(nil), chi.SupportedCurves...),
		SignatureSchemes:  append([]origtls.SignatureScheme(nil), chi.SignatureSchemes...),
		SupportedVersions: append([]uint16(nil), chi.SupportedVersions...),
		Extensions:        append([]uint16(nil), chi.Extensions...),
	}
}

type quicHelloKey struct{}

// quicHelloFromContext returns the hello of the QUIC connection a request
// came in on, if it came in on one.
func quicHelloFromContext(ctx context.Context) (*quicHello, bool) {
	h, ok := ctx.Value(quicHelloKey{}).(*quicHello)
	return h, ok
}

// helloRecorder holds hellos between the end of their handshake and the
// HTTP/3 server's accepting their connection.
type helloRecorder struct {
	mu        sync.Mutex
	hellos    map[string]recordedHello
	lastSweep time.Time
	now       func() time.Time
}

type recordedHello struct {
	hello *quicHello
	at    time.Time
}

func newHelloRecorder() *helloRecorder {
	return &helloRecorder{hellos: make(map[string]recordedHello), now: time.Now}
}

func (r *helloRecorder) put(key []byte, h *quicHello) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()
	// Connections that finish their handshake but are never accepted (the
	// peer went away first) leave their hellos here, so we drop old ones.
	if now.Sub(r.lastSweep) >= quicHelloTTL {
		for k, rh := range r.hellos {
			if now.Sub(rh.at) >= quicHelloTTL {
				delete(r.hellos, k)
			}
		}
		r.lastSweep = now
	}
	r.hellos[string(key)] = recordedHello{hello: h, at: now}
}

func (r *helloRecorder) take(key []byte) (*quicHello, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rh, ok := r.hellos[string(key)]
	if ok {
		delete(r.hellos, string(key))
	}
	return rh.hello, ok
}

func helloKey(cs origtls.ConnectionState) ([]byte, error) {
	return cs.ExportKeyingMaterial(quicHelloLabel, nil, 32)
}

// quicTLSConfig returns the crypto/tls configuration for QUIC connections.
// getCert is the TCP server's certificate source, so both serve the same,
// reloaded, certificate.
func quicTLSConfig(getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), rec *helloRecorder) *origtls.Config {
	base := &origtls.Config{
		MinVersion: origtls.VersionTLS13,
		NextProtos: []string{"h3"},
		// Like the TCP server's Connection: close, this keeps every
		// connection a full handshake, so every answer is about a fresh hello.
		SessionTicketsDisabled: true,
		GetCertificate: func(chi *origtls.ClientHelloInfo) (*origtls.Certificate, error) {
			c, err := getCert(&tls.ClientHelloInfo{ServerName: chi.ServerName})
			if err != nil || c == nil {
				return nil, err
			}
			return toOrigCertificate(c), nil
		},
	}
	conf := base.Clone()
	conf.GetConfigForClient = func(chi *origtls.ClientHelloInfo) (*origtls.Config, error) {
		h := newQUICHello(chi)
		c := base.Clone()
		c.VerifyConnection = func(cs origtls.ConnectionState) error {
			key, err := helloKey(cs)
			if err != nil {
				return err
			}
			h.Version = cs.Version
			rec.put(key, h)
			return nil
		}
		return c, nil
	}
	return conf
}

func toOrigCertificate(c *tls.Certificate) *origtls.Certificate {
	oc := &origtls.Certificate{
		Certificate:                 c.Certificate,
		PrivateKey:                  c.PrivateKey,
		OCSPStaple:                  c.OCSPStaple,
		SignedCertificateTimestamps: c.SignedCertificateTimestamps,
		Leaf:                        c.Leaf,
	}
	for _, s := range c.SupportedSignatureAlgorithms {
		oc.SupportedSignatureAlgorithms = append(oc.SupportedSignatureAlgorithms, origtls.SignatureScheme(s))
	}
	return oc
}

// listenQUIC starts listening for QUIC on the UDP address addr and returns
// the HTTP/3 server to serve handler on it.
func listenQUIC(addr string, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), handler http.Handler) (*h3.Server, *quic.Endpoint, error) {
	rec := newHelloRecorder()
	ep, err := quic.Listen("udp", addr, &quic.Config{
		TLSConfig: quicTLSConfig(getCert, rec),
		// Our pages need a handful of requests. These keep what one client
		// can make us hold small.
		MaxBidiRemoteStreams:    16,
		MaxUniRemoteStreams:     8,
		MaxStreamReadBufferSize: 64 << 10,
		MaxConnReadBufferSize:   256 << 10,
		HandshakeTimeout:        10 * time.Second,
		MaxIdleTimeout:          30 * time.Second,
	})
	if err != nil {
		return nil, nil, err
	}
	srv := &h3.Server{
		Handler:      handler,
		ConnContext:  quicConnContext(rec),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	return srv, ep, nil
}

func quicConnContext(rec *helloRecorder) func(context.Context, *quic.Conn) (context.Context, error) {
	return func(ctx context.Context, conn *quic.Conn) (context.Context, error) {
		quicConns.Add(1)
		key, err := helloKey(conn.ConnectionState())
		if err != nil {
			quicHellosMissing.Add(1)
			return nil, err
		}
		h, ok := rec.take(key)
		if !ok {
			quicHellosMissing.Add(1)
			return nil, errNoQUICHello
		}
		return context.WithValue(ctx, quicHelloKey{}, h), nil
	}
}

// startQUIC starts serving handler over HTTP/3 on the UDP address addr, and
// returns the function that shuts that server down. With an empty addr it
// starts nothing.
func startQUIC(addr string, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), handler http.Handler) func(context.Context) {
	if addr == "" {
		return func(context.Context) {}
	}
	srv, ep, err := listenQUIC(addr, getCert, handler)
	if err != nil {
		log.Fatalf("unable to listen for the HTTP/3 server on %s: %s", addr, err)
	}
	log.Printf("Booting HTTP/3 on %s", addr)
	go func() {
		err := srv.Serve(ep)
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("http/3 server error: %s", err)
		}
	}()
	return func(ctx context.Context) {
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("error shutting down HTTP/3: %s", err)
		}
	}
}

// writeClientInfo renders data and writes it as the response, as the end of
// handleTLSClientInfo does for TCP connections.
func writeClientInfo(w http.ResponseWriter, r *http.Request, data *clientInfo, render func(*http.Request, *clientInfo) ([]byte, int, string, error)) {
	bs, status, contentType, err := render(r, data)
	if err != nil {
		log.Printf("writeClientInfo: unable to execute render: %s\n", err)
		response500(w, r)
		return
	}
	defaultResponseHeaders(w.Header(), r, contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(bs)))
	w.WriteHeader(status)
	w.Write(bs)
}

// extensionSessionTicket is the session_ticket extension's codepoint, RFC
// 5077.
const extensionSessionTicket = 35

// pullQUICClientInfo describes and rates the hello of a client that came in
// over QUIC.
//
// QUIC carries only TLS 1.3 (RFC 9001, Section 4.2), so a QUIC client can't
// be made to use anything that only older versions of TLS have, whatever
// else its hello lists for its TCP connections. The checks of those things
// (BEAST, compression, cipher suites that are insecure or unknown) are left
// false, and the rating rests on what TLS 1.3 still leaves to the client:
// its key agreement above all.
func pullQUICClientInfo(h *quicHello, now time.Time) *clientInfo {
	d := &clientInfo{
		InsecureCipherSuites: make(map[string][]string),
		Transport:            "QUIC",
	}
	for _, ci := range h.CipherSuites {
		s, found := allCipherSuites[ci]
		if !found {
			s, found = weirdNSSSuites[ci]
		}
		if !found {
			s = fmt.Sprintf("Some unknown cipher suite: %#04x", ci)
		}
		d.GivenCipherSuites = append(d.GivenCipherSuites, s)
	}
	d.EphemeralKeysSupported = offersTLS13Handshake(h.CipherSuites, h.SupportedVersions)

	d.GivenNamedGroups = []string{}
	for _, gid := range h.SupportedCurves {
		id := uint16(gid)
		name, found := allNamedGroups[id]
		if !found {
			name = fmt.Sprintf("Unknown named group: %#04x", id)
		}
		if postQuantumGroups[id] {
			d.PostQuantumKeyAgreement = true
		}
		d.GivenNamedGroups = append(d.GivenNamedGroups, name)
	}

	sigs := make([]tls.SignatureScheme, 0, len(h.SignatureSchemes))
	for _, s := range h.SignatureSchemes {
		sigs = append(sigs, tls.SignatureScheme(s))
	}
	d.GivenSignatureAlgorithms = renderSignatureSchemes(sigs)
	d.SessionTicketsSupported = slices.Contains(h.Extensions, extensionSessionTicket)

	d.TLSVersion = actualSupportedVersions[h.Version]
	if d.TLSVersion == "" {
		d.TLSVersion = "an unknown version of SSL/TLS"
	}

	// These are pullClientInfo's rating rules for a client whose version is
	// TLS 1.3 and that has none of the older-TLS problems above.
	// TestQUICRatingMatchesTCP checks that the two agree.
	d.TLS12ImprovableCutoverPassed = !now.Before(tls12ImprovableCutover)
	d.TLS12BadCutoverPassed = !now.Before(tls12BadCutover)
	d.NoPQImprovableCutoverPassed = !now.Before(noPQImprovableCutover)
	d.NoPQBadCutoverPassed = !now.Before(noPQBadCutover)
	d.Rating = okay
	if !d.EphemeralKeysSupported || (!d.PostQuantumKeyAgreement && d.NoPQImprovableCutoverPassed) {
		d.Rating = improvable
	}
	if h.Version < tls.VersionTLS13 || (!d.PostQuantumKeyAgreement && d.NoPQBadCutoverPassed) {
		d.Rating = bad
	}
	return d
}
