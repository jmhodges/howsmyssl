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
	"container/list"
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
	// quicHelloKeyLen is how many bytes of keying material key a hello.
	quicHelloKeyLen = 32
	// quicHandshakeTimeout is how long a QUIC handshake may take.
	quicHandshakeTimeout = 10 * time.Second
)

var (
	quicAddr = flag.String("quicAddr", "", "UDP address to boot the HTTP/3 (QUIC) server on, like localhost:10443; HTTP/3 is off without it")

	quicVars          = expvar.NewMap("quic")
	quicConns         = new(expvar.Int)
	quicHellosMissing = new(expvar.Int)
	quicHellosEvicted = new(expvar.Int)
	errNoQUICHello    = errors.New("no recorded ClientHello for this QUIC connection")
	errQUICHelloBig   = errors.New("QUIC ClientHello is bigger than the hello recorder holds")
)

func init() {
	quicVars.Set("connections", quicConns)
	quicVars.Set("hellos_missing", quicHellosMissing)
	quicVars.Set("hellos_evicted", quicHellosEvicted)
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

// quicHelloListMax is the most entries of each of a hello's lists we keep. A
// ClientHello can be near 64 KB, but no real client lists anywhere near this
// many cipher suites, groups, signature schemes, versions or extensions, and
// it bounds what one recorded hello costs us.
const quicHelloListMax = 128

func firstN[T any](s []T) []T {
	return append([]T(nil), s[:min(len(s), quicHelloListMax)]...)
}

func newQUICHello(chi *origtls.ClientHelloInfo) *quicHello {
	return &quicHello{
		CipherSuites:      firstN(chi.CipherSuites),
		SupportedCurves:   firstN(chi.SupportedCurves),
		SignatureSchemes:  firstN(chi.SignatureSchemes),
		SupportedVersions: firstN(chi.SupportedVersions),
		Extensions:        firstN(chi.Extensions),
	}
}

// quicHelloMaxSize is the most a recorded hello costs us, by size, with its
// key.
const quicHelloMaxSize = 128 + 2*5*quicHelloListMax + quicHelloKeyLen

// size is roughly what h costs us to hold, in bytes.
func (h *quicHello) size() int {
	// Every list's elements are two bytes wide.
	return 128 + 2*(len(h.CipherSuites)+len(h.SupportedCurves)+len(h.SignatureSchemes)+len(h.SupportedVersions)+len(h.Extensions))
}

type quicHelloKey struct{}

// quicHelloFromContext returns the hello of the QUIC connection a request
// came in on, if it came in on one.
func quicHelloFromContext(ctx context.Context) (*quicHello, bool) {
	h, ok := ctx.Value(quicHelloKey{}).(*quicHello)
	return h, ok
}

// helloRecorder holds hellos between their handshake's recording them and
// the HTTP/3 server's accepting their connection.
//
// The server records a hello before the client has sent its Finished (see
// quicTLSConfig), so a client that sends a ClientHello and walks away leaves
// one here. Anyone can do that, from any source address, since we don't
// require QUIC address validation. So the recorder holds at most maxEntries
// hellos and maxBytes of them, each for at most ttl, and a full recorder
// evicts its oldest hellos to make room for a new one instead of growing.
//
// Evicting, rather than refusing new handshakes while full, is what keeps a
// flood of abandoned handshakes from turning QUIC off: refusing would take
// only enough of them to fill the recorder once per ttl (4096 per 15s),
// while pushing out a real client's hello takes maxEntries new ones between
// its handshake's recording it and its connection's being accepted, about
// one round trip. A client whose hello is evicted anyway finds none at
// accept (quicHellosMissing) and its connection is closed, so it falls back
// to TCP; it never gets another connection's hello.
type helloRecorder struct {
	mu     sync.Mutex
	hellos map[string]*list.Element // of *recordedHello, oldest first in order
	order  *list.List
	bytes  int

	ttl        time.Duration
	maxEntries int
	maxBytes   int
	now        func() time.Time
}

type recordedHello struct {
	key   string
	hello *quicHello
	size  int
	at    time.Time
}

const (
	// quicHelloTTL is how long a recorded hello waits for its connection to
	// be accepted. It is a little longer than quicHandshakeTimeout, after
	// which the connection can't be accepted anymore.
	quicHelloTTL = 15 * time.Second
	// quicHelloMaxEntries and quicHelloMaxBytes cap the hellos waiting to
	// be accepted. A hello costs at most quicHelloMaxSize, about 1.4 KB,
	// and a real one a few hundred bytes, so the entry cap usually binds
	// first, and the bytes cap holds it to 4 MB whatever the hellos.
	quicHelloMaxEntries = 4096
	quicHelloMaxBytes   = 4 << 20
)

func newHelloRecorder() *helloRecorder {
	return &helloRecorder{
		hellos:     make(map[string]*list.Element),
		order:      list.New(),
		ttl:        quicHelloTTL,
		maxEntries: quicHelloMaxEntries,
		maxBytes:   quicHelloMaxBytes,
		now:        time.Now,
	}
}

// sweep drops expired hellos. r.mu must be held.
func (r *helloRecorder) sweep(now time.Time) {
	for e := r.order.Front(); e != nil; e = r.order.Front() {
		rh := e.Value.(*recordedHello)
		if now.Sub(rh.at) < r.ttl {
			return
		}
		r.remove(e)
	}
}

// remove drops e. r.mu must be held.
func (r *helloRecorder) remove(e *list.Element) {
	rh := r.order.Remove(e).(*recordedHello)
	delete(r.hellos, rh.key)
	r.bytes -= rh.size
}

// put records h under key, evicting the oldest hellos held until it fits
// under the caps. A hello that wouldn't fit in an empty recorder isn't
// recorded, and put returns errQUICHelloBig.
func (r *helloRecorder) put(key []byte, h *quicHello) error {
	size := len(key) + h.size()
	r.mu.Lock()
	defer r.mu.Unlock()
	if size > r.maxBytes {
		return errQUICHelloBig
	}
	now := r.now()
	r.sweep(now)
	if e, ok := r.hellos[string(key)]; ok {
		r.remove(e)
	}
	for r.order.Len() > 0 && (r.order.Len() >= r.maxEntries || r.bytes+size > r.maxBytes) {
		r.remove(r.order.Front())
		quicHellosEvicted.Add(1)
	}
	rh := &recordedHello{key: string(key), hello: h, size: size, at: now}
	r.hellos[rh.key] = r.order.PushBack(rh)
	r.bytes += size
	return nil
}

func (r *helloRecorder) take(key []byte) (*quicHello, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweep(r.now())
	e, ok := r.hellos[string(key)]
	if !ok {
		return nil, false
	}
	h := e.Value.(*recordedHello).hello
	r.remove(e)
	return h, true
}

// len returns how many hellos are held and how many bytes they cost.
func (r *helloRecorder) len() (int, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.order.Len(), r.bytes
}

func helloKey(cs origtls.ConnectionState) ([]byte, error) {
	return cs.ExportKeyingMaterial(quicHelloLabel, nil, quicHelloKeyLen)
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
			return rec.put(key, h)
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
// the HTTP/3 server to serve handler on it. rec holds the hellos of the
// handshakes in between.
func listenQUIC(addr string, getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), handler http.Handler, rec *helloRecorder) (*h3.Server, *quic.Endpoint, error) {
	ep, err := quic.Listen("udp", addr, &quic.Config{
		TLSConfig: quicTLSConfig(getCert, rec),
		// Our pages need a handful of requests. These keep what one client
		// can make us hold small.
		MaxBidiRemoteStreams:    16,
		MaxUniRemoteStreams:     8,
		MaxStreamReadBufferSize: 64 << 10,
		MaxConnReadBufferSize:   256 << 10,
		HandshakeTimeout:        quicHandshakeTimeout,
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
	srv, ep, err := listenQUIC(addr, getCert, handler, newHelloRecorder())
	if err != nil {
		log.Fatalf("unable to listen for the HTTP/3 server on %s: %s", addr, err)
	}
	log.Printf("Booting HTTP/3 on %s", addr)
	go func() {
		err := srv.Serve(ep)
		// HTTP/3 is an extra. If its UDP socket fails, say so, and keep
		// serving the site over TCP.
		if err != nil && err != http.ErrServerClosed {
			log.Printf("http/3 server stopped, TCP serving goes on: %s", err)
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
