package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	origtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"expvar"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/jmhodges/howsmyssl/h3"
	tls "github.com/jmhodges/howsmyssl/tls1274"
	"golang.org/x/net/quic"
)

func TestQUICOffByDefault(t *testing.T) {
	if *quicAddr != "" {
		t.Errorf("-quicAddr defaults to %q; HTTP/3 must be off unless it is set", *quicAddr)
	}
}

// quicTestServer serves the site's handlers over HTTP/3 on a local UDP port.
type quicTestServer struct {
	addr string
	pool *x509.CertPool
	rec  *helloRecorder
}

func startQUICTestServer(t *testing.T, handler http.Handler) *quicTestServer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }

	rec := newHelloRecorder()
	srv, ep, err := listenQUIC("127.0.0.1:0", getCert, handler, rec)
	if err != nil {
		t.Fatalf("listenQUIC: %s", err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ep) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		<-done
	})
	return &quicTestServer{addr: ep.LocalAddr().String(), pool: pool, rec: rec}
}

// dial makes a QUIC connection to s, trusting the certificates in roots,
// and closes it right after.
func (s *quicTestServer) dial(t *testing.T, roots *x509.CertPool) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cep, err := quic.Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		cep.Close(ctx)
	}()
	conf := &origtls.Config{ServerName: "localhost", RootCAs: roots, NextProtos: []string{"h3"}}
	conn, err := cep.Dial(ctx, "udp", s.addr, &quic.Config{TLSConfig: conf})
	if err != nil {
		return err
	}
	conn.Abort(nil)
	return nil
}

// abandon starts a handshake with s that gets as far as the server's
// Finished and goes no further: the client doesn't trust the server's
// certificate, so it never sends its own Finished.
func (s *quicTestServer) abandon(t *testing.T) {
	t.Helper()
	if err := s.dial(t, x509.NewCertPool()); err == nil {
		t.Fatalf("a client that trusts nothing finished its handshake")
	}
}

func (s *quicTestServer) client(t *testing.T, conf *origtls.Config) *h3.ClientConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cep, err := quic.Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		cep.Close(ctx)
	})
	if conf == nil {
		conf = &origtls.Config{}
	}
	conf = conf.Clone()
	conf.ServerName = "localhost"
	conf.RootCAs = s.pool
	conf.NextProtos = []string{"h3"}
	conn, err := cep.Dial(ctx, "udp", s.addr, &quic.Config{TLSConfig: conf})
	if err != nil {
		t.Fatalf("Dial: %s", err)
	}
	cc, err := h3.NewClientConn(context.Background(), conn)
	if err != nil {
		t.Fatal(err)
	}
	return cc
}

func quicGet(t *testing.T, cc *h3.ClientConn, path string, h http.Header) (*http.Response, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://www.howsmyssl.com"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range h {
		req.Header[k] = vs
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("GET %s: %s", path, err)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s body: %s", path, err)
	}
	return resp, b
}

func testMux(t *testing.T) http.Handler {
	index = loadIndex()
	stats := newStatusStats(new(expvar.Map).Init())
	am := &allowMaps{
		AllowTheseDomains: make(map[string]bool),
		AllowSubdomainsOn: make(map[string]bool),
		BlockedDomains:    map[string]bool{"blocked.com": true},
	}
	ama := &atomic.Pointer[allowMaps]{}
	ama.Store(am)
	oa := newOriginAllower(ama, "testhostname", nullLogClient{}, new(expvar.Map).Init(), newTestLogger(t))
	return tlsMux("", "www.howsmyssl.com", "www.howsmyssl.com", makeStaticHandler(stats), handleWeb, oa, newTestLogger(t), newTestLogger(t))
}

func TestQUICJSONAPI(t *testing.T) {
	ts := startQUICTestServer(t, testMux(t))

	// Go's client offers a post-quantum key agreement by default, so it is
	// rated okay at every cutover.
	cc := ts.client(t, nil)
	resp, b := quicGet(t, cc, "/a/check", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("status %d, Content-Type %q, body %s", resp.StatusCode, resp.Header.Get("Content-Type"), b)
	}
	if _, ok := resp.Header["Connection"]; ok {
		t.Errorf("Connection header sent over HTTP/3")
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("JSON: %s in %s", err, b)
	}
	want := map[string]any{
		"transport":                            "QUIC",
		"tls_version":                          "TLS 1.3",
		"rating":                               string(okay),
		"post_quantum_key_agreement":           true,
		"ephemeral_keys_supported":             true,
		"tls_compression_supported":            false,
		"unknown_cipher_suite_supported":       false,
		"beast_vuln":                           false,
		"able_to_detect_n_minus_one_splitting": false,
		"insecure_cipher_suites":               map[string]any{},
	}
	for k, v := range want {
		if diff := cmp.Diff(v, got[k]); diff != "" {
			t.Errorf("%s (-want +got):\n%s", k, diff)
		}
	}
	if groups, _ := got["given_named_groups"].([]any); len(groups) == 0 || groups[0] != "X25519MLKEM768" {
		t.Errorf("given_named_groups: %v", got["given_named_groups"])
	}
	suites, _ := got["given_cipher_suites"].([]any)
	if len(suites) != 3 {
		t.Errorf("given_cipher_suites, want Go's three TLS 1.3 suites: %v", suites)
	}
	if sigs, _ := got["given_signature_algorithms"].([]any); len(sigs) == 0 {
		t.Errorf("given_signature_algorithms is empty")
	}

	// The same connection serves more requests, each rated from its hello.
	resp, b = quicGet(t, cc, "/a/check?callback=parseTLS", nil)
	if !strings.HasPrefix(string(b), "parseTLS({") || resp.Header.Get("Content-Type") != "application/javascript" {
		t.Errorf("JSONP: %q, %q", resp.Header.Get("Content-Type"), b)
	}

	// The origin checks apply over HTTP/3 too.
	resp, b = quicGet(t, cc, "/a/check", http.Header{"Origin": {"https://blocked.com"}})
	if resp.StatusCode != http.StatusBadRequest || string(b) != string(disallowedOriginBody) {
		t.Errorf("blocked origin: %d %s", resp.StatusCode, b)
	}
}

func TestQUICClassicGroupsOnly(t *testing.T) {
	ts := startQUICTestServer(t, testMux(t))
	cc := ts.client(t, &origtls.Config{CurvePreferences: []origtls.CurveID{origtls.X25519, origtls.CurveP256}})
	_, b := quicGet(t, cc, "/a/check", nil)
	var got clientInfo
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.PostQuantumKeyAgreement {
		t.Errorf("post_quantum_key_agreement: want false for a client offering only X25519 and P-256")
	}
	if diff := cmp.Diff([]string{"x25519", "secp256r1"}, got.GivenNamedGroups); diff != "" {
		t.Errorf("given_named_groups (-want +got):\n%s", diff)
	}
	// The rating depends on today's date, and is checked with fixed dates in
	// TestPullQUICClientInfo. Here we check that it was rated at all.
	if got.Rating != okay && got.Rating != improvable && got.Rating != bad {
		t.Errorf("rating: %q", got.Rating)
	}
}

func TestQUICIndex(t *testing.T) {
	ts := startQUICTestServer(t, testMux(t))
	cc := ts.client(t, nil)
	resp, b := quicGet(t, cc, "/", nil)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("status %d, Content-Type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if !strings.Contains(string(b), "over QUIC") {
		t.Errorf("index page over HTTP/3 doesn't say it came over QUIC")
	}
	_, b = quicGet(t, cc, "/healthcheck", nil)
	if !strings.Contains(string(b), "ok") {
		t.Errorf("healthcheck: %s", b)
	}
}

func TestPullQUICClientInfo(t *testing.T) {
	beforeImprovable := time.Date(2026, 6, 13, 23, 59, 0, 0, time.UTC)
	atImprovable := time.Date(2026, 6, 14, 17, 0, 0, 0, time.UTC)
	atBad := time.Date(2026, 12, 14, 18, 0, 0, 0, time.UTC)

	// A hello that also lists, for its TCP connections, cipher suites that
	// are insecure, unknown, or only work before TLS 1.3. None of them can be
	// used over QUIC, so none of them count.
	classic := &quicHello{
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_RC4_128_SHA,
			tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			0x0a0a, // GREASE
			0xfeed, // unknown
		},
		SupportedCurves:   []origtls.CurveID{origtls.X25519, origtls.CurveP256},
		SignatureSchemes:  []origtls.SignatureScheme{origtls.ECDSAWithP256AndSHA256, origtls.PSSWithSHA256},
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		Extensions:        []uint16{0, 10, 13, 43, 51, 57, extensionSessionTicket},
		Version:           tls.VersionTLS13,
	}
	pq := *classic
	pq.SupportedCurves = []origtls.CurveID{origtls.X25519MLKEM768, origtls.X25519}

	for _, tc := range []struct {
		name  string
		hello *quicHello
		now   time.Time
		want  rating
	}{
		{"ClassicBeforeImprovable", classic, beforeImprovable, okay},
		{"ClassicAtImprovable", classic, atImprovable, improvable},
		{"ClassicAtBad", classic, atBad, bad},
		{"PQBeforeImprovable", &pq, beforeImprovable, okay},
		{"PQAtBad", &pq, atBad, okay},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := pullQUICClientInfo(tc.hello, tc.now)
			if d.Rating != tc.want {
				t.Errorf("Rating: want %s, got %s", tc.want, d.Rating)
			}
			if d.Transport != "QUIC" || d.TLSVersion != "TLS 1.3" {
				t.Errorf("Transport %q, TLSVersion %q", d.Transport, d.TLSVersion)
			}
			if len(d.InsecureCipherSuites) != 0 || d.UnknownCipherSuiteSupported || d.BEASTVuln || d.TLSCompressionSupported {
				t.Errorf("older-TLS checks set over QUIC: %+v", d)
			}
			if !d.EphemeralKeysSupported || !d.SessionTicketsSupported {
				t.Errorf("EphemeralKeysSupported %v, SessionTicketsSupported %v", d.EphemeralKeysSupported, d.SessionTicketsSupported)
			}
		})
	}

	d := pullQUICClientInfo(classic, beforeImprovable)
	wantSuites := []string{
		"TLS_AES_128_GCM_SHA256",
		"TLS_RSA_WITH_RC4_128_SHA",
		"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		"TLS_GREASE_IS_THE_WORD_0A",
		"Some unknown cipher suite: 0xfeed",
	}
	if diff := cmp.Diff(wantSuites, d.GivenCipherSuites); diff != "" {
		t.Errorf("GivenCipherSuites (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"}, d.GivenSignatureAlgorithms); diff != "" {
		t.Errorf("GivenSignatureAlgorithms (-want +got):\n%s", diff)
	}

	noTicket := *classic
	noTicket.Extensions = []uint16{0, 10, 13}
	if pullQUICClientInfo(&noTicket, beforeImprovable).SessionTicketsSupported {
		t.Errorf("SessionTicketsSupported without the session_ticket extension")
	}

	// TCP answers have no transport key, so they are unchanged.
	b, err := json.Marshal(&clientInfo{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "transport") {
		t.Errorf("transport key in a TCP answer: %s", b)
	}
}

func TestHelloRecorder(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := newHelloRecorder()
	r.now = func() time.Time { return now }
	h1, h2 := &quicHello{Version: 1}, &quicHello{Version: 2}

	if err := r.put([]byte("one"), h1); err != nil {
		t.Fatal(err)
	}
	if got, ok := r.take([]byte("one")); !ok || got != h1 {
		t.Errorf("take one: %v %v", got, ok)
	}
	if _, ok := r.take([]byte("one")); ok {
		t.Errorf("a hello was taken twice")
	}
	if n, b := r.len(); n != 0 || b != 0 {
		t.Errorf("after take: %d hellos, %d bytes held; want none", n, b)
	}

	r.put([]byte("old"), h1)
	now = now.Add(quicHelloTTL)
	r.put([]byte("new"), h2)
	if _, ok := r.take([]byte("old")); ok {
		t.Errorf("a hello older than quicHelloTTL was kept")
	}
	if got, ok := r.take([]byte("new")); !ok || got != h2 {
		t.Errorf("take new: %v %v", got, ok)
	}
}

func TestHelloRecorderTTL(t *testing.T) {
	// The time to live must outlast a handshake, and not by much: a hello
	// whose connection can no longer be accepted is only a cost.
	if quicHelloTTL <= quicHandshakeTimeout || quicHelloTTL > 2*quicHandshakeTimeout {
		t.Errorf("quicHelloTTL is %s; want just over the handshake timeout, %s", quicHelloTTL, quicHandshakeTimeout)
	}
}

func TestHelloRecorderCaps(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := newHelloRecorder()
	r.now = func() time.Time { return now }
	r.maxEntries = 3

	for i := range 3 {
		if err := r.put([]byte{byte(i)}, &quicHello{}); err != nil {
			t.Fatalf("put %d: %s", i, err)
		}
	}
	if !r.full() {
		t.Errorf("full() is false with maxEntries hellos held")
	}
	if err := r.put([]byte{9}, &quicHello{}); err != errQUICHellosFull {
		t.Errorf("put into a full recorder: %v, want errQUICHellosFull", err)
	}
	if n, _ := r.len(); n != 3 {
		t.Errorf("a full recorder grew to %d hellos", n)
	}

	// Taking one makes room for one.
	r.take([]byte{0})
	if r.full() {
		t.Errorf("full() after a take")
	}
	if err := r.put([]byte{9}, &quicHello{}); err != nil {
		t.Errorf("put after a take: %s", err)
	}

	// Expiry makes room with no new hello coming in.
	now = now.Add(quicHelloTTL)
	if r.full() {
		t.Errorf("full() once every hello is past quicHelloTTL")
	}
	if n, b := r.len(); n != 0 || b != 0 {
		t.Errorf("past quicHelloTTL: %d hellos, %d bytes held; want none", n, b)
	}

	// The bytes cap binds on its own, and a huge hello is cut down to size
	// first.
	r = newHelloRecorder()
	r.now = func() time.Time { return now }
	huge := make([]uint16, 30000)
	h := newQUICHello(&origtls.ClientHelloInfo{CipherSuites: huge, SupportedVersions: huge, Extensions: huge})
	if len(h.CipherSuites) != quicHelloListMax || len(h.Extensions) != quicHelloListMax {
		t.Errorf("kept %d cipher suites and %d extensions; want %d", len(h.CipherSuites), len(h.Extensions), quicHelloListMax)
	}
	key := make([]byte, quicHelloKeyLen)
	if got := len(key) + h.size(); got > quicHelloMaxSize {
		t.Errorf("a hello costs %d bytes, over quicHelloMaxSize %d", got, quicHelloMaxSize)
	}
	r.maxBytes = 3 * quicHelloMaxSize
	for i := 0; ; i++ {
		key[0] = byte(i)
		if err := r.put(key, h); err != nil {
			if err != errQUICHellosFull {
				t.Fatal(err)
			}
			break
		}
		if i > 10 {
			t.Fatalf("the bytes cap didn't bind")
		}
	}
	if _, b := r.len(); b > r.maxBytes {
		t.Errorf("holding %d bytes, over maxBytes %d", b, r.maxBytes)
	}
	if !r.full() {
		t.Errorf("full() is false at the bytes cap")
	}
}

func TestQUICAbandonedHandshakes(t *testing.T) {
	// A client that sends its ClientHello and never its Finished leaves a
	// hello recorded. Many of them must not pile up past the cap, must
	// expire, and a full recorder must refuse new handshakes, not grow.
	ts := startQUICTestServer(t, testMux(t))
	var mu sync.Mutex
	now := time.Now()
	ts.rec.mu.Lock()
	ts.rec.maxEntries = 5
	ts.rec.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	ts.rec.mu.Unlock()

	refusedBefore := quicHellosRefused.Value()
	for range 20 {
		// No RootCAs, so the client rejects our certificate and walks away
		// without its Finished.
		ts.abandon(t)
	}
	n, _ := ts.rec.len()
	if n != 5 {
		t.Errorf("after 20 abandoned handshakes, %d hellos held; want the cap, 5", n)
	}
	if quicHellosRefused.Value()-refusedBefore < 15 {
		t.Errorf("only %d handshakes refused while full; want at least 15", quicHellosRefused.Value()-refusedBefore)
	}

	// While full, a good client is refused too.
	if err := ts.dial(t, ts.pool); err == nil {
		t.Errorf("a handshake succeeded while the recorder was full")
	}

	// Once the abandoned hellos expire, they are gone and good clients get
	// in again.
	mu.Lock()
	now = now.Add(quicHelloTTL)
	mu.Unlock()
	if ts.rec.full() {
		t.Errorf("still full after quicHelloTTL")
	}
	if n, b := ts.rec.len(); n != 0 || b != 0 {
		t.Errorf("after quicHelloTTL, %d hellos and %d bytes held; want none", n, b)
	}
	cc := ts.client(t, nil)
	if resp, _ := quicGet(t, cc, "/a/check", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("after expiry, /a/check gave %d", resp.StatusCode)
	}
}

func TestQUICHelloPerConnection(t *testing.T) {
	// Each connection's answer must come from its own hello, however the
	// handshakes and requests interleave.
	ts := startQUICTestServer(t, testMux(t))
	classic := ts.client(t, &origtls.Config{CurvePreferences: []origtls.CurveID{origtls.CurveP384}})
	pq := ts.client(t, &origtls.Config{CurvePreferences: []origtls.CurveID{origtls.X25519MLKEM768}})
	for i := 0; i < 2; i++ {
		for _, c := range []struct {
			cc   *h3.ClientConn
			want []string
		}{
			{classic, []string{"secp384r1"}},
			{pq, []string{"X25519MLKEM768"}},
		} {
			_, b := quicGet(t, c.cc, "/a/check", nil)
			var got clientInfo
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(c.want, got.GivenNamedGroups); diff != "" {
				t.Errorf("given_named_groups (-want +got):\n%s", diff)
			}
		}
	}
}

func TestQUICRatingMatchesTCP(t *testing.T) {
	// pullQUICClientInfo carries pullClientInfo's rating rules for TLS 1.3
	// clients. Rate the same TLS 1.3 hellos both ways, at every cutover.
	dates := []time.Time{
		time.Date(2026, 6, 13, 23, 59, 0, 0, time.UTC),
		time.Date(2026, 6, 14, 17, 0, 0, 0, time.UTC),
		time.Date(2026, 12, 14, 18, 0, 0, 0, time.UTC),
	}
	for _, tc := range []struct {
		name   string
		curves []tls.CurveID
	}{
		{"Classic", []tls.CurveID{tls.X25519, tls.CurveP256}},
		{"PQ", []tls.CurveID{tls.X25519MLKEM768, tls.X25519}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := connect(t, &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: tc.curves})
			st := c.ConnectionState()
			h := &quicHello{
				CipherSuites:      st.ClientCipherSuites,
				SupportedVersions: st.SupportedVersions,
				Version:           st.Version,
			}
			for _, id := range st.SupportedCurves {
				h.SupportedCurves = append(h.SupportedCurves, origtls.CurveID(id))
			}
			for _, s := range st.SupportedSignatureAlgorithms {
				h.SignatureSchemes = append(h.SignatureSchemes, origtls.SignatureScheme(s))
			}
			for _, now := range dates {
				tcp, q := pullClientInfo(c, now), pullQUICClientInfo(h, now)
				if tcp.Rating != q.Rating {
					t.Errorf("at %s: TCP rating %s, QUIC rating %s", now, tcp.Rating, q.Rating)
				}
				if diff := cmp.Diff(tcp.GivenNamedGroups, q.GivenNamedGroups); diff != "" {
					t.Errorf("given_named_groups (-tcp +quic):\n%s", diff)
				}
				if diff := cmp.Diff(tcp.GivenSignatureAlgorithms, q.GivenSignatureAlgorithms); diff != "" {
					t.Errorf("given_signature_algorithms (-tcp +quic):\n%s", diff)
				}
				if tcp.TLSVersion != q.TLSVersion || tcp.PostQuantumKeyAgreement != q.PostQuantumKeyAgreement {
					t.Errorf("TCP %s %v, QUIC %s %v", tcp.TLSVersion, tcp.PostQuantumKeyAgreement, q.TLSVersion, q.PostQuantumKeyAgreement)
				}
			}
		})
	}
}
