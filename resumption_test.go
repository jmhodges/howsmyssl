package main

import (
	"bufio"
	"crypto/x509"
	"encoding/json"
	"expvar"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmhodges/howsmyssl/howhttp"
	tls "github.com/jmhodges/howsmyssl/tls1274"
	ztls "github.com/zmap/zcrypto/tls"
	zx509 "github.com/zmap/zcrypto/x509"
)

// TestSessionTicketResumptionByVersion pins down, per TLS version, whether
// the server resumes a session from the ticket it handed out on a client's
// previous connection. It runs the production TLS config (makeTLSConfig) and
// the production mux over the howhttp listener, and asks for /a/check over
// HTTP/1.1 on each connection, as an API client would.
//
// The server hands out tickets at every version. At TLS 1.1 and up it
// resumes from them. At TLS 1.0 it never does: tls1274's serverHandshake
// throws the session away so that the BEAST check always has a full
// handshake to look at. The client still gets a working connection, by a
// full handshake.
//
// The "Connection: close" that tlsMux puts on every response doesn't stop
// any of this. It ends the connection, and resumption is what happens on
// the next one.
//
// Two client libraries are used so that the result doesn't rest on one
// implementation's idea of resumption: zcrypto's, and tls1274 itself.
//
// This is the regression test for
// https://github.com/jmhodges/howsmyssl/issues/355.
func TestSessionTicketResumptionByVersion(t *testing.T) {
	versions := []struct {
		name       string
		version    uint16
		wantTLS    string
		wantResume bool
	}{
		{"TLS10", tls.VersionTLS10, "TLS 1.0", false},
		{"TLS11", tls.VersionTLS11, "TLS 1.1", true},
		{"TLS12", tls.VersionTLS12, "TLS 1.2", true},
		{"TLS13", tls.VersionTLS13, "TLS 1.3", true},
	}
	clients := []struct {
		name string
		new  func(addr string, version uint16) resumptionClient
		// logsTicket is whether the library records the session ticket
		// it put in its ClientHello.
		logsTicket bool
	}{
		{"zcrypto", newZtlsResumptionClient, true},
		{"tls1274", newForkResumptionClient, false},
	}

	addr := startTLSMuxServer(t)

	for _, cl := range clients {
		for _, v := range versions {
			t.Run(cl.name+"/"+v.name, func(t *testing.T) {
				client := cl.new(addr, v.version)

				first := client.check(t)
				if first.version != v.version {
					t.Fatalf("first connection, negotiated version: want %#04x, got %#04x", v.version, first.version)
				}
				if first.hadSession {
					t.Errorf("first connection: the client already had a session to offer")
				}
				if first.didResume {
					t.Errorf("first connection: resumed, with no earlier session to resume")
				}
				checkResumptionReport(t, "first connection", first, v.wantTLS)

				second := client.check(t)
				if second.version != v.version {
					t.Fatalf("second connection, negotiated version: want %#04x, got %#04x", v.version, second.version)
				}
				// Without this, "didn't resume" could just mean the
				// server never sent a ticket, or the client lost it.
				if !second.hadSession {
					t.Fatalf("second connection: the client had no session from the first connection to offer")
				}
				// Stronger, where the library lets us look: the ticket
				// was on the wire. This is what shows that at TLS 1.0
				// the server was offered a ticket and turned it down.
				if cl.logsTicket && v.version < tls.VersionTLS13 && second.offeredTicketLen == 0 {
					t.Errorf("second connection: the ClientHello carried no session ticket")
				}
				if second.didResume != v.wantResume {
					t.Errorf("second connection, resumed: want %t, got %t", v.wantResume, second.didResume)
				}
				// Resumed or not, the client gets its whole report:
				// the ClientHello it is built from is sent either way.
				checkResumptionReport(t, "second connection", second, v.wantTLS)
			})
		}
	}
}

// resumptionResult is what one connection of a resumptionClient saw.
type resumptionResult struct {
	version uint16
	// hadSession is whether the client's session cache gave it a session
	// from an earlier connection to offer in this one's ClientHello.
	hadSession bool
	// offeredTicketLen is the length of the session ticket in the
	// ClientHello's session_ticket extension, for a client library that
	// can say what it sent. It is 0 otherwise, and at TLS 1.3, where the
	// ticket goes in the pre_shared_key extension instead.
	offeredTicketLen int
	didResume        bool
	header           http.Header
	closed           bool
	report           *clientInfo
}

// resumptionClient makes connections that all share one session cache.
type resumptionClient interface {
	check(t *testing.T) resumptionResult
}

func checkResumptionReport(t *testing.T, which string, res resumptionResult, wantTLS string) {
	t.Helper()
	if !res.closed {
		t.Errorf("%s: the response should tell the client to close the connection, headers: %v", which, res.header)
	}
	if res.report.TLSVersion != wantTLS {
		t.Errorf("%s, tls_version: want %#v, got %#v", which, wantTLS, res.report.TLSVersion)
	}
	if !res.report.SessionTicketsSupported {
		t.Errorf("%s, session_ticket_supported: want true, got false", which)
	}
	if len(res.report.GivenCipherSuites) == 0 {
		t.Errorf("%s, given_cipher_suites: want the client's suites, got none", which)
	}
}

// getCheck asks for /a/check over c and reads the whole response. Reading it
// all matters for TLS 1.3, where the session tickets arrive after the
// handshake, in among the application data.
func getCheck(t *testing.T, c net.Conn, res *resumptionResult) {
	t.Helper()
	req, err := http.NewRequest("GET", "https://localhost/a/check", nil)
	if err != nil {
		t.Fatalf("NewRequest: %s", err)
	}
	if err := req.Write(c); err != nil {
		t.Fatalf("writing the request: %s", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		t.Fatalf("reading the response: %s", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the response body: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status code: want %d, got %d, body: %s", http.StatusOK, resp.StatusCode, body)
	}
	res.header = resp.Header
	res.closed = resp.Close
	res.report = &clientInfo{}
	if err := json.Unmarshal(body, res.report); err != nil {
		t.Fatalf("unmarshaling the report: %s, body: %s", err, body)
	}
}

// ztlsSessionCache counts the sessions it hands back to the client.
type ztlsSessionCache struct {
	ztls.ClientSessionCache
	hits atomic.Int64
}

func (sc *ztlsSessionCache) Get(key string) (*ztls.ClientSessionState, bool) {
	s, ok := sc.ClientSessionCache.Get(key)
	if ok && s != nil {
		sc.hits.Add(1)
	}
	return s, ok
}

type ztlsResumptionClient struct {
	addr  string
	conf  *ztls.Config
	cache *ztlsSessionCache
}

func newZtlsResumptionClient(addr string, version uint16) resumptionClient {
	cache := &ztlsSessionCache{ClientSessionCache: ztls.NewLRUClientSessionCache(-1)}
	pool := zx509.NewCertPool()
	pool.AddCert(rootCAZtls)
	return &ztlsResumptionClient{
		addr:  addr,
		cache: cache,
		conf: &ztls.Config{
			ServerName:         "localhost",
			RootCAs:            pool,
			MinVersion:         version,
			MaxVersion:         version,
			ClientSessionCache: cache,
		},
	}
}

func (zc *ztlsResumptionClient) check(t *testing.T) resumptionResult {
	t.Helper()
	before := zc.cache.hits.Load()
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := ztls.DialWithDialer(d, "tcp", zc.addr, zc.conf)
	if err != nil {
		t.Fatalf("zcrypto handshake failed: %s", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	st := c.ConnectionState()
	res := resumptionResult{
		version:    st.Version,
		hadSession: zc.cache.hits.Load() > before,
		didResume:  st.DidResume,
	}
	if hl := c.GetHandshakeLog(); hl != nil && hl.ClientHello != nil && hl.ClientHello.SessionTicket != nil {
		res.offeredTicketLen = hl.ClientHello.SessionTicket.Length
	}
	getCheck(t, c, &res)
	return res
}

// forkSessionCache counts the sessions it hands back to the client.
type forkSessionCache struct {
	tls.ClientSessionCache
	hits atomic.Int64
}

func (sc *forkSessionCache) Get(key string) (*tls.ClientSessionState, bool) {
	s, ok := sc.ClientSessionCache.Get(key)
	if ok && s != nil {
		sc.hits.Add(1)
	}
	return s, ok
}

type forkResumptionClient struct {
	addr  string
	conf  *tls.Config
	cache *forkSessionCache
}

func newForkResumptionClient(addr string, version uint16) resumptionClient {
	cache := &forkSessionCache{ClientSessionCache: tls.NewLRUClientSessionCache(-1)}
	pool := x509.NewCertPool()
	pool.AddCert(rootCA)
	return &forkResumptionClient{
		addr:  addr,
		cache: cache,
		conf: &tls.Config{
			ServerName:         "localhost",
			RootCAs:            pool,
			MinVersion:         version,
			MaxVersion:         version,
			ClientSessionCache: cache,
		},
	}
}

func (fc *forkResumptionClient) check(t *testing.T) resumptionResult {
	t.Helper()
	before := fc.cache.hits.Load()
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", fc.addr, fc.conf)
	if err != nil {
		t.Fatalf("tls1274 handshake failed: %s", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	st := c.ConnectionState()
	res := resumptionResult{
		version:    st.Version,
		hadSession: fc.cache.hits.Load() > before,
		didResume:  st.DidResume,
	}
	getCheck(t, c, &res)
	return res
}

// startTLSMuxServer serves the production mux over the production TLS config,
// wired the way main does it, and returns the address it listens on.
func startTLSMuxServer(t *testing.T) string {
	t.Helper()
	tl, err := tls.Listen("tcp", "localhost:0", serverConf)
	if err != nil {
		t.Fatalf("tls.Listen: %s", err)
	}
	li := howhttp.NewListener(tl, new(expvar.Map).Init())

	ama := &atomic.Pointer[allowMaps]{}
	ama.Store(&allowMaps{
		AllowTheseDomains: make(map[string]bool),
		AllowSubdomainsOn: make(map[string]bool),
		BlockedDomains:    make(map[string]bool),
	})
	oa := newOriginAllower(ama, "testhostname", nullLogClient{}, new(expvar.Map).Init(), newTestLogger(t))
	stats := newStatusStats(new(expvar.Map).Init())
	m := tlsMux("", "localhost", "", makeStaticHandler(stats), http.NotFound, oa, newTestLogger(t), newTestLogger(t))

	srv, err := howhttp.NewServer(li, m)
	if err != nil {
		li.Close()
		t.Fatalf("howhttp.NewServer: %s", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve() }()
	t.Cleanup(func() {
		if err := srv.Close(); err != nil {
			t.Errorf("closing the server: %s", err)
		}
		if err := <-serveErr; err != nil && err != http.ErrServerClosed {
			t.Errorf("Serve: %s", err)
		}
	})
	return li.Addr().String()
}
