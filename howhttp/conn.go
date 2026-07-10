// Package howhttp provides the custom HTTP/1.x and HTTP/2 server plumbing that
// howsmyssl uses to serve requests over its forked tls1262 stack while still
// reusing net/http and golang.org/x/net/http2.
package howhttp

import (
	"errors"
	"expvar"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	origtls "crypto/tls"

	tls "github.com/jmhodges/howsmyssl/tls1262"
)

var (
	_              net.Listener = &Listener{}
	_              net.Conn     = &Conn{}
	errTLSConnConv              = errors.New("unable to convert net.Conn to *tls1262.Conn")
)

type Listener struct {
	net.Listener
	*handshakeStats
}

type handshakeStats struct {
	Successes         *expvar.Int
	Errs              *expvar.Int
	ReadTimeouts      *expvar.Int
	WriteTimeouts     *expvar.Int
	UnknownTimeouts   *expvar.Int
	EOFs              *expvar.Int
	IntentionalCloses *expvar.Int
	PeerResets        *expvar.Int
}

func newHandshakeStats(ns *expvar.Map) *handshakeStats {
	s := &handshakeStats{
		Successes:         &expvar.Int{},
		Errs:              &expvar.Int{},
		ReadTimeouts:      &expvar.Int{},
		WriteTimeouts:     &expvar.Int{},
		UnknownTimeouts:   &expvar.Int{},
		EOFs:              &expvar.Int{},
		IntentionalCloses: &expvar.Int{},
		PeerResets:        &expvar.Int{},
	}
	ns.Set("successes", s.Successes)
	ns.Set("errors", s.Errs)
	ns.Set("read_timeouts", s.ReadTimeouts)
	ns.Set("write_timeouts", s.WriteTimeouts)
	ns.Set("unknown_timeouts", s.UnknownTimeouts)
	ns.Set("eofs", s.EOFs)
	ns.Set("intentional_closes", s.IntentionalCloses)
	ns.Set("peer_resets", s.PeerResets)
	return s
}

func NewListener(nl net.Listener, ns *expvar.Map) *Listener {
	statNS := new(expvar.Map).Init()
	ns.Set("handshake", statNS)
	lis := &Listener{
		Listener:       nl,
		handshakeStats: newHandshakeStats(statNS),
	}
	return lis
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return c, err
	}
	tlsConn, ok := c.(*tls.Conn)
	if !ok {
		c.Close()
		return nil, errTLSConnConv
	}
	return &Conn{
		Conn:           tlsConn,
		handshakeStats: l.handshakeStats,
	}, nil
}

type Conn struct {
	*tls.Conn // Conn is embedded for net/http to see Conn as CloseWriter, HandshakeContext, etc.

	// handshakeOnce drives the wrapper handshake() exactly once; the
	// outcome is cached in handshakeErr so repeat callers (every Read/Write
	// after the first) observe the same result without re-counting stats
	// or short-circuiting around a failed handshake.
	handshakeOnce sync.Once
	handshakeErr  error

	// draining is set by our Close before delegating to the embedded
	// tls.Conn.Close. It tells errorToStats that any in-flight Read/Write
	// returning net.ErrClosed is the normal teardown signal — the frame
	// reader observing the close we just performed — not an anomaly worth
	// logging. See errorToStats for the consumer side.
	draining atomic.Bool

	*handshakeStats
}

func (c *Conn) Read(b []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	size, err := c.Conn.Read(b)
	c.errorToStats(err)
	return size, err
}

func (c *Conn) Write(b []byte) (int, error) {
	if err := c.handshake(); err != nil {
		return 0, err
	}
	size, err := c.Conn.Write(b)
	c.errorToStats(err)
	return size, err
}

// Close marks the conn as draining and then delegates to the embedded
// tls.Conn.Close.
//
// Setting draining before the underlying close happens-before any
// concurrent in-flight Read/Write that subsequently returns net.ErrClosed,
// so errorToStats can recognize that error as the expected teardown
// signal rather than logging it as anomalous. Every server-initiated
// close path in this package routes through here: serve()'s
// handshake-failure cleanup, serveH2's deferred close after
// h2.ServeConn returns (idle timeout, peer GOAWAY, MaxConcurrentStreams
// drain, etc.), closeAllH2Conns during force-shutdown, h1.Server's
// per-conn close, and the http2 GOAWAY hook registered on h1 by
// http2.ConfigureServer.
func (c *Conn) Close() error {
	c.draining.Store(true)
	return c.Conn.Close()
}

// ConnectionState is here for the net/http library to set the `Request.TLS`
// field correctly (its connectionStater interface check). It's not to be called
// to get the client info. Use pullClientInfo, instead (which looks at the
// forked version of the ConnectionState with more info).
//
// Also, the returned struct's unexported ekm closure is unset, so calling
// ExportKeyingMaterial on it will panic.
func (c *Conn) ConnectionState() origtls.ConnectionState {
	cs := c.Conn.ConnectionState()
	return origtls.ConnectionState{
		Version:                     cs.Version,
		HandshakeComplete:           cs.HandshakeComplete,
		DidResume:                   cs.DidResume,
		CipherSuite:                 cs.CipherSuite,
		CurveID:                     origtls.CurveID(cs.CurveID),
		NegotiatedProtocol:          cs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
		ServerName:                  cs.ServerName,
		PeerCertificates:            cs.PeerCertificates,
		VerifiedChains:              cs.VerifiedChains,
		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
		OCSPResponse:                cs.OCSPResponse,
		TLSUnique:                   cs.TLSUnique,
		ECHAccepted:                 cs.ECHAccepted,
		HelloRetryRequest:           cs.HelloRetryRequest,
	}
}

// handshake drives the underlying TLS handshake at most once and caches the
// outcome. Stats are updated exactly once: a success bumps Successes; a
// failure bumps the error counters via errorToStats. Subsequent callers see
// the same cached error (or nil) without re-counting.
func (c *Conn) handshake() error {
	c.handshakeOnce.Do(func() {
		err := c.Conn.Handshake()
		if err != nil {
			c.handshakeErr = err
			c.errorToStats(err)
			return
		}
		c.Successes.Add(1)
	})
	return c.handshakeErr
}

func (c *Conn) errorToStats(err error) {
	if err == nil {
		return
	}
	c.Errs.Add(1)
	if err == io.EOF {
		c.EOFs.Add(1)
		return
	}
	if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
		switch opErr.Op {
		case "read":
			c.ReadTimeouts.Add(1)
		case "write":
			c.WriteTimeouts.Add(1)
		default:
			log.Printf("unknown timeout type: %s", opErr.Op)
			c.UnknownTimeouts.Add(1)
		}
		return
	}
	// Our Close ran (graceful shutdown, force-close, h2 idle drain,
	// h1 per-conn teardown, ...); the in-flight Read/Write observed it
	// as net.ErrClosed. Expected lifecycle, not an anomaly. We require
	// draining to be set so that any net.ErrClosed coming from a path
	// that bypasses our wrapper Close still surfaces as unknown — those
	// are the ones worth investigating.
	if c.draining.Load() && errors.Is(err, net.ErrClosed) {
		c.IntentionalCloses.Add(1)
		return
	}
	// Peer-initiated abrupt close. TCP LBs in front of us routinely RST
	// conns during idle eviction; clients hang up mid-request. Common
	// and benign on a public TLS endpoint — watch the rate via expvar
	// rather than the log.
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		c.PeerResets.Add(1)
		return
	}
	log.Printf("unknown tls error: %s", err)
}
