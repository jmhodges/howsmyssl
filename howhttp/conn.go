// Package howhttp provides the custom HTTP/1.x and HTTP/2 server plumbing that
// howsmyssl uses to serve requests over its forked tls1274 stack while still
// reusing net/http and golang.org/x/net/http2.
package howhttp

import (
	"context"
	"errors"
	"expvar"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	origtls "crypto/tls"

	tls "github.com/jmhodges/howsmyssl/tls1274"
)

var (
	_              net.Listener = &Listener{}
	_              net.Conn     = &Conn{}
	errTLSConnConv              = errors.New("unable to convert net.Conn to *tls1274.Conn")
)

type Listener struct {
	net.Listener
	*connStats
}

// connStats holds the expvar counters for a Listener's connections, in two
// groups that are kept apart so neither can be mistaken for the other.
//
// The "handshake" group counts TLS handshakes only: its successes, and its
// errors split by kind. An EOF there is a client that hung up mid-handshake,
// a failed handshake like any other.
//
// The "post_handshake" group counts what Read and Write return after a
// handshake that succeeded. Its EOFs and intentional closes are how a
// connection normally ends (the client hanging up after its last request, or
// our own Close), so they are counted under their own names but not in its
// "errors" total.
type connStats struct {
	HandshakeSuccesses *expvar.Int
	HandshakeErrs      *errStats
	PostHandshakeErrs  *errStats
}

// errStats counts errors by kind. Errs is the total of the errors, and the
// rest split them by kind. EOFs, IntentionalCloses and ReadAborts are left
// out of Errs where they are a connection's normal end (see
// cleanEndsAreErrs).
type errStats struct {
	Errs              *expvar.Int
	ReadTimeouts      *expvar.Int
	WriteTimeouts     *expvar.Int
	UnknownTimeouts   *expvar.Int
	EOFs              *expvar.Int
	IntentionalCloses *expvar.Int
	PeerResets        *expvar.Int
	// UnknownErrs counts the errors of no kind above. They are in Errs,
	// and each is also logged as "unknown tls error", but only as many as
	// unknownLog lets through, so this is the exact count.
	UnknownErrs *expvar.Int
	// ReadAborts counts reads that stopped because the read deadline was
	// set in the past on purpose, which is how net/http's HTTP/1.x server
	// ends its background read after every request. Not an error, and not
	// in Errs. Only exported in the "post_handshake" group.
	ReadAborts *expvar.Int

	// cleanEndsAreErrs says whether EOFs and IntentionalCloses also count
	// in Errs. True for handshakes, where either means the handshake
	// failed; false after a handshake, where both are the normal end of a
	// connection.
	cleanEndsAreErrs bool

	// unknownLog caps the "unknown tls error" log lines. A public TLS port
	// sees scanners and broken clients fail handshakes all day, and each
	// of those is an unknown error.
	unknownLog *logLimiter
}

func newConnStats(ns *expvar.Map) *connStats {
	hsNS := new(expvar.Map).Init()
	ns.Set("handshake", hsNS)
	postNS := new(expvar.Map).Init()
	ns.Set("post_handshake", postNS)

	s := &connStats{
		HandshakeSuccesses: &expvar.Int{},
		HandshakeErrs:      newErrStats(hsNS, true),
		PostHandshakeErrs:  newErrStats(postNS, false),
	}
	hsNS.Set("successes", s.HandshakeSuccesses)
	return s
}

func newErrStats(ns *expvar.Map, cleanEndsAreErrs bool) *errStats {
	s := &errStats{
		Errs:              &expvar.Int{},
		ReadTimeouts:      &expvar.Int{},
		WriteTimeouts:     &expvar.Int{},
		UnknownTimeouts:   &expvar.Int{},
		EOFs:              &expvar.Int{},
		IntentionalCloses: &expvar.Int{},
		PeerResets:        &expvar.Int{},
		UnknownErrs:       &expvar.Int{},
		ReadAborts:        &expvar.Int{},
		cleanEndsAreErrs:  cleanEndsAreErrs,
		unknownLog:        newLogLimiter("unknown tls error", unknownErrLogsPerWindow, unknownErrLogWindow),
	}
	ns.Set("errors", s.Errs)
	ns.Set("read_timeouts", s.ReadTimeouts)
	ns.Set("write_timeouts", s.WriteTimeouts)
	ns.Set("unknown_timeouts", s.UnknownTimeouts)
	ns.Set("eofs", s.EOFs)
	ns.Set("intentional_closes", s.IntentionalCloses)
	ns.Set("peer_resets", s.PeerResets)
	ns.Set("unknown_errors", s.UnknownErrs)
	if !cleanEndsAreErrs {
		ns.Set("read_aborts", s.ReadAborts)
	}
	return s
}

func NewListener(nl net.Listener, ns *expvar.Map) *Listener {
	return &Listener{
		Listener:  nl,
		connStats: newConnStats(ns),
	}
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
		Conn:      tlsConn,
		connStats: l.connStats,
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
	// tls.Conn.Close. It tells errStats.count that any in-flight Read/Write
	// returning net.ErrClosed is the normal teardown signal — the frame
	// reader observing the close we just performed — not an anomaly worth
	// logging. See errStats.count for the consumer side.
	draining atomic.Bool

	// readDeadlinePassed is set while the read deadline is one that was
	// already in the past when it was set. net/http's HTTP/1.x server does
	// that (with time.Unix(1, 0)) to stop its background read at the end
	// of every request, and errStats.count uses it to tell that from a
	// real read timeout.
	readDeadlinePassed atomic.Bool

	// readErrCounted is set by the first Read that returns an error other
	// than a timeout. tls1274 keeps such an error and returns it from every
	// Read after it, and net/http's HTTP/1.x server can read again after
	// one: when its background read sees the client hang up, the read for
	// the next request sees the same EOF. Only the first is counted, so one
	// hang-up (or reset, or close) counts once.
	readErrCounted atomic.Bool

	*connStats
}

func (c *Conn) Read(b []byte) (int, error) {
	if err := c.handshake(context.Background()); err != nil {
		return 0, err
	}
	size, err := c.Conn.Read(b)
	if err != nil && !isTimeout(err) && c.readErrCounted.Swap(true) {
		return size, err
	}
	c.PostHandshakeErrs.count(err, c.draining.Load(), c.readDeadlinePassed.Load())
	return size, err
}

// isTimeout says whether err is a timeout. tls1274 doesn't keep those: the
// next Read after one reads again, so each is its own event and counted.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (c *Conn) Write(b []byte) (int, error) {
	if err := c.handshake(context.Background()); err != nil {
		return 0, err
	}
	size, err := c.Conn.Write(b)
	c.PostHandshakeErrs.count(err, c.draining.Load(), false)
	return size, err
}

// Close marks the conn as draining and then delegates to the embedded
// tls.Conn.Close.
//
// Setting draining before the underlying close happens-before any
// concurrent in-flight Read/Write that subsequently returns net.ErrClosed,
// so errStats.count can recognize that error as the expected teardown
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

// SetReadDeadline notes whether t is already past (see readDeadlinePassed)
// and then sets it on the embedded tls.Conn.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadlinePassed.Store(deadlinePassed(t))
	return c.Conn.SetReadDeadline(t)
}

// SetDeadline is SetReadDeadline and SetWriteDeadline in one, so it notes
// the read deadline the same way.
func (c *Conn) SetDeadline(t time.Time) error {
	c.readDeadlinePassed.Store(deadlinePassed(t))
	return c.Conn.SetDeadline(t)
}

func deadlinePassed(t time.Time) bool {
	return !t.IsZero() && !t.After(time.Now())
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

// HandshakeContext runs the TLS handshake through the wrapper, so it is
// counted. Server.serve calls this; without the override it would reach the
// embedded tls.Conn's method and a failed handshake would never be counted.
func (c *Conn) HandshakeContext(ctx context.Context) error {
	return c.handshake(ctx)
}

// Handshake is HandshakeContext with context.Background.
func (c *Conn) Handshake() error {
	return c.handshake(context.Background())
}

// handshake drives the underlying TLS handshake at most once and caches the
// outcome. Stats are updated exactly once: a success bumps
// HandshakeSuccesses; a failure bumps HandshakeErrs. Subsequent callers see
// the same cached error (or nil) without re-counting.
func (c *Conn) handshake(ctx context.Context) error {
	c.handshakeOnce.Do(func() {
		err := c.Conn.HandshakeContext(ctx)
		if err != nil {
			c.handshakeErr = err
			c.HandshakeErrs.count(err, c.draining.Load(), c.readDeadlinePassed.Load())
			return
		}
		c.HandshakeSuccesses.Add(1)
	})
	return c.handshakeErr
}

// count classifies err into s's counters. draining is whether our Close has
// run on the conn that returned err, and readDeadlinePassed whether its read
// deadline was set in the past on purpose.
func (s *errStats) count(err error, draining, readDeadlinePassed bool) {
	if err == nil {
		return
	}
	if err == io.EOF {
		s.EOFs.Add(1)
		if s.cleanEndsAreErrs {
			s.Errs.Add(1)
		}
		return
	}
	if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
		if opErr.Op == "read" && readDeadlinePassed && !s.cleanEndsAreErrs {
			s.ReadAborts.Add(1)
			return
		}
		s.Errs.Add(1)
		switch opErr.Op {
		case "read":
			s.ReadTimeouts.Add(1)
		case "write":
			s.WriteTimeouts.Add(1)
		default:
			log.Printf("unknown timeout type: %s", opErr.Op)
			s.UnknownTimeouts.Add(1)
		}
		return
	}
	// Our Close ran (graceful shutdown, force-close, h2 idle drain,
	// h1 per-conn teardown, ...); the in-flight Read/Write observed it
	// as net.ErrClosed. Expected lifecycle, not an anomaly. We require
	// draining to be set so that any net.ErrClosed coming from a path
	// that bypasses our wrapper Close still surfaces as unknown — those
	// are the ones worth investigating.
	if draining && errors.Is(err, net.ErrClosed) {
		s.IntentionalCloses.Add(1)
		if s.cleanEndsAreErrs {
			s.Errs.Add(1)
		}
		return
	}
	// Peer-initiated abrupt close. TCP LBs in front of us routinely RST
	// conns during idle eviction; clients hang up mid-request. Common
	// and benign on a public TLS endpoint — watch the rate via expvar
	// rather than the log.
	s.Errs.Add(1)
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		s.PeerResets.Add(1)
		return
	}
	s.UnknownErrs.Add(1)
	s.unknownLog.printf("%s", err)
}

// At most unknownErrLogsPerWindow "unknown tls error" lines are logged per
// unknownErrLogWindow, for each of the "handshake" and "post_handshake"
// groups. The unknown_errors counter has the exact number.
const (
	unknownErrLogsPerWindow = 10
	unknownErrLogWindow     = time.Minute
)

// logLimiter logs at most max lines per window, each starting with
// prefix. The first line of a new window after one that dropped lines
// says how many it dropped. A window starts with the first line after the
// last window ended, so a quiet spell costs nothing.
type logLimiter struct {
	prefix string
	max    int
	window time.Duration
	now    func() time.Time
	logf   func(format string, args ...any)

	mu         sync.Mutex
	start      time.Time
	logged     int
	suppressed int
}

func newLogLimiter(prefix string, max int, window time.Duration) *logLimiter {
	return &logLimiter{
		prefix: prefix,
		max:    max,
		window: window,
		now:    time.Now,
		logf:   log.Printf,
	}
}

func (l *logLimiter) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if l.start.IsZero() || now.Sub(l.start) >= l.window {
		if l.suppressed > 0 {
			l.logf("%s: %d more not logged since %s", l.prefix, l.suppressed, l.start.UTC().Format(time.RFC3339))
		}
		l.start = now
		l.logged = 0
		l.suppressed = 0
	}
	if l.logged >= l.max {
		l.suppressed++
		return
	}
	l.logged++
	l.logf(l.prefix+": "+format, args...)
}
