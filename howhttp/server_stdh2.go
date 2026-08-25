//go:build go1.27

package howhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// Server serves HTTP/1.x and HTTP/2 over our forked tls1266 stack using
// net/http alone.
//
// Go 1.27 made that possible. Before it, net/http could only dispatch ALPN
// through TLSNextProto, whose func signature names the concrete
// *crypto/tls.Conn type, so a server on a non-crypto/tls connection had to
// route ALPN itself and hand "h2" conns to golang.org/x/net/http2 (see
// server_xnet.go, still built on older toolchains). As of 1.27, net/http's
// conn.serve does the handshake and the dispatch through two interfaces:
//
//	type connectionStater interface{ ConnectionState() tls.ConnectionState }
//	type handshakeContexter interface{ HandshakeContext(ctx context.Context) error }
//
// and, when the negotiated protocol is "h2", hands the net.Conn straight to
// net/http's own HTTP/2 implementation. *Conn satisfies both (see the
// assertions in conn.go), so net/http can drive our connections end to end:
// it performs the handshake under its own timeout, routes ALPN, tracks every
// connection for graceful shutdown, and sends the HTTP/2 GOAWAYs. None of
// that needs to live here anymore.
//
// Server remains a wrapper around http.Server, rather than the type itself,
// only to keep two guarantees the rest of howsmyssl and this package's tests
// rely on: repeat and concurrent Serve calls all observe the same outcome,
// and a listener that something else already closed isn't reported as a
// shutdown failure.
type Server struct {
	h1 *http.Server
	li net.Listener

	// startOnce gates the launch of the h1.Serve goroutine. It matters for
	// more than tidiness: each http.Server.Serve call tracks the listener
	// it's given, and Shutdown closes each registration in turn, so a
	// second concurrent Serve would make Shutdown report net.ErrClosed
	// from the redundant close.
	startOnce sync.Once

	// serveDone is closed when the h1.Serve goroutine returns. serveErr is
	// written before the close, so reads after `<-serveDone` are
	// well-defined. Using a closeable channel (rather than a buffered
	// error channel with a single slot) lets every Serve caller observe
	// the result, so repeat / concurrent Serve calls don't block forever
	// on a drained buffer.
	serveDone chan struct{}
	serveErr  error

	// connMu guards conns, which holds one entry per live connection. See
	// closeIdleH2Conns for why we track this ourselves.
	connMu sync.Mutex
	conns  map[net.Conn]*connTrack
}

type connTrack struct {
	h2   bool // negotiated protocol was h2; decided once, on first use
	idle bool // no request in flight
}

// connState is http.Server's ConnState hook. net/http's HTTP/2 server drives
// it for h2 conns the same way the HTTP/1.x server does for its own, which is
// the only way to learn that an h2 conn has gone quiet.
func (s *Server) connState(c net.Conn, st http.ConnState) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	switch st {
	case http.StateIdle, http.StateActive:
		t, ok := s.conns[c]
		if !ok {
			// Reading ConnectionState is meaningful, and worth doing once
			// per conn rather than per request, only from here on:
			// net/http reports these states after the handshake it drove
			// has completed.
			hc, isOurs := c.(*Conn)
			t = &connTrack{h2: isOurs && hc.ConnectionState().NegotiatedProtocol == "h2"}
			s.conns[c] = t
		}
		t.idle = st == http.StateIdle
	case http.StateClosed, http.StateHijacked:
		delete(s.conns, c)
	}
}

// closeIdleH2Conns closes every tracked HTTP/2 conn that has no streams in
// flight.
//
// It works around a net/http race that would otherwise make our Shutdown
// unreliable. http.Server.Shutdown reaches HTTP/2 conns in one shot: it runs
// the hook that sweeps the HTTP/2 server's set of active conns and sends each
// one a GOAWAY. A conn that finishes its TLS handshake before Shutdown starts
// but registers itself with the HTTP/2 server after that sweep is never told
// to shut down, and Shutdown's own closeIdleConns can't reclaim it either,
// because net/http deliberately parks HTTP/2 conns in StateActive for their
// whole lifetime (go.dev/issue/39776). Shutdown then polls until its context
// expires. It is easy to hit whenever a client is still opening connections
// as shutdown begins: a plain net/http TLS server, with none of this package
// involved, loses the race for about a third of the runs of a 50-request
// version of TestServer_ShutdownDrainsInFlight.
//
// Closing a conn that reports no streams in flight drains it as safely as the
// GOAWAY it missed would have: every request that conn accepted has already
// been answered. If this is ever fixed upstream, this and connState can go.
func (s *Server) closeIdleH2Conns() {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	for c, t := range s.conns {
		if t.h2 && t.idle {
			c.Close()
			delete(s.conns, c)
		}
	}
}

// NewServer creates a new Server with the given listener and handler. The
// listener is expected to be a *Listener, or, at least, a listener created
// with tls1266.Listen.
func NewServer(listener net.Listener, handler http.Handler) (*Server, error) {
	h1 := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       2 * time.Minute,

		// net/http applies the minimum of the positive timeouts above to
		// the TLS handshake itself, and uses IdleTimeout for idle HTTP/2
		// conns as well as HTTP/1.x ones.

		ConnContext: addTLSConnToContext,

		HTTP2: &http.HTTP2Config{
			// Server-side keepalive ping. Detects half-open conns
			// through NLBs/proxies that silently drop state.
			SendPingTimeout: 30 * time.Second,
			PingTimeout:     15 * time.Second,
		},
	}

	s := &Server{
		h1:        h1,
		li:        listener,
		serveDone: make(chan struct{}),
		conns:     map[net.Conn]*connTrack{},
	}
	h1.ConnState = s.connState
	return s, nil
}

// Serve serves HTTP/1.x and HTTP/2 and blocks until the server is shut down.
// Returns http.ErrServerClosed after a successful Shutdown or Close, or the
// underlying error otherwise.
//
// Only the first call starts serving; subsequent concurrent or later calls
// observe the same outcome. After Shutdown or Close has been called without a
// preceding Serve, future Serve calls return http.ErrServerClosed: net/http
// refuses to track a listener for a server that is already shutting down.
func (s *Server) Serve() error {
	s.startOnce.Do(func() {
		go func() {
			s.serveErr = s.h1.Serve(s.li)
			close(s.serveDone)
		}()
	})
	<-s.serveDone
	if errors.Is(s.serveErr, http.ErrServerClosed) {
		return http.ErrServerClosed
	}
	return s.serveErr
}

// Shutdown gracefully shuts down the server. It stops accepting new
// connections, waits for in-flight HTTP/1.x requests to finish, and sends
// GOAWAY on every active HTTP/2 connection, force-closing whatever is still
// live when ctx expires.
//
// Once Shutdown has been called, the server may not be reused; future calls
// to Serve return http.ErrServerClosed.
func (s *Server) Shutdown(ctx context.Context) error {
	// h1.Shutdown closes the listeners it is tracking, so the extra close
	// at the end is for the case where Serve never ran and the listener
	// would otherwise leak. It reports net.ErrClosed the rest of the time.
	done := make(chan error, 1)
	go func() { done <- s.h1.Shutdown(ctx) }()

	// Reap HTTP/2 conns that net/http won't; see closeIdleH2Conns.
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	var err error
	for waiting := true; waiting; {
		select {
		case err = <-done:
			waiting = false
		case <-tick.C:
			s.closeIdleH2Conns()
		}
	}
	if err != nil && ctx.Err() != nil {
		// The drain ran out of time. Force-close whatever is still live
		// rather than leaking it, the same way the caller would have to.
		err = errors.Join(err, filterBenignClose(s.h1.Close()))
	}
	return errors.Join(filterBenignClose(err), filterBenignClose(s.li.Close()))
}

// Close immediately closes the listener and every tracked connection,
// regardless of state. For a graceful drain, use Shutdown.
//
// Once Close has been called, the server may not be reused; future calls to
// Serve return http.ErrServerClosed.
func (s *Server) Close() error {
	err := s.h1.Close()
	return errors.Join(filterBenignClose(err), filterBenignClose(s.li.Close()))
}

// RegisterOnShutdown registers a function to call on Shutdown. See
// http.Server.RegisterOnShutdown for details.
func (s *Server) RegisterOnShutdown(f func()) { s.h1.RegisterOnShutdown(f) }
