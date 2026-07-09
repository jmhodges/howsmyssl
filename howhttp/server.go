package howhttp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	tls1265 "github.com/jmhodges/howsmyssl/tls1265"
	"golang.org/x/net/http2"
)

type contextKey struct{ name string }

func (k *contextKey) String() string { return "howhttp context value " + k.name }

// smuggledConnKey is for smuggling our wrapping *Conn's underlying *tls.Conn
// out to handlers that need to investigate the client's TLS settings.
var smuggledConnKey = &contextKey{"smuggledConn"}

// SmuggledConn returns the underlying *tls1265.Conn that was attached to the
// request's context.
func SmuggledConn(ctx context.Context) (*tls1265.Conn, bool) {
	tc, ok := ctx.Value(smuggledConnKey).(*tls1265.Conn)
	return tc, ok
}

// addTLSConnToContext is suitable for use as http.Server.ConnContext. It pulls
// the underlying *tls1265.Conn out of a *Conn and stashes it on the context for
// handlers to retrieve via SmuggledConn.
//
// We do this smuggling instead of using http.Hijacker.Hijack to avoid needing
// to do a bunch of connection management and HTTP response formatting
// ourselves. We smuggle the whole *tls1265.Conn into the context instead of
// just its ConnectionState because the handshake may not yet be performed, and
// we don't want to lock here waiting for the handshake to finish.
func addTLSConnToContext(ctx context.Context, c net.Conn) context.Context {
	tc, ok := c.(*Conn)
	if !ok {
		log.Printf("howhttp.addTLSConnToContext: unable to convert net.Conn to *howhttp.Conn: %#v\n", c)
		return ctx
	}
	return context.WithValue(ctx, smuggledConnKey, tc.Conn)
}

// Server is a wrapper around the net/http and x/http2 servers. It exists
// (instead of using net/http solely) to allow us to use HTTP/2 with our custom
// TLS library. The net/http library's TLSNextProto and similar hooks only work
// with types from the crypto/tls package, but we need our own TLS library to
// be used.
//
// Server has to route connections to the correct server based on the TLS ALPN
// protocol and do some tracking of the connections it creates. It uses
// http2.ConfigureServer solely to make sure that graceful shutdown works, but
// doesn't even let the HTTP/1.x server handle the ALPN routing to avoid the
// crypto/tls type problems (specifically, that TLSNextProto encodes the
// crypto/tls.Conn type).
type Server struct {
	h1        *http.Server
	h2        *http2.Server
	routingLi *routingListener
	realLi    net.Listener
	h2mu      sync.Mutex
	h2conns   map[net.Conn]struct{} // for force-close on ctx timeout
	h2wg      sync.WaitGroup        // waits for ServeConn goroutines to exit

	// startOnce gates the launch of Serve's background goroutines and
	// races with Shutdown/Close — whichever wins decides whether the
	// accept loop ever runs. Loser of the race takes a no-goroutines
	// fast path.
	startOnce sync.Once
	started   atomic.Bool

	// serveDone is closed when the h1.Serve goroutine returns. serveErr
	// is written before the close, so reads after `<-serveDone` are
	// well-defined. Using a closeable channel (rather than a buffered
	// error channel with a single slot) lets every Serve caller observe
	// the result, so repeat / concurrent Serve calls don't block forever
	// on a drained buffer.
	serveDone chan struct{}
	serveErr  error

	acceptDone chan struct{}
	inShutdown atomic.Bool
}

// NewServer creates a new Server with the given listener and handler. The
// listener is expected to be a *Listener, or, at least, a listener created
// with tls1265.Listen.
func NewServer(listener net.Listener, handler http.Handler) (*Server, error) {
	h1 := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       2 * time.Minute,

		ConnContext: addTLSConnToContext, // Also performed in the http2.ServeConnOpts
	}
	h2 := &http2.Server{
		IdleTimeout: 2 * time.Minute,

		// Server-side keepalive ping (Go 1.24+). Detects half-open conns
		// through NLBs/proxies that silently drop state.
		ReadIdleTimeout: 30 * time.Second,
		PingTimeout:     15 * time.Second,
	}

	// We call http2.ConfigureServer only to get h1.RegisterOnShutdown's
	// callback set up with the connections we create. However,
	err := http2.ConfigureServer(h1, h2)
	if err != nil {
		return nil, fmt.Errorf("unable to configure HTTP/2 server: %w", err)
	}

	rl := newRoutingListener(listener)

	return &Server{
		h1:         h1,
		h2:         h2,
		realLi:     listener,
		routingLi:  rl,
		h2conns:    map[net.Conn]struct{}{},
		serveDone:  make(chan struct{}),
		acceptDone: make(chan struct{}),
	}, nil
}

// Serve starts the HTTP/1.x and HTTP/2 service goroutines and blocks until
// the server is shut down. Returns http.ErrServerClosed after a successful
// Shutdown or Close, or the underlying error otherwise.
//
// Only the first call starts the goroutines; subsequent concurrent or
// later calls observe the same outcome (they block until h1.Serve returns
// and then return the same error). After Shutdown or Close has been called
// without a preceding Serve, future Serve calls return http.ErrServerClosed
// immediately.
func (s *Server) Serve() error {
	s.startOnce.Do(func() {
		s.started.Store(true)
		go func() {
			s.serveErr = s.h1.Serve(s.routingLi)
			close(s.serveDone)
		}()
		go s.acceptLoop()
	})
	if !s.started.Load() {
		return http.ErrServerClosed
	}
	<-s.serveDone
	if errors.Is(s.serveErr, http.ErrServerClosed) {
		return http.ErrServerClosed
	}
	return s.serveErr
}

func (s *Server) acceptLoop() {
	defer close(s.acceptDone)
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		c, err := s.realLi.Accept()
		if err != nil {
			if s.shuttingDown() {
				// h1.Shutdown / h1.Close will close routingLi and unblock
				// h1.Serve with http.ErrServerClosed.
				return
			}
			if retriableAcceptError(err) {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("howhttp: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			// Non-shutdown, non-retriable error: tear everything down so
			// Serve returns and realLi doesn't leak. Mark inShutdown so any
			// in-flight serve() goroutine that finishes its handshake after
			// this point bails out via the serveH2 guard rather than
			// registering an h2 conn that nothing will drain. Order: close
			// realLi first so the socket is released even if routingLi.Close
			// somehow blocks, then routingLi so h1.Serve returns.
			log.Printf("howhttp: fatal Accept error: %v", err)
			s.inShutdown.Store(true)
			s.realLi.Close()
			s.routingLi.Close()
			return
		}
		tempDelay = 0
		ourConn, ok := c.(*Conn)
		if !ok {
			log.Printf("Accept: unable to convert net.Conn to *howhttp.Conn: %#v\n", c)
			c.Close()
			continue
		}
		go s.serve(ourConn)
	}
}

func (s *Server) shuttingDown() bool {
	return s.inShutdown.Load()
}

// retriableAcceptError reports whether err returned from
// net.Listener.Accept is a transient condition worth retrying with
// backoff instead of tearing down the accept loop. It replaces the
// deprecated net.Error.Temporary().
//
// The set mirrors what stdlib's net.OpError.Temporary() returns true
// for on an "accept" op, minus errnos that can't surface from a
// blocking Listener.Accept in Go (EAGAIN/EWOULDBLOCK/ETIMEDOUT).
//
// Caveats worth knowing if this ever needs revisiting:
//
//   - EMFILE/ENFILE (per-process and system-wide FD exhaustion) are
//     retried here to match stdlib, but Bryan Mills has argued on
//     golang-nuts that retrying just hides the problem and a
//     semaphore capping concurrent conns would be better. If we ever
//     add that cap, EMFILE/ENFILE should probably become fatal.
//
//   - ECONNABORTED means the queued connection was reset by the peer
//     before Accept returned. It's benign — strictly it warrants
//     "continue immediately, don't sleep" rather than the backoff
//     path we share with FD exhaustion. We keep one code path for
//     simplicity; split it if the backoff ever shows up as latency.
//
//   - We deliberately don't retry the kernel-transient network
//     errnos accept(2) lists (ENETDOWN, EPROTO, ENOPROTOOPT,
//     EHOSTDOWN, ENONET, EHOSTUNREACH, EOPNOTSUPP, ENETUNREACH).
//     Those indicate real network problems and we'd rather surface
//     them than spin.
func retriableAcceptError(err error) bool {
	return errors.Is(err, syscall.EMFILE) ||
		errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EINTR)
}

func (s *Server) serve(c *Conn) {
	if to := s.tlsHandshakeTimeout(); to > 0 {
		dl := time.Now().Add(to)
		c.SetReadDeadline(dl)
		c.SetWriteDeadline(dl)
	}

	if err := c.HandshakeContext(context.Background()); err != nil {
		c.Close()
		return
	}

	// 3. Clear deadlines so http.Server / http2.Server set their own.
	c.SetReadDeadline(time.Time{})
	c.SetWriteDeadline(time.Time{})

	// 4. Now NegotiatedProtocol is valid; dispatch.
	switch c.ConnectionState().NegotiatedProtocol {
	case "h2":
		s.serveH2(c)
	default:
		if err := s.routingLi.deliverToHTTP1Server(c); err != nil {
			c.Close()
		}
	}
}

func (s *Server) serveH2(c *Conn) {
	// h2mu serializes us with closeAllH2Conns. Holding it across both the
	// inShutdown check and h2wg.Add ensures one of two orderings:
	//   - we run before shutdown: c is in h2conns AND Add(1) has happened
	//     before any closeAllH2Conns iteration or h2wg.Wait observation.
	//   - we run after shutdown: we see inShutdown==true and bail.
	// Without this, a serve() goroutine that finished its handshake just as
	// Close() began could slip its conn into the map after closeAllH2Conns
	// scanned, then Add(1) after h2wg.Wait() observed counter==0 — which is
	// either a hang (Wait re-blocks) or a panic (Add-after-Wait misuse).
	s.h2mu.Lock()
	if s.shuttingDown() {
		s.h2mu.Unlock()
		c.Close()
		return
	}
	s.h2conns[c] = struct{}{}
	s.h2wg.Add(1)
	s.h2mu.Unlock()

	go func() {
		defer s.h2wg.Done()
		defer func() {
			s.h2mu.Lock()
			delete(s.h2conns, c)
			s.h2mu.Unlock()
			c.Close()
		}()
		s.h2.ServeConn(c, &http2.ServeConnOpts{
			Context:    addTLSConnToContext(context.Background(), c),
			Handler:    s.h1.Handler,
			BaseConfig: s.h1,
		})
	}()
}

// Shutdown gracefully shuts down the server. It stops accepting new
// connections, waits for in-flight HTTP/1.x requests to finish, sends
// GOAWAY on every active HTTP/2 connection (and waits for them to drain),
// and force-closes any HTTP/2 connections still live when ctx expires.
//
// Once Shutdown has been called, the server may not be reused; future
// calls to Serve return http.ErrServerClosed.
func (s *Server) Shutdown(ctx context.Context) error {
	s.inShutdown.Store(true)
	s.preemptServe()

	// 1. Stop accepting new conns. The accept goroutine will close s.rl
	//    on its way out, which unblocks any in-flight h1.Serve Accept.
	s.realLi.Close()

	// 2. Wait for accept loop to finish dispatching anything already accepted.
	<-s.acceptDone

	// 3. h1.Shutdown drains active h1 requests AND, via the
	//    ConfigureServer-registered hook, sends GOAWAY on every active h2 conn.
	h1err := s.h1.Shutdown(ctx)

	// 4. Wait for h2.ServeConn goroutines to actually exit (h1.Shutdown
	//    doesn't track them). If ctx expires first, force-close.
	done := make(chan struct{})
	go func() { s.h2wg.Wait(); close(done) }()

	select {
	case <-done:
		return h1err
	case <-ctx.Done():
		s.closeAllH2Conns()
		s.h2wg.Wait()
		return errors.Join(h1err, ctx.Err())
	}
}

// Close immediately closes the listener and every tracked connection,
// regardless of state. For a graceful drain, use Shutdown.
//
// Once Close has been called, the server may not be reused; future
// calls to Serve return http.ErrServerClosed.
func (s *Server) Close() error {
	s.inShutdown.Store(true)
	s.preemptServe()
	realErr := s.realLi.Close()
	<-s.acceptDone
	h1err := s.h1.Close()
	s.closeAllH2Conns()
	s.h2wg.Wait()
	return errors.Join(filterBenignClose(realErr), filterBenignClose(h1err))
}

// filterBenignClose drops net.ErrClosed since it just means a listener or
// conn we were going to close was already closed by another path (the most
// common cases: double-Close, Close after Shutdown, or Close after the
// accept loop tore the listener down on a fatal Accept error). Callers
// shouldn't have to special-case that to tell real failures from idempotent
// teardown.
func filterBenignClose(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// RegisterOnShutdown registers a function to call on Shutdown. See
// http.Server.RegisterOnShutdown for details. Callbacks are run via
// s.h1, which is also where the http2 GOAWAY hook is registered, so user
// callbacks compose with it correctly.
func (s *Server) RegisterOnShutdown(f func()) { s.h1.RegisterOnShutdown(f) }

// preemptServe ensures Serve will never start the background goroutines
// after Shutdown/Close has been entered. If Serve has already run,
// startOnce is a no-op; if Serve has not yet run, we pre-close
// acceptDone so the <-s.acceptDone wait in Shutdown/Close doesn't block,
// and any later Serve sees startOnce done with started==false and
// returns http.ErrServerClosed.
func (s *Server) preemptServe() {
	s.startOnce.Do(func() {
		close(s.acceptDone)
	})
}

func (s *Server) closeAllH2Conns() {
	s.h2mu.Lock()
	defer s.h2mu.Unlock()
	for c := range s.h2conns {
		c.Close() // h2.ServeConn returns once the conn is closed
	}
}

// tlsHandshakeTimeout returns the time limit permitted for the TLS
// handshake, or zero for unlimited.
//
// It returns the minimum of any positive ReadHeaderTimeout,
// ReadTimeout, or WriteTimeout.
func (s *Server) tlsHandshakeTimeout() time.Duration {
	var ret time.Duration
	for _, v := range [...]time.Duration{
		s.h1.ReadHeaderTimeout,
		s.h1.ReadTimeout,
		s.h1.WriteTimeout,
	} {
		if v <= 0 {
			continue
		}
		if ret == 0 || v < ret {
			ret = v
		}
	}
	return ret
}

type routingListener struct {
	net.Listener
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newRoutingListener(li net.Listener) *routingListener {
	return &routingListener{Listener: li, ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *routingListener) deliverToHTTP1Server(c net.Conn) error {
	select {
	case l.ch <- c:
		return nil
	case <-l.done:
		return net.ErrClosed
	}
}

func (l *routingListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *routingListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}
