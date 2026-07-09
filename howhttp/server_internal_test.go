package howhttp

import (
	"expvar"
	"net"
	"net/http"
	"testing"
	"time"

	tls "github.com/jmhodges/howsmyssl/tls1265"
	"golang.org/x/net/http2"
)

// TestServeH2BailsWhenShuttingDown is a deterministic test for the
// close-vs-spawn race: a serve() goroutine that finishes its handshake
// after Close has begun must not insert into h2conns or Add to h2wg.
// Doing either could deadlock h2wg.Wait or panic on Add-after-Wait.
func TestServeH2BailsWhenShuttingDown(t *testing.T) {
	s := &Server{
		h1:         &http.Server{},
		h2:         &http2.Server{},
		h2conns:    map[net.Conn]struct{}{},
		serveDone:  make(chan struct{}),
		acceptDone: make(chan struct{}),
	}
	s.inShutdown.Store(true)

	serverPipe, clientPipe := net.Pipe()
	defer clientPipe.Close()

	conn := &Conn{
		Conn:           tls.Server(serverPipe, &tls.Config{}),
		handshakeStats: newHandshakeStats(new(expvar.Map).Init()),
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.serveH2(conn)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveH2 did not return promptly when shuttingDown")
	}

	s.h2mu.Lock()
	n := len(s.h2conns)
	s.h2mu.Unlock()
	if n != 0 {
		t.Errorf("h2conns has %d entries, want 0", n)
	}

	// h2wg.Wait must return immediately — Add(1) must not have been called.
	wgDone := make(chan struct{})
	go func() { s.h2wg.Wait(); close(wgDone) }()
	select {
	case <-wgDone:
	case <-time.After(time.Second):
		t.Fatal("h2wg.Wait blocked — Add(1) was called despite shuttingDown")
	}

	// The pipe should be closed from the server side; the client read
	// should see io.ErrClosedPipe.
	if _, err := clientPipe.Read(make([]byte, 1)); err == nil {
		t.Error("expected pipe read to error after serveH2 closed the conn")
	}
}
