package howhttp_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jmhodges/howsmyssl/howhttp"
	howhttptest "github.com/jmhodges/howsmyssl/howhttp/httptest"
)

var noopHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

func TestServer_ShutdownBeforeServe(t *testing.T) {
	hs := howhttptest.NewUnstartedServer(noopHandler)
	t.Cleanup(func() { _ = hs.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := hs.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- hs.Serve() }()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve after Shutdown returned %v, want http.ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
}

func TestServer_CloseBeforeServe(t *testing.T) {
	hs := howhttptest.NewUnstartedServer(noopHandler)
	t.Cleanup(func() { _ = hs.Close() })

	if err := hs.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- hs.Serve() }()
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve after Close returned %v, want http.ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
}

func TestServer_DoubleShutdown(t *testing.T) {
	hs := howhttptest.NewUnstartedServer(noopHandler)
	t.Cleanup(func() { _ = hs.Close() })

	var wg sync.WaitGroup
	wg.Add(2)
	errs := make([]error, 2)
	for i := range errs {
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			errs[i] = hs.Shutdown(ctx)
		}(i)
	}
	doneAll := make(chan struct{})
	go func() { wg.Wait(); close(doneAll) }()
	select {
	case <-doneAll:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent Shutdown calls did not return")
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("Shutdown #%d: %v", i, err)
		}
	}
}

func TestServer_ServeReturnsErrServerClosed(t *testing.T) {
	hs := howhttptest.NewUnstartedServer(noopHandler)
	t.Cleanup(func() { _ = hs.Close() })

	serveErr := make(chan error, 1)
	go func() { serveErr <- hs.Serve() }()

	// Give Serve a moment to actually enter the loop. Not strictly
	// required for correctness (Shutdown handles either order) but makes
	// the test exercise the post-Serve path rather than the pre-Serve
	// shortcut.
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := hs.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}

	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve returned %v, want http.ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
}

func TestServer_RepeatServeReturnsErrServerClosed(t *testing.T) {
	hs := howhttptest.NewUnstartedServer(noopHandler)
	t.Cleanup(func() { _ = hs.Close() })

	first := make(chan error, 1)
	go func() { first <- hs.Serve() }()

	// Give Serve a moment to enter the loop so the test exercises the
	// post-startOnce path, not the pre-Serve fast path.
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := hs.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}

	select {
	case err := <-first:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("first Serve returned %v, want ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first Serve did not return after Shutdown")
	}

	// A second Serve call after the server is done must not block on a
	// drained buffered channel — it has to return the same outcome.
	second := make(chan error, 1)
	go func() { second <- hs.Serve() }()
	select {
	case err := <-second:
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("second Serve returned %v, want ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Serve hung — Serve is not safe to call after the server has stopped")
	}
}

func TestServer_ConcurrentServeBothReturn(t *testing.T) {
	hs := howhttptest.NewUnstartedServer(noopHandler)
	t.Cleanup(func() { _ = hs.Close() })

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(len(errs))
	for i := range errs {
		go func(i int) {
			defer wg.Done()
			errs[i] = hs.Serve()
		}(i)
	}

	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := hs.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("concurrent Serves did not both return after Shutdown")
	}

	for i, err := range errs {
		if !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve #%d returned %v, want ErrServerClosed", i, err)
		}
	}
}

func TestServer_RegisterOnShutdown(t *testing.T) {
	hs := howhttptest.NewUnstartedServer(noopHandler)
	t.Cleanup(func() { _ = hs.Close() })

	fired := make(chan struct{})
	hs.RegisterOnShutdown(func() { close(fired) })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := hs.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	select {
	case <-fired:
	case <-time.After(2 * time.Second):
		t.Fatal("RegisterOnShutdown callback did not fire")
	}
}

// fatalAcceptListener is a net.Listener whose Accept always returns a
// non-retriable error. It counts Close calls so the test can assert the
// underlying listener was released.
type fatalAcceptListener struct {
	err    error
	closes atomic.Int32
}

func (l *fatalAcceptListener) Accept() (net.Conn, error) { return nil, l.err }
func (l *fatalAcceptListener) Close() error              { l.closes.Add(1); return nil }
func (l *fatalAcceptListener) Addr() net.Addr            { return &net.TCPAddr{} }

func TestServer_FatalAcceptClosesRealListener(t *testing.T) {
	li := &fatalAcceptListener{err: errors.New("fatal accept error for test")}
	hs, err := howhttp.NewServer(li, noopHandler)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- hs.Serve() }()

	select {
	case <-serveErr:
		// Don't assert on the error class — the accept loop translates the
		// fatal error into an http.ErrServerClosed from h1.Serve. What we
		// care about is that the real listener was closed.
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after fatal Accept error")
	}

	if got := li.closes.Load(); got < 1 {
		t.Errorf("realLi.Close call count = %d, want >=1", got)
	}
}

func TestServer_CloseForcesH2(t *testing.T) {
	// Handler that blocks until the request context is cancelled — i.e.
	// until the underlying h2 conn is torn down.
	handlerEntered := make(chan struct{})
	srv := howhttptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case handlerEntered <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))

	// Kick off an h2 request that will hang in the handler.
	reqDone := make(chan error, 1)
	go func() {
		resp, err := srv.Client().Get(srv.URL + "/")
		if err != nil {
			reqDone <- err
			return
		}
		_, err = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		reqDone <- err
	}()

	select {
	case <-handlerEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("handler never entered")
	}

	// Now force-close. Should return quickly even though the handler is
	// still parked.
	closeStart := time.Now()
	if err := srv.Config.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if elapsed := time.Since(closeStart); elapsed > 2*time.Second {
		t.Errorf("Close took %v, want under 2s", elapsed)
	}

	select {
	case <-reqDone:
	case <-time.After(2 * time.Second):
		t.Fatal("client request did not unblock after Close")
	}
}
