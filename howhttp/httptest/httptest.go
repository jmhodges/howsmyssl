// Package howhttptest provides utilities for spinning up a [howhttp.Server]
// backed by a [tls1265.Listen]er for use in tests, in the style of
// [net/http/httptest].
//
// Use [NewServer] to start a server bound to 127.0.0.1 with a freshly
// generated, self-signed certificate. The returned [*Server] exposes a
// preconfigured [*http.Client] that trusts the generated certificate, plus
// builders for [*crypto/tls.Config] and [*tls1265.Config] for tests that need
// to drive raw TLS connections.
package howhttptest

import (
	"context"
	origtls "crypto/tls"
	"crypto/x509"
	"errors"
	"expvar"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/jmhodges/howsmyssl/howhttp"
	tls1265 "github.com/jmhodges/howsmyssl/tls1265"
)

// Server is a TLS HTTP server listening on a random localhost port, serving
// over a [tls1265.Listen]er wrapped by [howhttp.NewListener] and a
// [howhttp.Server]. It is the howhttp equivalent of
// [net/http/httptest.Server].
//
// The fields below are populated by [NewServer] and must not be mutated after
// it returns; they are exposed for inspection.
type Server struct {
	// URL is the base URL ("https://127.0.0.1:PORT") clients should target.
	URL string
	// Listener is the [howhttp.NewListener]-wrapped tls1265 listener that the
	// server is accepting on.
	Listener net.Listener
	// TLS is the [tls1265.Config] the server is using.
	TLS *tls1265.Config
	// Config is the underlying [howhttp.Server].
	Config *howhttp.Server

	leafCert *x509.Certificate
	rootCAs  *x509.CertPool

	serveErr chan error

	clientOnce sync.Once
	client     *http.Client
}

// NewServer starts and returns a new [Server] serving handler over TLS on a
// random localhost port. The server generates a fresh self-signed
// certificate at construction time; tests should obtain a trusting
// [*http.Client] via [Server.Client].
//
// NewServer panics if it cannot bind a listener, generate a certificate, or
// configure the underlying [howhttp.Server]. The caller must call
// [Server.Close] when finished.
func NewServer(handler http.Handler) *Server {
	certDER, leaf, key, err := generateLocalhostCert()
	if err != nil {
		panic(err)
	}

	rootCAs := x509.NewCertPool()
	rootCAs.AddCert(leaf)

	tlsConf := &tls1265.Config{
		Certificates: []tls1265.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
			Leaf:        leaf,
		}},
		NextProtos: []string{"h2", "http/1.1"},
	}

	nl, err := tls1265.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		panic(fmt.Errorf("howhttptest: listen: %w", err))
	}

	li := howhttp.NewListener(nl, new(expvar.Map).Init())

	hs, err := howhttp.NewServer(li, handler)
	if err != nil {
		li.Close()
		panic(fmt.Errorf("howhttptest: howhttp.NewServer: %w", err))
	}

	s := &Server{
		URL:      "https://" + li.Addr().String(),
		Listener: li,
		TLS:      tlsConf,
		Config:   hs,
		leafCert: leaf,
		rootCAs:  rootCAs,
		serveErr: make(chan error, 1),
	}

	go func() { s.serveErr <- hs.Serve() }()

	return s
}

// NewUnstartedServer returns a [howhttp.Server] bound to a plain TCP
// listener at 127.0.0.1 on a random port, with [howhttp.Server.Serve]
// not yet called. It is intended for tests that exercise the Server
// lifecycle ([howhttp.Server.Shutdown], [howhttp.Server.Close], etc.)
// without accepting real client connections — the underlying listener
// does not terminate TLS, so any connection that reaches Accept will
// fail at handshake.
//
// The caller is responsible for closing the returned server (calling
// Shutdown or Close, typically via t.Cleanup).
//
// NewUnstartedServer panics if it cannot bind a listener or
// configure the [howhttp.Server].
func NewUnstartedServer(handler http.Handler) *howhttp.Server {
	nl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(fmt.Errorf("howhttptest: net.Listen: %w", err))
	}
	li := howhttp.NewListener(nl, new(expvar.Map).Init())
	hs, err := howhttp.NewServer(li, handler)
	if err != nil {
		li.Close()
		panic(fmt.Errorf("howhttptest: howhttp.NewServer: %w", err))
	}
	return hs
}

// Close shuts the server down, blocking until in-flight requests finish or a
// short internal deadline expires.
//
// Close is a void function so it composes with `defer srv.Close()` and
// `t.Cleanup(srv.Close)`, but it does not swallow failures: if Shutdown
// errors (most commonly a context.DeadlineExceeded because something
// failed to drain) or the Serve goroutine returns a non-ErrServerClosed
// error, the error is logged so a hung or broken shutdown surfaces in
// the test output instead of disappearing.
func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Config.Shutdown(ctx); err != nil {
		log.Printf("howhttptest: Server.Close: Shutdown: %v", err)
	}
	if err := <-s.serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("howhttptest: Server.Close: Serve returned: %v", err)
	}
}

// Certificate returns the parsed leaf certificate the server is presenting.
func (s *Server) Certificate() *x509.Certificate { return s.leafCert }

// RootCAs returns the [*x509.CertPool] containing the server's leaf
// certificate. The same pool can be assigned to either a [*crypto/tls.Config]
// or a [*tls1265.Config], since both use the same [crypto/x509] type.
func (s *Server) RootCAs() *x509.CertPool { return s.rootCAs }

// ClientTLSConfig returns a fresh [*crypto/tls.Config] that trusts the
// server's certificate. The returned value may be freely mutated by the
// caller.
func (s *Server) ClientTLSConfig() *origtls.Config {
	return &origtls.Config{
		RootCAs:    s.rootCAs,
		ServerName: "127.0.0.1",
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// ClientTLS1265Config returns a fresh [*tls1265.Config] that trusts the
// server's certificate. Useful for tests that need to drive a raw
// [tls1265.Dial]-style client. The returned value may be freely mutated by
// the caller.
func (s *Server) ClientTLS1265Config() *tls1265.Config {
	return &tls1265.Config{
		RootCAs:    s.rootCAs,
		ServerName: "127.0.0.1",
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// Client returns an HTTP client preconfigured to trust the server's
// certificate and to negotiate HTTP/2 via ALPN when available. The same
// client instance is returned on subsequent calls.
func (s *Server) Client() *http.Client {
	s.clientOnce.Do(func() {
		s.client = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:   s.ClientTLSConfig(),
				ForceAttemptHTTP2: true,
			},
		}
	})
	return s.client
}
