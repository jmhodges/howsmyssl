package howhttp

import (
	"context"
	origtls "crypto/tls"
	"crypto/x509"
	"expvar"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	tls "github.com/jmhodges/howsmyssl/tls1274"
	"golang.org/x/net/http2"
)

// statValue reads ns[sub][key] as an int, or 0 if it isn't there.
func statValue(ns *expvar.Map, sub, key string) int64 {
	m, ok := ns.Get(sub).(*expvar.Map)
	if !ok {
		return 0
	}
	v, ok := m.Get(key).(*expvar.Int)
	if !ok {
		return 0
	}
	return v.Value()
}

// TestListener_CleanRequestsAddNoHandshakeErrors drives good requests over
// real TLS connections and then has the client hang up, the way any browser
// or curl does. Those connections end with the server's next Read seeing
// io.EOF. That must not show up in the handshake error counters, which are
// read under their expvar names ("handshake" -> "errors") so the test checks
// what an alert would read. It also must not count as a post-handshake error:
// an EOF after a complete request is an ordinary end, and so is net/http's
// HTTP/1.x server stopping its background read after each request.
func TestListener_CleanRequestsAddNoHandshakeErrors(t *testing.T) {
	for _, proto := range []string{"http/1.1", "h2"} {
		t.Run(proto, func(t *testing.T) {
			cert := selfSignedCert(t)
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			nl, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{proto},
			})
			if err != nil {
				t.Fatal(err)
			}
			ns := new(expvar.Map).Init()
			li := NewListener(nl, ns)
			srv, err := NewServer(li, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.WriteString(w, "ok")
			}))
			if err != nil {
				t.Fatal(err)
			}
			serveDone := make(chan error, 1)
			go func() { serveDone <- srv.Serve() }()
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				srv.Shutdown(ctx)
				<-serveDone
			})

			roots := x509.NewCertPool()
			roots.AddCert(leaf)
			clientTLS := &origtls.Config{RootCAs: roots, ServerName: "localhost"}
			url := "https://" + li.Addr().String() + "/"

			const n = 3
			for i := range n {
				// A new transport per request gives each request its own
				// connection, and so its own handshake.
				var rt http.RoundTripper
				var closeIdle func()
				if proto == "h2" {
					tr := &http2.Transport{TLSClientConfig: clientTLS}
					rt, closeIdle = tr, tr.CloseIdleConnections
				} else {
					tr := &http.Transport{TLSClientConfig: clientTLS}
					rt, closeIdle = tr, tr.CloseIdleConnections
				}
				resp, err := (&http.Client{Transport: rt}).Get(url)
				if err != nil {
					t.Fatalf("request %d: %s", i, err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("request %d: status %d", i, resp.StatusCode)
				}
				if wantMajor := map[string]int{"h2": 2, "http/1.1": 1}[proto]; resp.ProtoMajor != wantMajor {
					t.Fatalf("request %d: got %s, want %s", i, resp.Proto, proto)
				}
				closeIdle()
			}

			// Wait for the server to see each client hang up, wherever it
			// counts that.
			deadline := time.Now().Add(5 * time.Second)
			for {
				seen := statValue(ns, "handshake", "errors") + statValue(ns, "post_handshake", "eofs")
				if seen >= n {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("server saw %d of %d client hang-ups after 5s", seen, n)
				}
				time.Sleep(10 * time.Millisecond)
			}

			if got := statValue(ns, "handshake", "successes"); got != n {
				t.Errorf("handshake successes = %d, want %d", got, n)
			}
			for _, key := range []string{"errors", "eofs", "read_timeouts", "write_timeouts", "unknown_timeouts", "intentional_closes", "peer_resets"} {
				if got := statValue(ns, "handshake", key); got != 0 {
					t.Errorf("handshake %s = %d after %d clean requests, want 0", key, got, n)
				}
			}
			for _, key := range []string{"errors", "read_timeouts", "write_timeouts", "unknown_timeouts", "peer_resets"} {
				if got := statValue(ns, "post_handshake", key); got != 0 {
					t.Errorf("post_handshake %s = %d after %d clean requests, want 0", key, got, n)
				}
			}
			if got := statValue(ns, "post_handshake", "eofs"); got != n {
				t.Errorf("post_handshake eofs = %d, want %d", got, n)
			}
		})
	}
}

// TestListener_FailedHandshakesAreCounted sends bytes that aren't a TLS
// ClientHello to a real server. That handshake fails, and the failure must
// show up in the "handshake" counters, with nothing in "post_handshake".
func TestListener_FailedHandshakesAreCounted(t *testing.T) {
	nl, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	ns := new(expvar.Map).Init()
	li := NewListener(nl, ns)
	srv, err := NewServer(li, http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		<-serveDone
	})

	const n = 2
	for i := range n {
		c, err := net.Dial("tcp", li.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
		// The server answers with an alert or just closes; either way
		// it's done with us once the read ends.
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.Copy(io.Discard, c); err != nil {
			t.Logf("conn %d: %s", i, err)
		}
		c.Close()
	}

	deadline := time.Now().Add(5 * time.Second)
	for statValue(ns, "handshake", "errors") < n {
		if time.Now().After(deadline) {
			t.Fatalf("handshake errors = %d after %d failed handshakes and 5s, want %d (handshake: %s)", statValue(ns, "handshake", "errors"), n, n, ns.Get("handshake"))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := statValue(ns, "handshake", "successes"); got != 0 {
		t.Errorf("handshake successes = %d, want 0", got)
	}
	if m, ok := ns.Get("post_handshake").(*expvar.Map); ok {
		m.Do(func(kv expvar.KeyValue) {
			if v, ok := kv.Value.(*expvar.Int); ok && v.Value() != 0 {
				t.Errorf("post_handshake %s = %d after only failed handshakes, want 0", kv.Key, v.Value())
			}
		})
	}
}
