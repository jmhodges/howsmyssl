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
			// HTTP/1.x conns report their close here, so the test can wait
			// for the server to be done reading each one. HTTP/2 conns
			// don't pass through it.
			closed := make(chan struct{}, 16)
			srv.h1.ConnState = func(_ net.Conn, st http.ConnState) {
				if st == http.StateClosed {
					closed <- struct{}{}
				}
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
			if proto == "http/1.1" {
				// The server may read a hang-up twice. Counting stops
				// only once it has closed the conn.
				for i := range n {
					select {
					case <-closed:
					case <-time.After(5 * time.Second):
						t.Fatalf("the server closed %d of %d conns after 5s", i, n)
					}
				}
			}

			if got := statValue(ns, "handshake", "successes"); got != n {
				t.Errorf("handshake successes = %d, want %d", got, n)
			}
			for _, key := range []string{"errors", "eofs", "read_timeouts", "write_timeouts", "unknown_timeouts", "intentional_closes", "peer_resets", "unknown_errors"} {
				if got := statValue(ns, "handshake", key); got != 0 {
					t.Errorf("handshake %s = %d after %d clean requests, want 0", key, got, n)
				}
			}
			for _, key := range []string{"errors", "read_timeouts", "write_timeouts", "unknown_timeouts", "peer_resets", "unknown_errors"} {
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

// acceptedConn returns the server end of a real TLS connection over loopback,
// wrapped by a Listener, after its handshake, and the client end.
func acceptedConn(t *testing.T) (*Conn, *origtls.Conn, *connStats) {
	t.Helper()
	nl, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	li := NewListener(nl, new(expvar.Map).Init())
	t.Cleanup(func() { li.Close() })

	clientCh := make(chan *origtls.Conn, 1)
	go func() {
		c, err := origtls.Dial("tcp", li.Addr().String(), &origtls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Errorf("dial: %s", err)
		}
		clientCh <- c
	}()
	nc, err := li.Accept()
	if err != nil {
		t.Fatal(err)
	}
	conn := nc.(*Conn)
	t.Cleanup(func() { conn.Close() })
	if err := conn.Handshake(); err != nil {
		t.Fatalf("server handshake: %s", err)
	}
	client := <-clientCh
	if client == nil {
		t.FailNow()
	}
	t.Cleanup(func() { client.Close() })
	return conn, client, li.connStats
}

// TestConn_ReadErrorCountedOnce covers a read error that tls1274 keeps and
// returns from every Read after it. That is one event, however many times
// the conn is read afterwards, so it must count once. Timeouts aren't kept,
// so each one is a new read and counts on its own.
func TestConn_ReadErrorCountedOnce(t *testing.T) {
	const reads = 3
	b := make([]byte, 1)

	t.Run("EOF", func(t *testing.T) {
		conn, client, stats := acceptedConn(t)
		client.Close()
		for i := range reads {
			if _, err := conn.Read(b); err != io.EOF {
				t.Fatalf("Read #%d: err = %v, want io.EOF", i, err)
			}
		}
		if got := stats.PostHandshakeErrs.EOFs.Value(); got != 1 {
			t.Errorf("post_handshake eofs = %d after one hang-up read %d times, want 1", got, reads)
		}
		if got := stats.PostHandshakeErrs.Errs.Value(); got != 0 {
			t.Errorf("post_handshake errors = %d, want 0", got)
		}
	})

	t.Run("PeerReset", func(t *testing.T) {
		conn, client, stats := acceptedConn(t)
		// Linger 0 makes the close send a RST instead of a FIN.
		if err := client.NetConn().(*net.TCPConn).SetLinger(0); err != nil {
			t.Fatal(err)
		}
		client.NetConn().Close()
		for i := range reads {
			if _, err := conn.Read(b); err == nil {
				t.Fatalf("Read #%d: err = nil after the peer reset", i)
			}
		}
		if got := stats.PostHandshakeErrs.PeerResets.Value(); got != 1 {
			t.Errorf("post_handshake peer_resets = %d after one reset read %d times, want 1", got, reads)
		}
		if got := stats.PostHandshakeErrs.Errs.Value(); got != 1 {
			t.Errorf("post_handshake errors = %d after one reset, want 1", got)
		}
	})

	t.Run("ReadTimeouts", func(t *testing.T) {
		conn, client, stats := acceptedConn(t)
		for i := range reads {
			conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			if _, err := conn.Read(b); !isTimeout(err) {
				t.Fatalf("Read #%d: err = %v, want a timeout", i, err)
			}
		}
		if got := stats.PostHandshakeErrs.ReadTimeouts.Value(); got != reads {
			t.Errorf("post_handshake read_timeouts = %d after %d timed-out reads, want %d", got, reads, reads)
		}
		// A hang-up after the timeouts still counts, once.
		conn.SetReadDeadline(time.Time{})
		client.Close()
		for i := range reads {
			if _, err := conn.Read(b); err != io.EOF {
				t.Fatalf("Read #%d after the hang-up: err = %v, want io.EOF", i, err)
			}
		}
		if got := stats.PostHandshakeErrs.EOFs.Value(); got != 1 {
			t.Errorf("post_handshake eofs = %d after one hang-up, want 1", got)
		}
	})
}

// TestListener_HangUpDuringRequestCountedOnce has each client hang up while
// its request's handler is still running, so net/http's HTTP/1.x background
// read is the one that sees the EOF. The server then reads the conn once more
// for the next request and gets the same EOF from tls1274. That is still one
// hang-up, and must count once. The handler waits until the background read
// has seen the hang-up, and the test waits until the server has closed every
// conn, so the second read has always happened before the counters are read.
func TestListener_HangUpDuringRequestCountedOnce(t *testing.T) {
	cert := selfSignedCert(t)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	nl, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ns := new(expvar.Map).Init()
	li := NewListener(nl, ns)
	srv, err := NewServer(li, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A known length lets the client read the whole body, and hang
		// up, before this handler returns.
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "ok")
		w.(http.Flusher).Flush()
		// The conn's context ends when the background read sees the
		// hang-up.
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
			t.Errorf("the server's background read didn't see the client hang up within 5s")
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{}, 16)
	srv.h1.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateClosed {
			closed <- struct{}{}
		}
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
	url := "https://" + li.Addr().String() + "/"

	const n = 3
	for i := range n {
		tr := &http.Transport{TLSClientConfig: &origtls.Config{RootCAs: roots, ServerName: "localhost"}}
		resp, err := (&http.Client{Transport: tr}).Get(url)
		if err != nil {
			t.Fatalf("request %d: %s", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 1 {
			t.Fatalf("request %d: got %s, want HTTP/1.1", i, resp.Proto)
		}
		tr.CloseIdleConnections()
	}
	for i := range n {
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatalf("the server closed %d of %d conns after 5s", i, n)
		}
	}

	if got := statValue(ns, "post_handshake", "eofs"); got != n {
		t.Errorf("post_handshake eofs = %d after %d hang-ups, want %d", got, n, n)
	}
	if got := statValue(ns, "post_handshake", "errors"); got != 0 {
		t.Errorf("post_handshake errors = %d, want 0", got)
	}
	if got := statValue(ns, "handshake", "errors"); got != 0 {
		t.Errorf("handshake errors = %d, want 0", got)
	}
}
