package howhttp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	origtls "crypto/tls"
	"crypto/x509"
	"expvar"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	tls "github.com/jmhodges/howsmyssl/tls1274"
	"golang.org/x/net/http2"
)

// pipeListener hands the server ends of in-memory connections to a Server,
// wrapped the way Listener.Accept wraps real ones. In-memory connections let
// the test below run on synctest's fake clock.
type pipeListener struct {
	conf  *tls.Config
	stats *connStats
	ch    chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return &Conn{Conn: tls.Server(c, l.conf), connStats: l.stats}, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{} }

// dial returns the client end of a new connection to the server.
func (l *pipeListener) dial() net.Conn {
	server, client := net.Pipe()
	l.ch <- server
	return client
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestServer_HTTP2ConnWithNoRequestIsClosed checks that the Server NewServer
// configures doesn't let an HTTP/2 client hold a connection open by being
// polite and asking for nothing. The client here finishes the TLS handshake,
// sends the HTTP/2 preface and its SETTINGS, answers every PING, and never
// opens a stream. Before noRequestTimeout applied to HTTP/2, the server kept
// that connection (and the ClientHello tls1274 saves on it) for 2 minutes.
//
// The limits under test are the real ones from NewServer. synctest's fake
// clock is what keeps this from taking that long to run.
func TestServer_HTTP2ConnWithNoRequestIsClosed(t *testing.T) {
	// A little over the 10s an HTTP/1.x client gets to send its request
	// headers: after the idle timeout, the server sends a GOAWAY and gives
	// the client a second to hang up before it closes the connection.
	//
	// These are written out, not taken from noRequestTimeout, so that
	// raising it means coming here and reading why it is short.
	const (
		minHeld = 10 * time.Second
		maxHeld = 12 * time.Second
	)

	synctest.Test(t, func(t *testing.T) {
		li := &pipeListener{
			conf: &tls.Config{
				Certificates: []tls.Certificate{selfSignedCert(t)},
				NextProtos:   []string{"h2", "http/1.1"},
			},
			stats: newConnStats(new(expvar.Map).Init()),
			ch:    make(chan net.Conn),
			done:  make(chan struct{}),
		}
		handled := false
		s, err := NewServer(li, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handled = true
		}))
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		serveDone := make(chan struct{})
		go func() {
			defer close(serveDone)
			s.Serve()
		}()
		defer func() {
			s.Close()
			<-serveDone
		}()

		c := origtls.Client(li.dial(), &origtls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		})
		defer c.Close()
		if err := c.Handshake(); err != nil {
			t.Fatalf("client handshake: %v", err)
		}
		if got := c.ConnectionState().NegotiatedProtocol; got != "h2" {
			t.Fatalf("negotiated protocol %q, want h2", got)
		}
		start := time.Now()

		// net.Pipe has no buffer, so reads have to be running before the
		// client writes anything: the server writes its session tickets and
		// SETTINGS before it reads the client's preface.
		var (
			wmu       sync.Mutex // guards writes to c
			fr        = http2.NewFramer(c, c)
			pings     int
			goAway    *http2.GoAwayFrame
			readErr   error
			closedAt  time.Time
			readsDone = make(chan struct{})
		)
		go func() {
			defer close(readsDone)
			for {
				f, err := fr.ReadFrame()
				if err != nil {
					readErr = err
					closedAt = time.Now()
					return
				}
				switch f := f.(type) {
				case *http2.SettingsFrame:
					if !f.IsAck() {
						wmu.Lock()
						fr.WriteSettingsAck()
						wmu.Unlock()
					}
				case *http2.PingFrame:
					if !f.IsAck() {
						pings++
						wmu.Lock()
						fr.WritePing(true, f.Data)
						wmu.Unlock()
					}
				case *http2.GoAwayFrame:
					goAway = f
				}
			}
		}()

		wmu.Lock()
		_, err = io.WriteString(c, http2.ClientPreface)
		if err == nil {
			err = fr.WriteSettings()
		}
		wmu.Unlock()
		if err != nil {
			t.Fatalf("writing the HTTP/2 preface and SETTINGS: %v", err)
		}

		<-readsDone
		held := closedAt.Sub(start)
		t.Logf("server closed the connection after %s (read error: %v, PINGs answered: %d)", held, readErr, pings)
		if held > maxHeld {
			t.Errorf("an HTTP/2 connection that never made a request was held for %s, want at most %s", held, maxHeld)
		}
		if held < minHeld {
			t.Errorf("connection was closed after %s, before the %s a client is allowed to take", held, minHeld)
		}
		if goAway == nil {
			t.Errorf("server closed the connection without a GOAWAY")
		} else if goAway.ErrCode != http2.ErrCodeNo {
			t.Errorf("GOAWAY error code was %s, want NO_ERROR", goAway.ErrCode)
		}
		if handled {
			t.Errorf("handler ran, but the client made no request")
		}

		// The server has to let go of the connection as well, or closing it
		// frees nothing.
		synctest.Wait()
		s.h2mu.Lock()
		n := len(s.h2conns)
		s.h2mu.Unlock()
		if n != 0 {
			t.Errorf("server still tracks %d HTTP/2 connections after closing the only one", n)
		}
	})
}
