package howhttp

import (
	"context"
	"expvar"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	tls "github.com/jmhodges/howsmyssl/tls1274"
)

// lineRecorder collects what a logLimiter logs.
type lineRecorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *lineRecorder) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *lineRecorder) get() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

// TestLogLimiter_Window covers the limiter on its own clock: max lines a
// window, then one line saying how many were dropped when the next window
// starts.
func TestLogLimiter_Window(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	rec := &lineRecorder{}
	l := newLogLimiter("unknown tls error", 3, time.Minute)
	l.now = func() time.Time { return now }
	l.logf = rec.logf

	for i := range 100 {
		l.printf("err %d", i)
	}
	want := []string{
		"unknown tls error: err 0",
		"unknown tls error: err 1",
		"unknown tls error: err 2",
	}
	if got := rec.get(); !equalLines(got, want) {
		t.Fatalf("first window logged %q, want %q", got, want)
	}

	now = now.Add(59 * time.Second)
	l.printf("still the first window")
	if got := rec.get(); len(got) != 3 {
		t.Fatalf("a line 59s in was logged: %q", got[3:])
	}

	now = now.Add(time.Second)
	l.printf("second window")
	want = append(want,
		"unknown tls error: 98 more not logged since 2026-11-23T12:00:00Z",
		"unknown tls error: second window",
	)
	if got := rec.get(); !equalLines(got, want) {
		t.Fatalf("after the window logged %q, want %q", got, want)
	}

	// A window with nothing dropped adds no summary line.
	now = now.Add(time.Hour)
	l.printf("after a quiet hour")
	want = append(want, "unknown tls error: after a quiet hour")
	if got := rec.get(); !equalLines(got, want) {
		t.Fatalf("after a quiet hour logged %q, want %q", got, want)
	}
}

func equalLines(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestErrStats_UnknownErrsCountedEvenWhenNotLogged has many unknown errors
// arrive at once. Every one counts in Errs and UnknownErrs, but only
// unknownErrLogsPerWindow are logged.
func TestErrStats_UnknownErrsCountedEvenWhenNotLogged(t *testing.T) {
	stats := newErrStats(new(expvar.Map).Init(), true)
	rec := &lineRecorder{}
	stats.unknownLog.logf = rec.logf

	const n = 500
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			stats.count(fmt.Errorf("tls: some odd failure %d", i), false, false)
		})
	}
	wg.Wait()

	if got := stats.Errs.Value(); got != n {
		t.Errorf("Errs = %d, want %d", got, n)
	}
	if got := stats.UnknownErrs.Value(); got != n {
		t.Errorf("UnknownErrs = %d, want %d", got, n)
	}
	if got := len(rec.get()); got != unknownErrLogsPerWindow {
		t.Errorf("logged %d lines for %d unknown errors, want %d", got, n, unknownErrLogsPerWindow)
	}
}

// TestErrStats_KnownErrsAreNotUnknown checks the kinds that have their own
// counter don't count as unknown and don't log.
func TestErrStats_KnownErrsAreNotUnknown(t *testing.T) {
	stats := newErrStats(new(expvar.Map).Init(), true)
	rec := &lineRecorder{}
	stats.unknownLog.logf = rec.logf

	stats.count(io.EOF, false, false)
	stats.count(net.ErrClosed, true, false)
	stats.count(&net.OpError{Op: "read", Err: errFakeTimeout{}}, false, false)

	if got := stats.UnknownErrs.Value(); got != 0 {
		t.Errorf("UnknownErrs = %d, want 0", got)
	}
	if got := rec.get(); len(got) != 0 {
		t.Errorf("logged %q, want nothing", got)
	}
}

type errFakeTimeout struct{}

func (errFakeTimeout) Error() string   { return "fake timeout" }
func (errFakeTimeout) Timeout() bool   { return true }
func (errFakeTimeout) Temporary() bool { return true }

// TestListener_ManyFailedHandshakesLogBounded sends a burst of bytes that
// aren't a TLS ClientHello to a real server, the way a scanner does. Every
// failed handshake must be counted, and the log must stay bounded.
func TestListener_ManyFailedHandshakesLogBounded(t *testing.T) {
	nl, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	ns := new(expvar.Map).Init()
	li := NewListener(nl, ns)
	rec := &lineRecorder{}
	li.HandshakeErrs.unknownLog.logf = rec.logf
	li.PostHandshakeErrs.unknownLog.logf = rec.logf
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

	const n = 80
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			c, err := net.Dial("tcp", li.Addr().String())
			if err != nil {
				t.Errorf("conn %d: %s", i, err)
				return
			}
			defer c.Close()
			io.WriteString(c, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
			c.SetReadDeadline(time.Now().Add(5 * time.Second))
			io.Copy(io.Discard, c)
		})
	}
	wg.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for statValue(ns, "handshake", "errors") < n {
		if time.Now().After(deadline) {
			t.Fatalf("handshake errors = %d after %d failed handshakes and 5s, want %d (handshake: %s)", statValue(ns, "handshake", "errors"), n, n, ns.Get("handshake"))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := statValue(ns, "handshake", "errors"); got != n {
		t.Errorf("handshake errors = %d, want %d", got, n)
	}
	if got := statValue(ns, "handshake", "unknown_errors"); got != n {
		t.Errorf("handshake unknown_errors = %d, want %d", got, n)
	}
	lines := rec.get()
	if len(lines) != unknownErrLogsPerWindow {
		t.Errorf("logged %d lines for %d failed handshakes, want %d", len(lines), n, unknownErrLogsPerWindow)
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "unknown tls error: ") {
			t.Errorf("logged %q, want an \"unknown tls error: \" line", l)
		}
	}
}
