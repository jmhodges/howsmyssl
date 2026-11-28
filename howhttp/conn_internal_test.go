package howhttp

import (
	"expvar"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	tls "github.com/jmhodges/howsmyssl/tls1274"
)

// TestConn_HandshakeFailureCountedOnce locks in the contract that a single
// handshake failure produces exactly one error increment on the stats — no
// matter how many subsequent Read/Write calls hit the wrapper, and nothing
// in the post-handshake counters. Pre-fix, the error was counted once by
// handshake() and again by the Read/Write
// wrapper, inflating the counter for one logical event; the retry path also
// re-entered Conn.Conn.Read, which re-counted the cached handshake error.
func TestConn_HandshakeFailureCountedOnce(t *testing.T) {
	serverPipe, clientPipe := net.Pipe()
	// Close the peer immediately so the server-side Handshake errors out
	// reading the ClientHello.
	clientPipe.Close()

	stats := newConnStats(new(expvar.Map).Init())
	conn := &Conn{
		Conn:      tls.Server(serverPipe, &tls.Config{}),
		connStats: stats,
	}

	b := make([]byte, 1)
	for i := range 3 {
		if _, err := conn.Read(b); err == nil {
			t.Fatalf("Read #%d: expected error on conn with closed peer, got nil", i)
		}
	}

	if got := stats.HandshakeErrs.Errs.Value(); got != 1 {
		t.Errorf("HandshakeErrs.Errs = %d after 3 Reads on a failed-handshake conn, want 1", got)
	}
	if got := stats.HandshakeSuccesses.Value(); got != 0 {
		t.Errorf("HandshakeSuccesses = %d, want 0", got)
	}
	if got := stats.PostHandshakeErrs.Errs.Value(); got != 0 {
		t.Errorf("PostHandshakeErrs.Errs = %d on a failed-handshake conn, want 0", got)
	}
}

// TestConn_CloseMarksDraining confirms our Close override sets the
// draining flag before delegating to the embedded tls.Conn.Close. The
// flag is what lets errStats.count recognize a concurrent in-flight
// Read/Write's resulting net.ErrClosed as the expected teardown signal
// instead of logging it as anomalous.
func TestConn_CloseMarksDraining(t *testing.T) {
	serverPipe, clientPipe := net.Pipe()
	defer clientPipe.Close()

	conn := &Conn{
		Conn:      tls.Server(serverPipe, &tls.Config{}),
		connStats: newConnStats(new(expvar.Map).Init()),
	}
	if conn.draining.Load() {
		t.Fatal("draining set before Close")
	}
	_ = conn.Close()
	if !conn.draining.Load() {
		t.Fatal("draining not set after Close")
	}
}

// TestErrStats_IntentionalClose covers the post-Close
// classification: a net.ErrClosed observed on a draining conn is the
// frame reader (or a Write loop) noticing the close we performed. It
// bumps IntentionalCloses, still counts in a handshake's Errs (a close
// mid-handshake means it failed), and must not fall through to the "unknown tls error" log line.
func TestErrStats_IntentionalClose(t *testing.T) {
	stats := newErrStats(new(expvar.Map).Init(), true)

	stats.count(net.ErrClosed, true, false)

	if got := stats.IntentionalCloses.Value(); got != 1 {
		t.Errorf("IntentionalCloses = %d, want 1", got)
	}
	if got := stats.Errs.Value(); got != 1 {
		t.Errorf("Errs = %d, want 1", got)
	}
	if got := stats.PeerResets.Value(); got != 0 {
		t.Errorf("PeerResets = %d, want 0", got)
	}
}

// TestErrStats_NetErrClosedNotDraining confirms we don't
// quietly bucket a net.ErrClosed that arrived without our Close having
// run. Such an error means some path bypassed our wrapper Close, which
// is worth investigating, so it must still surface as "unknown tls
// error" rather than being absorbed by IntentionalCloses.
func TestErrStats_NetErrClosedNotDraining(t *testing.T) {
	stats := newErrStats(new(expvar.Map).Init(), true)

	stats.count(net.ErrClosed, false, false)

	if got := stats.IntentionalCloses.Value(); got != 0 {
		t.Errorf("IntentionalCloses = %d, want 0 (draining unset)", got)
	}
	if got := stats.Errs.Value(); got != 1 {
		t.Errorf("Errs = %d, want 1", got)
	}
}

// TestErrStats_TimeoutBeatsDraining locks in cascade ordering:
// a deadline that fires on the underlying net.Conn surfaces as a
// *net.OpError whose Timeout() is true, and that classification must
// win even if Close has already flipped the draining flag. Otherwise a
// concurrent Close racing a deadline would silently re-bucket real
// timeouts as IntentionalCloses and we'd lose visibility into them.
func TestErrStats_TimeoutBeatsDraining(t *testing.T) {
	stats := newErrStats(new(expvar.Map).Init(), true)

	// Shape matches what tls.Conn.Read returns when the underlying
	// net.Conn's read deadline fires: *net.OpError wrapping a
	// deadline-exceeded error whose Timeout() returns true.
	stats.count(&net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, true, false)

	if got := stats.ReadTimeouts.Value(); got != 1 {
		t.Errorf("ReadTimeouts = %d, want 1", got)
	}
	if got := stats.IntentionalCloses.Value(); got != 0 {
		t.Errorf("IntentionalCloses = %d, want 0 (timeout must win over draining)", got)
	}
	if got := stats.Errs.Value(); got != 1 {
		t.Errorf("Errs = %d, want 1", got)
	}
}

// TestErrStats_PeerReset covers ECONNRESET and EPIPE — the
// errors that show up when the peer (most often a TCP LB doing idle
// eviction, or a client hanging up mid-request) tears the conn down
// abruptly. They're benign on a public TLS endpoint; we count them so
// the rate is visible but don't log each one.
func TestErrStats_PeerReset(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"ECONNRESET", &net.OpError{Op: "read", Err: syscall.ECONNRESET}},
		{"EPIPE", &net.OpError{Op: "write", Err: syscall.EPIPE}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stats := newErrStats(new(expvar.Map).Init(), false)

			stats.count(tc.err, false, false)

			if got := stats.PeerResets.Value(); got != 1 {
				t.Errorf("PeerResets = %d, want 1", got)
			}
			if got := stats.Errs.Value(); got != 1 {
				t.Errorf("Errs = %d, want 1", got)
			}
			if got := stats.IntentionalCloses.Value(); got != 0 {
				t.Errorf("IntentionalCloses = %d, want 0", got)
			}
		})
	}
}

// TestErrStats_CleanEndsAfterHandshake locks in that, after a handshake, the
// normal ends of a connection — the client's EOF and our own Close — are
// counted under their own names but not in Errs, while real errors still are.
// During a handshake the same EOF is a failed handshake and counts in Errs.
func TestErrStats_CleanEndsAfterHandshake(t *testing.T) {
	post := newErrStats(new(expvar.Map).Init(), false)
	post.count(io.EOF, false, false)
	post.count(net.ErrClosed, true, false)
	if got := post.EOFs.Value(); got != 1 {
		t.Errorf("post EOFs = %d, want 1", got)
	}
	if got := post.IntentionalCloses.Value(); got != 1 {
		t.Errorf("post IntentionalCloses = %d, want 1", got)
	}
	if got := post.Errs.Value(); got != 0 {
		t.Errorf("post Errs = %d after an EOF and an intentional close, want 0", got)
	}
	post.count(&net.OpError{Op: "write", Err: os.ErrDeadlineExceeded}, false, false)
	if got := post.Errs.Value(); got != 1 {
		t.Errorf("post Errs = %d after a write timeout, want 1", got)
	}

	hs := newErrStats(new(expvar.Map).Init(), true)
	hs.count(io.EOF, false, false)
	if got := hs.EOFs.Value(); got != 1 {
		t.Errorf("handshake EOFs = %d, want 1", got)
	}
	if got := hs.Errs.Value(); got != 1 {
		t.Errorf("handshake Errs = %d after an EOF, want 1", got)
	}
}

// TestErrStats_ReadAbortIsNotATimeout covers net/http's HTTP/1.x server
// ending its background read after every request by setting the read
// deadline in the past. After a handshake that read's timeout is a read
// abort, not a read timeout or an error. A read timeout from a deadline
// that hadn't passed when it was set is still a timeout.
func TestErrStats_ReadAbortIsNotATimeout(t *testing.T) {
	post := newErrStats(new(expvar.Map).Init(), false)
	timeout := &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}
	post.count(timeout, false, true)
	if got := post.ReadAborts.Value(); got != 1 {
		t.Errorf("ReadAborts = %d, want 1", got)
	}
	if got := post.ReadTimeouts.Value(); got != 0 {
		t.Errorf("ReadTimeouts = %d after a read abort, want 0", got)
	}
	if got := post.Errs.Value(); got != 0 {
		t.Errorf("Errs = %d after a read abort, want 0", got)
	}
	post.count(timeout, false, false)
	if got := post.ReadTimeouts.Value(); got != 1 {
		t.Errorf("ReadTimeouts = %d after a real read timeout, want 1", got)
	}
	if got := post.Errs.Value(); got != 1 {
		t.Errorf("Errs = %d after a real read timeout, want 1", got)
	}
}

// TestConn_SetReadDeadlineNotesPastDeadlines checks the wrapper's deadline
// overrides, which feed readDeadlinePassed.
func TestConn_SetReadDeadlineNotesPastDeadlines(t *testing.T) {
	serverPipe, clientPipe := net.Pipe()
	defer clientPipe.Close()
	conn := &Conn{
		Conn:      tls.Server(serverPipe, &tls.Config{}),
		connStats: newConnStats(new(expvar.Map).Init()),
	}
	for _, tc := range []struct {
		name string
		set  func(time.Time) error
		t    time.Time
		want bool
	}{
		{"read, long ago", conn.SetReadDeadline, time.Unix(1, 0), true},
		{"read, future", conn.SetReadDeadline, time.Now().Add(time.Hour), false},
		{"read, zero", conn.SetReadDeadline, time.Time{}, false},
		{"both, long ago", conn.SetDeadline, time.Unix(1, 0), true},
		{"both, zero", conn.SetDeadline, time.Time{}, false},
	} {
		if err := tc.set(tc.t); err != nil {
			t.Fatalf("%s: %s", tc.name, err)
		}
		if got := conn.readDeadlinePassed.Load(); got != tc.want {
			t.Errorf("%s: readDeadlinePassed = %v, want %v", tc.name, got, tc.want)
		}
	}
}
