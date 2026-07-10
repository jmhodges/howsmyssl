package howhttp

import (
	"expvar"
	"net"
	"os"
	"syscall"
	"testing"

	tls "github.com/jmhodges/howsmyssl/tls1265"
)

// TestConn_HandshakeFailureCountedOnce locks in the contract that a single
// handshake failure produces exactly one error increment on the stats — no
// matter how many subsequent Read/Write calls hit the wrapper. Pre-fix,
// errorToStats was invoked once by handshake() and again by the Read/Write
// wrapper, inflating the counter for one logical event; the retry path also
// re-entered Conn.Conn.Read, which re-counted the cached handshake error.
func TestConn_HandshakeFailureCountedOnce(t *testing.T) {
	serverPipe, clientPipe := net.Pipe()
	// Close the peer immediately so the server-side Handshake errors out
	// reading the ClientHello.
	clientPipe.Close()

	stats := newHandshakeStats(new(expvar.Map).Init())
	conn := &Conn{
		Conn:           tls.Server(serverPipe, &tls.Config{}),
		handshakeStats: stats,
	}

	b := make([]byte, 1)
	for i := range 3 {
		if _, err := conn.Read(b); err == nil {
			t.Fatalf("Read #%d: expected error on conn with closed peer, got nil", i)
		}
	}

	if got := stats.Errs.Value(); got != 1 {
		t.Errorf("Errs = %d after 3 Reads on a failed-handshake conn, want 1", got)
	}
	if got := stats.Successes.Value(); got != 0 {
		t.Errorf("Successes = %d, want 0", got)
	}
}

// TestConn_CloseMarksDraining confirms our Close override sets the
// draining flag before delegating to the embedded tls.Conn.Close. The
// flag is what lets errorToStats recognize a concurrent in-flight
// Read/Write's resulting net.ErrClosed as the expected teardown signal
// instead of logging it as anomalous.
func TestConn_CloseMarksDraining(t *testing.T) {
	serverPipe, clientPipe := net.Pipe()
	defer clientPipe.Close()

	conn := &Conn{
		Conn:           tls.Server(serverPipe, &tls.Config{}),
		handshakeStats: newHandshakeStats(new(expvar.Map).Init()),
	}
	if conn.draining.Load() {
		t.Fatal("draining set before Close")
	}
	_ = conn.Close()
	if !conn.draining.Load() {
		t.Fatal("draining not set after Close")
	}
}

// TestConn_ErrorToStats_IntentionalClose covers the post-Close
// classification: a net.ErrClosed observed on a draining conn is the
// frame reader (or a Write loop) noticing the close we performed. It
// bumps IntentionalCloses, still counts in Errs as a total, and must
// not fall through to the "unknown tls error" log line.
func TestConn_ErrorToStats_IntentionalClose(t *testing.T) {
	stats := newHandshakeStats(new(expvar.Map).Init())
	conn := &Conn{handshakeStats: stats}
	conn.draining.Store(true)

	conn.errorToStats(net.ErrClosed)

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

// TestConn_ErrorToStats_NetErrClosedNotDraining confirms we don't
// quietly bucket a net.ErrClosed that arrived without our Close having
// run. Such an error means some path bypassed our wrapper Close, which
// is worth investigating, so it must still surface as "unknown tls
// error" rather than being absorbed by IntentionalCloses.
func TestConn_ErrorToStats_NetErrClosedNotDraining(t *testing.T) {
	stats := newHandshakeStats(new(expvar.Map).Init())
	conn := &Conn{handshakeStats: stats}

	conn.errorToStats(net.ErrClosed)

	if got := stats.IntentionalCloses.Value(); got != 0 {
		t.Errorf("IntentionalCloses = %d, want 0 (draining unset)", got)
	}
	if got := stats.Errs.Value(); got != 1 {
		t.Errorf("Errs = %d, want 1", got)
	}
}

// TestConn_ErrorToStats_TimeoutBeatsDraining locks in cascade ordering:
// a deadline that fires on the underlying net.Conn surfaces as a
// *net.OpError whose Timeout() is true, and that classification must
// win even if Close has already flipped the draining flag. Otherwise a
// concurrent Close racing a deadline would silently re-bucket real
// timeouts as IntentionalCloses and we'd lose visibility into them.
func TestConn_ErrorToStats_TimeoutBeatsDraining(t *testing.T) {
	stats := newHandshakeStats(new(expvar.Map).Init())
	conn := &Conn{handshakeStats: stats}
	conn.draining.Store(true)

	// Shape matches what tls.Conn.Read returns when the underlying
	// net.Conn's read deadline fires: *net.OpError wrapping a
	// deadline-exceeded error whose Timeout() returns true.
	conn.errorToStats(&net.OpError{Op: "read", Err: os.ErrDeadlineExceeded})

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

// TestConn_ErrorToStats_PeerReset covers ECONNRESET and EPIPE — the
// errors that show up when the peer (most often a TCP LB doing idle
// eviction, or a client hanging up mid-request) tears the conn down
// abruptly. They're benign on a public TLS endpoint; we count them so
// the rate is visible but don't log each one.
func TestConn_ErrorToStats_PeerReset(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"ECONNRESET", &net.OpError{Op: "read", Err: syscall.ECONNRESET}},
		{"EPIPE", &net.OpError{Op: "write", Err: syscall.EPIPE}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stats := newHandshakeStats(new(expvar.Map).Init())
			conn := &Conn{handshakeStats: stats}

			conn.errorToStats(tc.err)

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
