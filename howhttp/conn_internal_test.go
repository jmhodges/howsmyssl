package howhttp

import (
	"expvar"
	"net"
	"testing"

	tls "github.com/jmhodges/howsmyssl/tls1262"
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
