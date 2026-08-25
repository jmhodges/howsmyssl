// Plumbing shared by both Server implementations (server_stdh2.go and
// server_xnet.go).

package howhttp

import (
	"context"
	"errors"
	"log"
	"net"

	tls1266 "github.com/jmhodges/howsmyssl/tls1266"
)

type contextKey struct{ name string }

func (k *contextKey) String() string { return "howhttp context value " + k.name }

// smuggledConnKey is for smuggling our wrapping *Conn's underlying *tls.Conn
// out to handlers that need to investigate the client's TLS settings.
var smuggledConnKey = &contextKey{"smuggledConn"}

// SmuggledConn returns the underlying *tls1266.Conn that was attached to the
// request's context.
func SmuggledConn(ctx context.Context) (*tls1266.Conn, bool) {
	tc, ok := ctx.Value(smuggledConnKey).(*tls1266.Conn)
	return tc, ok
}

// addTLSConnToContext is suitable for use as http.Server.ConnContext. It pulls
// the underlying *tls1266.Conn out of a *Conn and stashes it on the context for
// handlers to retrieve via SmuggledConn.
//
// We do this smuggling instead of using http.Hijacker.Hijack to avoid needing
// to do a bunch of connection management and HTTP response formatting
// ourselves. We smuggle the whole *tls1266.Conn into the context instead of
// just its ConnectionState because the handshake may not yet be performed, and
// we don't want to lock here waiting for the handshake to finish.
func addTLSConnToContext(ctx context.Context, c net.Conn) context.Context {
	tc, ok := c.(*Conn)
	if !ok {
		log.Printf("howhttp.addTLSConnToContext: unable to convert net.Conn to *howhttp.Conn: %#v\n", c)
		return ctx
	}
	return context.WithValue(ctx, smuggledConnKey, tc.Conn)
}

// filterBenignClose drops net.ErrClosed since it just means a listener or
// conn we were going to close was already closed by another path (the most
// common cases: double-Close, Close after Shutdown, or Close after the
// server tore the listener down itself). Callers shouldn't have to
// special-case that to tell real failures from idempotent teardown.
func filterBenignClose(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
