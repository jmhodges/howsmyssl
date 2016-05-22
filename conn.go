package main

import (
	"errors"
	"expvar"
	"io"
	"log"
	"net"
	"sync"

	"github.com/jmhodges/howsmyssl/tls"
)

var (
	_                net.Listener = &listener{}
	_                net.Conn     = &conn{}
	tlsConnConvError              = errors.New("Unable to convert net.Conn to tls.Conn")
)

type listener struct {
	net.Listener
	*tlsStats
}

type tlsStats struct {
	handshakeReadErrs      *expvar.Int
	handshakeReadEOFs      *expvar.Int
	handshakeReadTimeouts  *expvar.Int
	handshakeWriteErrs     *expvar.Int
	handshakeWriteEOFs     *expvar.Int
	handshakeWriteTimeouts *expvar.Int
}

func newTLSStats(ns *expvar.Map) *tlsStats {
	s := &tlsStats{
		handshakeReadErrs:      &expvar.Int{},
		handshakeReadEOFs:      &expvar.Int{},
		handshakeReadTimeouts:  &expvar.Int{},
		handshakeWriteErrs:     &expvar.Int{},
		handshakeWriteEOFs:     &expvar.Int{},
		handshakeWriteTimeouts: &expvar.Int{},
	}
	ns.Set("read_handshake_errors", s.handshakeReadErrs)
	ns.Set("read_handshake_errors_timeout", s.handshakeReadTimeouts)
	ns.Set("read_handshake_errors_eof", s.handshakeReadEOFs)
	ns.Set("write_handshake_errors", s.handshakeWriteErrs)
	ns.Set("write_handshake_errors_timeout", s.handshakeWriteTimeouts)
	ns.Set("write_handshake_errors_eof", s.handshakeWriteEOFs)
	return s
}
func newListener(nl net.Listener, ns *expvar.Map) *listener {
	lis := &listener{
		Listener: nl,
		tlsStats: newTLSStats(ns),
	}
	return lis
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return c, err

	}
	tlsConn, ok := c.(*tls.Conn)
	if !ok {
		c.Close()
		return nil, tlsConnConvError
	}
	return &conn{
		Conn:           tlsConn,
		handshakeMutex: &sync.Mutex{},
		st:             nil,
		tlsStats:       l.tlsStats,
	}, nil
}

type conn struct {
	*tls.Conn
	handshakeMutex *sync.Mutex
	st             *tls.ServerHandshakeState

	*tlsStats
}

func (c *conn) Read(b []byte) (int, error) {
	err := c.handshake()
	if err != nil {

		c.handshakeReadErrs.Add(1)
		if err == io.EOF {
			c.handshakeReadEOFs.Add(1)
		} else if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
			c.handshakeReadTimeouts.Add(1)
		} else {
			log.Printf("unknown read handshake error: %s", err)
		}

		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	err := c.handshake()
	if err != nil {
		c.handshakeWriteErrs.Add(1)
		if err == io.EOF {
			c.handshakeWriteEOFs.Add(1)
		} else if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
			c.handshakeWriteTimeouts.Add(1)
		} else {
			log.Printf("unknown write handshake error: %s", err)
		}

		return 0, err
	}
	return c.Conn.Write(b)
}

// This, unfortunately, means we take two uncontended locks on every read and
// write: the c.handshakeMutex here and the one in tls.Conn.
func (c *conn) handshake() error {
	st, err := c.Conn.ServerHandshake()
	if err == tls.HandshakeAlreadyPerformedError {
		return nil
	}
	if err != nil {
		return err
	}
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	c.st = st
	return nil
}
