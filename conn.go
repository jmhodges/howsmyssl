package main

import (
	"errors"
	"expvar"
	"io"
	"log"
	"net"
	"sync"

	tls "github.com/jmhodges/howsmyssl/tls18"
)

var (
	_                net.Listener = &listener{}
	_                net.Conn     = &conn{}
	tlsConnConvError              = errors.New("Unable to convert net.Conn to tls.Conn")
)

type listener struct {
	net.Listener
	*handshakeStats
}

type handshakeStats struct {
	Successes       *expvar.Int
	Errs            *expvar.Int
	ReadTimeouts    *expvar.Int
	WriteTimeouts   *expvar.Int
	UnknownTimeouts *expvar.Int
	EOFs            *expvar.Int
}

func newHandshakeStats(ns *expvar.Map) *handshakeStats {
	s := &handshakeStats{
		Successes:       &expvar.Int{},
		Errs:            &expvar.Int{},
		ReadTimeouts:    &expvar.Int{},
		WriteTimeouts:   &expvar.Int{},
		UnknownTimeouts: &expvar.Int{},
		EOFs:            &expvar.Int{},
	}
	ns.Set("successes", s.Successes)
	ns.Set("errors", s.Errs)
	ns.Set("read_timeouts", s.ReadTimeouts)
	ns.Set("write_timeouts", s.WriteTimeouts)
	ns.Set("unknown_timeouts", s.UnknownTimeouts)
	ns.Set("eofs", s.EOFs)
	return s
}
func newListener(nl net.Listener, ns *expvar.Map) *listener {
	statNS := new(expvar.Map).Init()
	ns.Set("handshake", statNS)
	lis := &listener{
		Listener:       nl,
		handshakeStats: newHandshakeStats(statNS),
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
		handshakeStats: l.handshakeStats,
	}, nil
}

type conn struct {
	*tls.Conn
	handshakeMutex *sync.Mutex
	st             *tls.ServerHandshakeState

	*handshakeStats
}

func (c *conn) Read(b []byte) (int, error) {
	err := c.handshake()
	if err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	err := c.handshake()
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

// This, unfortunately, means we take two uncontended locks on every read and
// write: the c.handshakeMutex here and the one in tls.Conn.
func (c *conn) handshake() error {
	st, err := c.Conn.ServerHandshake()
	if err == tls.HandshakeAlreadyPerformedError {
		c.Successes.Add(1)
		return nil
	}
	if err != nil {
		c.Errs.Add(1)
		if err == io.EOF {
			c.EOFs.Add(1)
		} else if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
			switch opErr.Op {
			case "read":
				c.ReadTimeouts.Add(1)
			case "write":
				c.WriteTimeouts.Add(1)
			default:
				log.Printf("unknown timeout type: %s", opErr.Op)
				c.UnknownTimeouts.Add(1)
			}
		} else {
			log.Printf("unknown handshake error: %s", err)
		}
		return err
	}
	c.Successes.Add(1)
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	c.st = st
	return nil
}
