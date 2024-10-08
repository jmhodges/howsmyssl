package main

import (
	"errors"
	"expvar"
	"io"
	"log"
	"net"
	"sync/atomic"

	tls "github.com/jmhodges/howsmyssl/tls110"
)

var (
	_              net.Listener = &listener{}
	_              net.Conn     = &conn{}
	errTLSConnConv              = errors.New("Unable to convert net.Conn to tls.Conn")
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
		return nil, errTLSConnConv
	}
	return &conn{
		Conn:             tlsConn,
		handshakeCounted: new(atomic.Bool),
		handshakeStats:   l.handshakeStats,
	}, nil
}

type conn struct {
	*tls.Conn
	handshakeCounted *atomic.Bool
	*handshakeStats
}

func (c *conn) Read(b []byte) (int, error) {
	err := c.handshake()
	if err != nil {
		c.errorToStats(err)
		return 0, err
	}
	size, err := c.Conn.Read(b)
	c.errorToStats(err)
	return size, err
}

func (c *conn) Write(b []byte) (int, error) {
	err := c.handshake()
	if err != nil {
		c.errorToStats(err)
		return 0, err
	}
	size, err := c.Conn.Write(b)
	c.errorToStats(err)
	return size, err
}

func (c *conn) handshake() error {
	alreadyCounted := !c.handshakeCounted.CompareAndSwap(false, true)
	if alreadyCounted {
		return nil
	}

	err := c.Conn.Handshake()
	if err != nil {
		c.errorToStats(err)
		return err
	}
	if !alreadyCounted {
		c.Successes.Add(1)
	}
	return nil
}

func (c *conn) errorToStats(err error) {
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
			log.Printf("unknown tls error: %s", err)
		}
	}
}
