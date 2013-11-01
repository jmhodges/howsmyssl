package main

import (
	"errors"
	"github.com/jmhodges/howsmyssl/tls"
	"net"
	"sync"
)

var (
	_                net.Listener = &listener{}
	_                net.Conn     = &conn{}
	tlsConnConvError              = errors.New("Unable to convert net.Conn to tls.Conn")
)

type listener struct {
	net.Listener
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
	return &conn{tlsConn, &sync.Mutex{}, nil}, nil
}

type conn struct {
	*tls.Conn
	handshakeMutex *sync.Mutex
	st             *tls.ServerHandshakeState
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
