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
	readProbs  *expvar.Int
	readEOFs   *expvar.Int
	writeProbs *expvar.Int
	writeEOFs  *expvar.Int
}

func newListener(nl net.Listener, ns *expvar.Map) *listener {
	lis := &listener{
		Listener:   nl,
		readProbs:  &expvar.Int{},
		readEOFs:   &expvar.Int{},
		writeProbs: &expvar.Int{},
		writeEOFs:  &expvar.Int{},
	}
	ns.Set("read_handshake_problems", lis.readProbs)
	ns.Set("read_handshake_problems_eof", lis.readEOFs)
	ns.Set("write_handshake_problems", lis.writeProbs)
	ns.Set("write_handshake_problems_eof", lis.writeEOFs)
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
		readProbs:      l.readProbs,
		readEOFs:       l.readEOFs,
		writeProbs:     l.writeProbs,
		writeEOFs:      l.writeEOFs,
	}, nil
}

type conn struct {
	*tls.Conn
	handshakeMutex *sync.Mutex
	st             *tls.ServerHandshakeState

	readProbs  *expvar.Int
	readEOFs   *expvar.Int
	writeProbs *expvar.Int
	writeEOFs  *expvar.Int
}

func (c *conn) Read(b []byte) (int, error) {
	err := c.handshake()
	if err != nil {

		c.readProbs.Add(1)
		if err == io.EOF {
			c.readEOFs.Add(1)
		} else {
			log.Printf("unknown write handshake error: %s", err)
		}

		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *conn) Write(b []byte) (int, error) {
	err := c.handshake()
	if err != nil {
		c.writeProbs.Add(1)
		if err == io.EOF {
			c.writeEOFs.Add(1)
		} else if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
			// log nothing on timeouts FIXME
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
