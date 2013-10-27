package main

import (
	"errors"
	"fmt"
	"github.com/jmhodges/howsmyssl/tls"
	"net"
	"strings"
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

// TODO(jmhodges): as this data gets larger, having the json encoding here
// makes less sense.
type tlsData struct {
	CipherSuites            []string `json:"cipher_suites"`
	EphemeralKeysSupported  bool     `json:"ephemeral_keys_supported"` // good
	SessionTicketsSupported bool     `json:"session_ticket_supported"` // good
	TLSCompressionSupported bool     `json:"tls_compression_support"`  // bad
}

func (c *conn) TLSData() *tlsData {
	ephemeralKeys := false
	compressionSupported := false
	cs := make([]string, 0)

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	for _, ci := range c.st.ClientHello.CipherSuites {
		s, found := allCipherSuites[ci]
		if found {
			if strings.Contains(s, "DHE_") {
				ephemeralKeys = true
			}
		} else {
			s = fmt.Sprintf("Some unknown cipher suite: %#x", ci)
		}
		cs = append(cs, s)
	}
	ticketSupported := c.st.ClientHello.TicketSupported

	for _, cm := range c.st.ClientHello.CompressionMethods {
		if cm != 0x0 {
			compressionSupported = true
			break
		}
	}
	return &tlsData{
		CipherSuites:            cs,
		EphemeralKeysSupported:  ephemeralKeys,
		SessionTicketsSupported: ticketSupported,
		TLSCompressionSupported: compressionSupported,
	}
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
