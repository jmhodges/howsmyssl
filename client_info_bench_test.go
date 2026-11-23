package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"net"
	"testing"
	"time"

	tls "github.com/jmhodges/howsmyssl/tls1274"
)

// serverSideConn runs one handshake between a client, which is handed the
// connection to do it on, and a server with the given TLS config. It returns
// the server's end, closed, with both sides' handshake errors. Unlike
// connect, it doesn't mind a client that gives up.
func serverSideConn(t testing.TB, conf *tls.Config, client func(net.Conn) error) (s *tls.Conn, serverErr, clientErr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Listen: %s", err)
	}
	defer ln.Close()
	type res struct {
		s   *tls.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- res{s: tls.Server(nil, conf), err: err}
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		s := tls.Server(c, conf)
		err = s.Handshake()
		ch <- res{s: s, err: err}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %s", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	clientErr = client(c)
	// A client that gave up early has left the server waiting for it.
	c.Close()
	r := <-ch
	return r.s, r.err, clientErr
}

// BenchmarkClientInfo measures what the handlers do with a handshake on each
// request: copy the connection's state out of the TLS library, make the
// report from it, and render it for the API or the page. The client is Go's,
// offering HTTP/2 as a browser does.
func BenchmarkClientInfo(b *testing.B) {
	index = loadIndex()
	clientConf := &tls.Config{
		ServerName: "localhost",
		RootCAs:    x509.NewCertPool(),
		NextProtos: []string{"h2", "http/1.1"},
	}
	clientConf.RootCAs.AddCert(rootCA)
	conn, serverErr, clientErr := serverSideConn(b, serverConf, func(c net.Conn) error {
		return tls.Client(c, clientConf).Handshake()
	})
	if serverErr != nil || clientErr != nil {
		b.Fatalf("handshake: server: %v, client: %v", serverErr, clientErr)
	}
	now := time.Now()
	b.Run("state", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			conn.ConnectionState()
		}
	})
	st := conn.ConnectionState()
	b.Run("report", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			clientInfoFromState(st, now)
		}
	})
	ci := clientInfoFromState(st, now)
	b.Run("json", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			out, err := json.Marshal(ci)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(out)))
		}
	})
	b.Run("page", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var buf bytes.Buffer
			if err := index.Execute(&buf, ci); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(buf.Len()))
		}
	})
}
