package main

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/jmhodges/howsmyssl/tls"
)

func TestBEASTVuln(t *testing.T) {
	clientConf := &tls.Config{
		MaxVersion:         tls.VersionTLS10,
		InsecureSkipVerify: true,
		CipherSuites:       []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}

	c := connect(t, clientConf)
	if !c.HasBeastVulnSuites {
		t.Errorf("HasBeastVulnSuites was false")
	}
	if !c.NMinusOneRecordSplittingDetected {
		t.Errorf("NMinusOneRecordSplittingDetected was false")
	}

}

func connect(t *testing.T, clientConf *tls.Config) *tls.Conn {
	conf := makeTLSConfig("./config/development.crt", "./config/development.key")
	li, err := tls.Listen("tcp", "localhost:0", conf)
	if err != nil {
		t.Fatalf("NewListener: %s", err)
	}
	type connRes struct {
		recv []byte
		conn *tls.Conn
	}
	ch := make(chan connRes)
	errCh := make(chan error)

	go func() {
		c, err := li.Accept()
		if err != nil {
			errCh <- err
			return
		}
		b := make([]byte, 1)
		io.ReadFull(c, b)
		c.Close()
		li.Close()
		tc := c.(*tls.Conn)
		ch <- connRes{recv: b, conn: tc}
	}()
	c, err := tls.Dial("tcp", li.Addr().String(), clientConf)
	if err != nil {
		t.Fatalf("Dial: %s", err)
	}
	defer c.Close()
	sent := []byte("a")
	c.Write(sent)
	var cr connRes
	select {
	case err := <-errCh:
		t.Fatalf("Accept: %s", err)
	case cr = <-ch:
		if !bytes.Equal(cr.recv, sent) {
			t.Fatalf("expected bytes %#v, got %#v", string(sent), string(cr.recv))
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out")
	}
	return cr.conn
}
