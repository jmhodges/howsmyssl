package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"expvar"
	"io"
	"io/ioutil"
	"log"
	"testing"
	"time"

	tls "github.com/jmhodges/howsmyssl/tls18"
)

func TestBEASTVuln(t *testing.T) {
	clientConf := &tls.Config{
		MaxVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}

	c := connect(t, clientConf)
	if !c.HasBeastVulnSuites {
		t.Errorf("HasBeastVulnSuites was false")
	}
	if !c.NMinusOneRecordSplittingDetected {
		t.Errorf("NMinusOneRecordSplittingDetected was false")
	}
}

// This is not to make sure that howsmyssl thinks the Go tls library is good,
// but, instead, we assume the client is "Probably Okay" and look to see that we
// can handle that golden path.
func TestGoDefaultIsOkay(t *testing.T) {
	clientConf := &tls.Config{}
	c := connect(t, clientConf)
	ci := ClientInfo(c)
	t.Logf("%#v", ci)

	if ci.Rating != okay {
		t.Errorf("Go client rating: want %s, got %s", okay, ci.Rating)
	}
}

var serverConf *tls.Config
var rootCA *x509.Certificate

func init() {
	serverConf = makeTLSConfig("./config/development_cert.pem", "./config/development_key.pem")
	certBytes, err := ioutil.ReadFile("./config/development_ca_cert.pem")
	if err != nil {
		log.Fatal(err)
	}
	cblock, _ := pem.Decode(certBytes)

	certs, err := x509.ParseCertificates(cblock.Bytes)
	if err != nil {
		log.Fatalf("x509.ParseCertificates: %s", err)
	}
	rootCA = certs[0]
}

func connect(t *testing.T, clientConf *tls.Config) *conn {
	clientConf.ServerName = "localhost"

	// Required to flip on session ticket keys
	clientConf.ClientSessionCache = tls.NewLRUClientSessionCache(-1)

	// Required to avoid InsecureSkipVerify (which is probably unnecessary, but
	// nice to be Good™.)
	clientConf.RootCAs = x509.NewCertPool()
	clientConf.RootCAs.AddCert(rootCA)

	tl, err := tls.Listen("tcp", "localhost:0", serverConf)
	if err != nil {
		t.Fatalf("NewListener: %s", err)
	}
	li := newListener(tl, new(expvar.Map).Init())
	type connRes struct {
		recv []byte
		conn *conn
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
		tc := c.(*conn)
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
