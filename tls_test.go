package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"expvar"
	"io"
	"io/ioutil"
	"log"
	"net"
	"reflect"
	"strconv"
	"testing"
	"time"

	tls "github.com/jmhodges/howsmyssl/tls110"
)

func TestBEASTVuln(t *testing.T) {
	t.Run("TLS10OnlyCBC", func(t *testing.T) {
		clientConf := &tls.Config{
			MaxVersion:   tls.VersionTLS10,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		}

		c := connect(t, clientConf)
		st := c.ConnectionState()
		if !st.AbleToDetectNMinusOneSplitting {
			t.Errorf("TLS 1.0, CBC suite, Conn: AbleToDetectNMinusOneSplitting was false")
		}
		if !st.NMinusOneRecordSplittingDetected {
			t.Errorf("TLS 1.0, CBC suite, Conn: NMinusOneRecordSplittingDetected was false")
		}
		ci := pullClientInfo(c)
		if ci.BEASTVuln {
			t.Errorf("TLS 1.0, CBC suite, ClientInfo: BEASTVuln should be false because Go mitigates the BEAST attack even on TLS 1.0")
		}
		if !ci.AbleToDetectNMinusOneSplitting {
			t.Errorf("TLS 1.0, CBC suite, ClientInfo: AbleToDetectNMinusOneSplitting was false")
		}
	})

	// AbleToDetectNMinusOneSplitting shouldn't be set unless there are BEAST vuln cipher suites included
	// and we're talking over TLS 1.0.
	t.Run("TLS10NoCBC", func(t *testing.T) {
		clientConf := &tls.Config{
			MaxVersion:   tls.VersionTLS10,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA},
		}
		c := connect(t, clientConf)
		st := c.ConnectionState()
		if st.AbleToDetectNMinusOneSplitting {
			t.Errorf("TLS 1.0, no CBC suites, Conn: AbleToDetectNMinusOneSplitting was true")
		}
		ci := pullClientInfo(c)
		if ci.BEASTVuln {
			t.Errorf("TLS 1.0, no CBC suites, ClientInfo: BEASTVuln should be false because Go mitigates the BEAST attack even on TLS 1.0")
		}
		if ci.AbleToDetectNMinusOneSplitting {
			t.Errorf("TLS 1.0, no CBC suites, ClientInfo: AbleToDetectNMinusOneSplitting was true but should be false because no CBC suites were included even though we used TLS 1.0")
		}
	})

	t.Run("TLS12NoCBC", func(t *testing.T) {
		clientConf := &tls.Config{
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305},
		}

		c := connect(t, clientConf)
		st := c.ConnectionState()
		if st.AbleToDetectNMinusOneSplitting {
			t.Errorf("TLS 1.2+, no CBC suites, Conn: AbleToDetectNMinusOneSplitting was true")
		}
		ci := pullClientInfo(c)
		if ci.BEASTVuln {
			t.Errorf("TLS 1.2+, no CBC suites, ClientInfo: BEASTVuln should be false because Go mitigates the BEAST attack even on TLS 1.0")
		}
		if ci.AbleToDetectNMinusOneSplitting {
			t.Errorf("TLS 1.2+, no CBC suites, ClientInfo: AbleToDetectNMinusOneSplitting was true but shouldn't be set since we're not on TLS 1.0 or older")
		}
	})
}

// This is not to make sure that howsmyssl thinks the Go tls library is good,
// but, instead, we assume the client is "Probably Okay" and look to see that we
// can handle that golden path.
func TestGoDefaultIsOkay(t *testing.T) {
	clientConf := &tls.Config{}
	c := connect(t, clientConf)
	ci := pullClientInfo(c)
	t.Logf("%#v", ci)

	if ci.Rating != okay {
		t.Errorf("Go client rating: want %s, got %s", okay, ci.Rating)
	}
	if len(ci.GivenCipherSuites) == 0 {
		t.Errorf("no cipher suites given")
	}
	if ci.TLSCompressionSupported {
		t.Errorf("TLSCompressionSupported was somehow true even though Go's TLS client doesn't support it")
	}
	if !ci.SessionTicketsSupported {
		t.Errorf("SessionTicketsSupported was false but we set that in connect explicitly")
	}
}

func TestSweet32(t *testing.T) {
	type sweetTest struct {
		rating   rating
		suites   []uint16
		expected map[string][]string
	}

	// Since the Sweet32 vulnerable ciphersuites are still used by many servers,
	// Sweet32 mitigation involves moving those ciphersuites to the end of the
	// ciphersuite list the client announces it can support. However, meta
	// ciphersuites like the GREASE or renegotiation ciphersuites and the TLS
	// 1.3 ciphersuites are also attached to the end. So, howsmyssl says a
	// client is vulnerable to Sweet32 if the Sweet32 vulnerable ciphersuites
	// are last or would be last except for some known meta ciphersuites like
	// GREASE, etc. In order to support testing this behavior, we had to
	// hardcode into tls110/handshake_client.go the meta ciphersuites we support
	// here to pass them to the server without dropping them like the client
	// usually would.  We don't use the tls110 client code anywhere but in these
	// tests, so this isn't so bad.
	greaseCS := uint16(0x0A0A)
	renegCS := uint16(0x00FF)
	tests := []sweetTest{
		{
			bad,
			[]uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			map[string][]string{
				"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": []string{sweet32Reason},
				"TLS_RSA_WITH_3DES_EDE_CBC_SHA":       []string{sweet32Reason},
			},
		},
		{
			bad,
			[]uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA},
			map[string][]string{
				"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA": []string{sweet32Reason},
			},
		},
		{
			okay,
			[]uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
			map[string][]string{},
		},
		{
			okay,
			[]uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, greaseCS},
			map[string][]string{},
		},
		{
			okay,
			[]uint16{tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, greaseCS, renegCS},
			map[string][]string{},
		},
	}
	for i, st := range tests {
		t.Run(strconv.Itoa(i),
			func(t *testing.T) {
				clientConf := &tls.Config{
					CipherSuites: st.suites,
				}
				c := connect(t, clientConf)
				ci := pullClientInfo(c)
				t.Logf("#%d, %#v", i, ci)

				if ci.Rating != st.rating {
					t.Errorf("#%d, Go client rating: want %s, got %s", i, st.rating, ci.Rating)
				}
				if len(ci.GivenCipherSuites) != len(st.suites) {
					suites := []string{}
					for _, cs := range st.suites {
						suites = append(suites, allCipherSuites[cs])
					}
					t.Errorf("#%d, num cipher suites given: want %d, got %d (%v, %v)", i, len(st.suites), len(ci.GivenCipherSuites), suites, ci.GivenCipherSuites)
				}
				if !reflect.DeepEqual(st.expected, ci.InsecureCipherSuites) {
					t.Errorf("#%d, insecure cipher suites found: want %s, got %s", i, st.expected, ci.InsecureCipherSuites)
				}
			},
		)
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
	var c *tls.Conn
	for i := 0; i < 10; i++ {
		d := &net.Dialer{
			Timeout: 500 * time.Millisecond,
		}
		c, err = tls.DialWithDialer(d, "tcp", li.Addr().String(), clientConf)
		if err == nil {
			break
		} else {
			t.Logf("unable to connect on attempt %d: %s", i, err)
			time.Sleep(100 * time.Millisecond)
		}
	}
	if err != nil {
		logErrFromServer(t, errCh)
		t.Fatalf("Dial: %s", err)
	}
	defer c.Close()
	sent := []byte("a")
	_, err = c.Write(sent)
	if err != nil {
		logErrFromServer(t, errCh)
		t.Fatalf("unable to send data to the conn: %s", err)
	}
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

func logErrFromServer(t *testing.T, errCh chan error) {
	defer func() {
		select {
		case err := <-errCh:
			if err != nil {
				t.Logf("error from server side: %s", err)
			}
		case <-time.After(100 * time.Millisecond):
			// do nothing
		}
	}()
}
