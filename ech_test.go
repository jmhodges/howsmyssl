package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/crypto/cryptobyte"

	"github.com/jmhodges/howsmyssl/echkeys"
	tls "github.com/jmhodges/howsmyssl/tls1274"
)

// echServerConf returns the test server's config with a new ECH key, and the
// ECHConfigList a client needs to use it.
func echServerConf(t *testing.T) (*tls.Config, []byte, tls.EncryptedClientHelloKey) {
	t.Helper()
	keyFile, configList, err := echkeys.Generate("public.example.com")
	if err != nil {
		t.Fatalf("echkeys.Generate: %s", err)
	}
	keys, err := echkeys.Parse(keyFile)
	if err != nil {
		t.Fatalf("echkeys.Parse: %s", err)
	}
	conf := serverConf.Clone()
	conf.EncryptedClientHelloKeys = keys
	return conf, configList, keys[0]
}

// Suites the rewriter adds to the outer ClientHello. Each one alone makes a
// client "Bad".
var outerOnlySuites = []uint16{
	tls.TLS_RSA_WITH_RC4_128_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
}

func TestECHAcceptedRatesInnerHello(t *testing.T) {
	srvConf, configList, key := echServerConf(t)

	// A man in the middle that holds the server's ECH key adds weak cipher
	// suites to the outer ClientHello, and seals the client's inner
	// ClientHello again to match. Go's client sends the same cipher suites
	// inside and out, so this is how the test makes the two differ. The
	// outer hello is the AAD of the sealed inner one, so the server accepting
	// ECH shows it read the rewritten outer hello, weak suites and all.
	rw := &outerHelloRewriter{key: key, addSuites: outerOnlySuites}
	c := connectWithServer(t, srvConf, &tls.Config{
		EncryptedClientHelloConfigList: configList,
		MinVersion:                     tls.VersionTLS13,
	}, rw.wrap)
	if !rw.resealed() {
		t.Fatalf("the client sent no ECH extension to rewrite")
	}

	st := c.ConnectionState()
	if !st.ECHAccepted {
		t.Fatalf("server did not accept ECH")
	}
	if st.ServerName != "localhost" {
		t.Errorf("ServerName: want the inner hello's %q, got %q", "localhost", st.ServerName)
	}
	ci := pullClientInfo(c, preCutover)
	if !ci.EncryptedClientHelloAccepted {
		t.Errorf("EncryptedClientHelloAccepted: want true, got false")
	}
	for _, s := range outerOnlySuites {
		name := allCipherSuites[s]
		if slices.Contains(ci.GivenCipherSuites, name) {
			t.Errorf("GivenCipherSuites has the outer hello's %s: %v", name, ci.GivenCipherSuites)
		}
	}
	if len(ci.InsecureCipherSuites) != 0 {
		t.Errorf("InsecureCipherSuites: want none from the inner hello, got %v", ci.InsecureCipherSuites)
	}
	if ci.Rating != okay {
		t.Errorf("Rating: want %q, got %q", okay, ci.Rating)
	}
	if ci.TLSVersion != "TLS 1.3" {
		t.Errorf("TLSVersion: want TLS 1.3, got %q", ci.TLSVersion)
	}
}

// TestECHRejectedSendsCurrentRetryConfigs checks a client whose ECH config is
// one the server has no key for, like one left over from before a rotation.
// The server must reject its ECH, see only its outer hello, and send back only
// its current config, which the client can then use to be accepted.
//
// A rejected client aborts, as RFC 9849 has it, after checking the
// certificate against the config's public name, so it never asks for an
// answer on that connection: the test reads the server's side of it instead.
func TestECHRejectedSendsCurrentRetryConfigs(t *testing.T) {
	oldFile, oldList, err := echkeys.Generate("public.example.com")
	if err != nil {
		t.Fatal(err)
	}
	keyFile, currentList, err := echkeys.AddKey(oldFile, "public.example.com")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := echkeys.Parse(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	srvConf := serverConf.Clone()
	srvConf.GetCertificate = nil
	srvConf.Certificates = []tls.Certificate{publicNameCert(t)}
	srvConf.EncryptedClientHelloKeys = keys

	_, foreignList, err := echkeys.Generate("public.example.com")
	if err != nil {
		t.Fatal(err)
	}

	// Unlike the accepted test, this can't rewrite the outer hello: on
	// rejection both sides hash the outer hello, so a rewritten one fails the
	// handshake. The outer and inner hellos differ in their server names.
	srv, srvErr, cliErr := handshakeBoth(t, srvConf, &tls.Config{
		EncryptedClientHelloConfigList: foreignList,
		MinVersion:                     tls.VersionTLS13,
	})

	var rej *tls.ECHRejectionError
	if !errors.As(cliErr, &rej) {
		t.Fatalf("client: want an ECHRejectionError, got %v", cliErr)
	}
	if !bytes.Equal(rej.RetryConfigList, currentList) {
		t.Errorf("RetryConfigList: want only the current key's config")
	}
	if bytes.Contains(rej.RetryConfigList, oldList[2:]) {
		t.Errorf("RetryConfigList holds the old key's config")
	}
	if srvErr != nil {
		t.Fatalf("server: %s", srvErr)
	}
	st := srv.ConnectionState()
	if st.ECHAccepted {
		t.Errorf("server accepted ECH from a config it has no key for")
	}
	if st.ServerName != "public.example.com" {
		t.Errorf("ServerName: want the outer hello's %q, got %q", "public.example.com", st.ServerName)
	}
	rejected := pullClientInfo(srv, preCutover)
	if rejected.EncryptedClientHelloAccepted {
		t.Errorf("EncryptedClientHelloAccepted: want false, got true")
	}
	if rejected.Rating != okay || rejected.TLSVersion != "TLS 1.3" {
		t.Errorf("rejected: want the outer hello's TLS 1.3 and %q, got %q and %q", okay, rejected.TLSVersion, rejected.Rating)
	}

	// The client tries again with the retry configs, as a browser does.
	c := connectWithServer(t, srvConf, &tls.Config{
		EncryptedClientHelloConfigList: rej.RetryConfigList,
		MinVersion:                     tls.VersionTLS13,
	}, nil)
	ci := pullClientInfo(c, preCutover)
	if !ci.EncryptedClientHelloAccepted {
		t.Errorf("retry with the retry configs: EncryptedClientHelloAccepted: want true, got false")
	}
	if ci.Rating != okay {
		t.Errorf("retry: Rating: want %q, got %q", okay, ci.Rating)
	}
}

// TestECHTwoKeysAcceptEither checks that during a rotation, with the new key
// and the old one in the file, clients holding either config are accepted.
func TestECHTwoKeysAcceptEither(t *testing.T) {
	oldFile, oldList, err := echkeys.Generate("public.example.com")
	if err != nil {
		t.Fatal(err)
	}
	keyFile, newList, err := echkeys.AddKey(oldFile, "public.example.com")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := echkeys.Parse(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	srvConf := serverConf.Clone()
	srvConf.EncryptedClientHelloKeys = keys
	for name, list := range map[string][]byte{"old": oldList, "new": newList} {
		t.Run(name, func(t *testing.T) {
			c := connectWithServer(t, srvConf, &tls.Config{
				EncryptedClientHelloConfigList: list,
				MinVersion:                     tls.VersionTLS13,
			}, nil)
			if !c.ConnectionState().ECHAccepted {
				t.Fatalf("server did not accept ECH with the %s config", name)
			}
			if ci := pullClientInfo(c, preCutover); !ci.EncryptedClientHelloAccepted {
				t.Errorf("EncryptedClientHelloAccepted: want true, got false")
			}
		})
	}
}

// publicNameCert returns a certificate for localhost and the ECH public name,
// signed by the development CA, as a rejected ECH client wants.
func publicNameCert(t *testing.T) tls.Certificate {
	t.Helper()
	caKeyPEM, err := os.ReadFile("./config/development_ca_key.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost", "public.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, rootCA, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshakeBoth runs one handshake that may fail, and returns the server's
// side of it with each side's error.
func handshakeBoth(t *testing.T, srvConf, clientConf *tls.Config) (*tls.Conn, error, error) {
	t.Helper()
	clientConf.ServerName = "localhost"
	clientConf.RootCAs = x509.NewCertPool()
	clientConf.RootCAs.AddCert(rootCA)

	li, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer li.Close()
	type res struct {
		c   *tls.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		raw, err := li.Accept()
		if err != nil {
			ch <- res{err: err}
			return
		}
		c := tls.Server(raw, srvConf)
		c.SetDeadline(time.Now().Add(5 * time.Second))
		ch <- res{c: c, err: c.Handshake()}
	}()
	raw, err := net.DialTimeout("tcp", li.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	cliErr := tls.Client(raw, clientConf).Handshake()
	r := <-ch
	if r.c == nil {
		t.Fatalf("Accept: %s", r.err)
	}
	t.Cleanup(func() { r.c.Close() })
	return r.c, r.err, cliErr
}

// TestECHKeysChangeNothingWithoutECH checks that giving the server ECH keys
// changes no answer for clients that don't use ECH, TLS 1.0 ones included.
func TestECHKeysChangeNothingWithoutECH(t *testing.T) {
	echConf, _, _ := echServerConf(t)
	clients := map[string]func() *tls.Config{
		"default": func() *tls.Config { return &tls.Config{} },
		"tls1.2":  func() *tls.Config { return &tls.Config{MaxVersion: tls.VersionTLS12} },
		"tls1.0": func() *tls.Config {
			return &tls.Config{
				MinVersion:   tls.VersionTLS10,
				MaxVersion:   tls.VersionTLS10,
				CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			}
		},
	}
	for name, newConf := range clients {
		t.Run(name, func(t *testing.T) {
			without := pullClientInfo(connect(t, newConf()), preCutover)
			with := pullClientInfo(connectWithServer(t, echConf, newConf(), nil), preCutover)
			if without.EncryptedClientHelloAccepted || with.EncryptedClientHelloAccepted {
				t.Errorf("EncryptedClientHelloAccepted: want false, got %t without keys and %t with", without.EncryptedClientHelloAccepted, with.EncryptedClientHelloAccepted)
			}
			// BEAST detection depends on how the client splits its
			// records, not on the server's keys.
			if diff := cmp.Diff(without, with); diff != "" {
				t.Errorf("answer changed when the server has ECH keys (-without +with):\n%s", diff)
			}
		})
	}
}

func TestECHAcceptedJSONKey(t *testing.T) {
	c := connect(t, &tls.Config{})
	b, err := json.Marshal(pullClientInfo(c, preCutover))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	v, ok := m["encrypted_client_hello_accepted"]
	if !ok {
		t.Fatalf("no encrypted_client_hello_accepted key in %s", b)
	}
	if v != false {
		t.Errorf("encrypted_client_hello_accepted: want false without ECH keys, got %#v", v)
	}
}

// outerHelloRewriter wraps a client's net.Conn and rewrites the first
// ClientHello it writes, which must carry an outer ECH extension: it appends
// addSuites to the outer hello's cipher suites, decrypts the inner ClientHello
// with key and seals it again against the new outer hello.
type outerHelloRewriter struct {
	key       tls.EncryptedClientHelloKey
	addSuites []uint16

	mu   sync.Mutex
	done bool
}

func (rw *outerHelloRewriter) resealed() bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return rw.done
}

func (rw *outerHelloRewriter) wrap(c net.Conn) net.Conn {
	return &rewritingConn{Conn: c, rw: rw}
}

type rewritingConn struct {
	net.Conn
	rw   *outerHelloRewriter
	done bool
}

func (c *rewritingConn) Write(b []byte) (int, error) {
	if c.done {
		return c.Conn.Write(b)
	}
	c.done = true
	rec, err := c.rw.rewriteRecord(b)
	if err != nil {
		return 0, fmt.Errorf("rewriting the ClientHello: %w", err)
	}
	if _, err := c.Conn.Write(rec); err != nil {
		return 0, err
	}
	return len(b), nil
}

const echExtensionType = 0xfe0d

func (rw *outerHelloRewriter) rewriteRecord(rec []byte) ([]byte, error) {
	// One handshake record holding one ClientHello, as Go's client writes it.
	if len(rec) < 9 || rec[0] != 22 || int(binary.BigEndian.Uint16(rec[3:5])) != len(rec)-5 {
		return nil, errors.New("first write is not one whole handshake record")
	}
	msg := rec[5:]
	if msg[0] != 1 || int(msg[1])<<16|int(msg[2])<<8|int(msg[3]) != len(msg)-4 {
		return nil, errors.New("record does not hold exactly one ClientHello")
	}
	body := cryptobyte.String(msg[4:])

	var vers uint16
	var random, sessionID, suites, compression, exts cryptobyte.String
	if !body.ReadUint16(&vers) || !body.ReadBytes((*[]byte)(&random), 32) ||
		!body.ReadUint8LengthPrefixed(&sessionID) ||
		!body.ReadUint16LengthPrefixed(&suites) ||
		!body.ReadUint8LengthPrefixed(&compression) ||
		!body.ReadUint16LengthPrefixed(&exts) || !body.Empty() {
		return nil, errors.New("malformed ClientHello")
	}
	type ext struct {
		typ  uint16
		data []byte
	}
	var extList []ext
	echIdx := -1
	for !exts.Empty() {
		var e ext
		var data cryptobyte.String
		if !exts.ReadUint16(&e.typ) || !exts.ReadUint16LengthPrefixed(&data) {
			return nil, errors.New("malformed extensions")
		}
		e.data = data
		if e.typ == echExtensionType {
			echIdx = len(extList)
		}
		extList = append(extList, e)
	}

	newSuites := append([]byte(nil), suites...)
	for _, s := range rw.addSuites {
		newSuites = binary.BigEndian.AppendUint16(newSuites, s)
	}

	// build marshals the ClientHello with the given ECH extension, and
	// returns where the ECH payload starts in it.
	build := func(echExt []byte, payloadLen int) ([]byte, int) {
		out := []byte{1, 0, 0, 0}
		out = binary.BigEndian.AppendUint16(out, vers)
		out = append(out, random...)
		out = append(out, byte(len(sessionID)))
		out = append(out, sessionID...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(newSuites)))
		out = append(out, newSuites...)
		out = append(out, byte(len(compression)))
		out = append(out, compression...)
		extsLenAt := len(out)
		out = append(out, 0, 0)
		payloadAt := -1
		for i, e := range extList {
			data := e.data
			if i == echIdx {
				data = echExt
			}
			out = binary.BigEndian.AppendUint16(out, e.typ)
			out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
			if i == echIdx {
				payloadAt = len(out) + len(data) - payloadLen
			}
			out = append(out, data...)
		}
		binary.BigEndian.PutUint16(out[extsLenAt:], uint16(len(out)-extsLenAt-2))
		n := len(out) - 4
		out[1], out[2], out[3] = byte(n>>16), byte(n>>8), byte(n)
		return out, payloadAt
	}

	if echIdx < 0 {
		return nil, errors.New("ClientHello has no ECH extension")
	}
	hello, err := rw.reseal(msg, extList[echIdx].data, build)
	if err != nil {
		return nil, err
	}
	rw.mu.Lock()
	rw.done = true
	rw.mu.Unlock()
	out := []byte{22, rec[1], rec[2], 0, 0}
	binary.BigEndian.PutUint16(out[3:], uint16(len(hello)))
	return append(out, hello...), nil
}

func (rw *outerHelloRewriter) reseal(oldHello, echExt []byte, build func([]byte, int) ([]byte, int)) ([]byte, error) {
	s := cryptobyte.String(echExt)
	var typ, configID uint8
	var kdfID, aeadID uint16
	var enc, payload cryptobyte.String
	if !s.ReadUint8(&typ) || typ != 0 || !s.ReadUint16(&kdfID) || !s.ReadUint16(&aeadID) ||
		!s.ReadUint8(&configID) || !s.ReadUint16LengthPrefixed(&enc) ||
		!s.ReadUint16LengthPrefixed(&payload) || !s.Empty() {
		return nil, errors.New("malformed outer ECH extension")
	}
	kem := hpke.DHKEM(ecdh.X25519())
	priv, err := kem.NewPrivateKey(rw.key.PrivateKey)
	if err != nil {
		return nil, err
	}
	kdf, err := hpke.NewKDF(kdfID)
	if err != nil {
		return nil, err
	}
	aead, err := hpke.NewAEAD(aeadID)
	if err != nil {
		return nil, err
	}
	info := append([]byte("tls ech\x00"), rw.key.Config...)

	// The AAD is the ClientHello body with the payload zeroed, found the
	// way the server finds it.
	oldAAD := slices.Clone(oldHello[4:])
	idx := bytes.Index(oldAAD, payload)
	if idx < 0 {
		return nil, errors.New("ECH payload not found")
	}
	clear(oldAAD[idx : idx+len(payload)])
	recipient, err := hpke.NewRecipient(enc, priv, kdf, aead, info)
	if err != nil {
		return nil, err
	}
	inner, err := recipient.Open(oldAAD, payload)
	if err != nil {
		return nil, fmt.Errorf("opening the inner ClientHello: %w", err)
	}

	pub, err := kem.NewPublicKey(priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	newEnc, sender, err := hpke.NewSender(pub, kdf, aead, info)
	if err != nil {
		return nil, err
	}
	var b cryptobyte.Builder
	b.AddUint8(0)
	b.AddUint16(kdfID)
	b.AddUint16(aeadID)
	b.AddUint8(configID)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(newEnc) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(make([]byte, len(payload))) })
	newExt, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	hello, payloadAt := build(newExt, len(payload))
	sealed, err := sender.Seal(hello[4:], inner)
	if err != nil {
		return nil, err
	}
	if len(sealed) != len(payload) {
		return nil, fmt.Errorf("sealed inner is %d bytes, want %d", len(sealed), len(payload))
	}
	copy(hello[payloadAt:], sealed)
	return hello, nil
}
