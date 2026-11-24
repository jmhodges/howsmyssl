package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	tls "github.com/jmhodges/howsmyssl/tls1274"
	ztls "github.com/zmap/zcrypto/tls"
)

// A client is reported and rated by the TLS version of its handshake. A TLS
// 1.3 draft version in its supported_versions extension is no TLS 1.3: no
// server finishes a draft handshake now, so a client that lists one and gets
// TLS 1.2 is a TLS 1.2 client.

const (
	draftVersionTLS13Draft28   = 0x7f1c
	draftVersionX25519MLKEM768 = 0x11ec
)

// draftVersionInstants are the times the tests below rate a client at: before
// any of the dated rating changes, between the two of them, and from the
// moment TLS 1.2 becomes Bad.
var draftVersionInstants = []struct {
	name string
	now  time.Time
}{
	{"BeforeCutovers", preCutover},
	{"AfterImprovableCutover", tls12ImprovableCutover},
	{"AfterBadCutover", tls12BadCutover},
}

func TestDraftVersionAtTLS12IsRatedAsTLS12(t *testing.T) {
	tests := []struct {
		name     string
		versions []uint16 // no supported_versions extension if empty
	}{
		// What the others must match: a TLS 1.2 client that lists no
		// draft.
		{"NoExtension", nil},
		{"TLS12Only", []uint16{tls.VersionTLS12}},
		{"Draft28First", []uint16{draftVersionTLS13Draft28, tls.VersionTLS12}},
		{"Draft28Last", []uint16{tls.VersionTLS12, draftVersionTLS13Draft28}},
		{"OldestAndNewestDraft", []uint16{versionTLS13Draft33, versionTLS13Draft18, tls.VersionTLS12, tls.VersionTLS11}},
	}
	// The client lists a post-quantum group, so after the cutovers its TLS
	// version is the only thing that can make it Bad.
	wantRatings := []rating{okay, improvable, bad}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := connectZtls(t, &ztls.Config{
				ExternalClientHello: draftVersionTLS12Hello(t, tc.versions),
				// connectZtls gives every client a session cache, and
				// zcrypto/tls then reads the first supported version of
				// a hello that may have none.
				SessionTicketsDisabled: true,
			})
			if got := c.ConnectionState().Version; got != tls.VersionTLS12 {
				t.Fatalf("negotiated version: want %#04x, got %#04x", tls.VersionTLS12, got)
			}
			for i, inst := range draftVersionInstants {
				ci := pullClientInfo(c, inst.now)
				if ci.TLSVersion != "TLS 1.2" {
					t.Errorf("%s, TLSVersion: want TLS 1.2, got %s", inst.name, ci.TLSVersion)
				}
				if !ci.PostQuantumKeyAgreement {
					t.Errorf("%s, PostQuantumKeyAgreement: want true, got false", inst.name)
				}
				if ci.Rating != wantRatings[i] {
					t.Errorf("%s, Rating: want %s, got %s", inst.name, wantRatings[i], ci.Rating)
				}
			}
		})
	}
}

// Go's own client finishes a TLS 1.3 handshake and offers a post-quantum key
// share, so none of the dated rating changes touch it.
func TestDraftVersionRealTLS13KeepsItsRating(t *testing.T) {
	c := connect(t, &tls.Config{MinVersion: tls.VersionTLS13})
	if got := c.ConnectionState().Version; got != tls.VersionTLS13 {
		t.Fatalf("negotiated version: want %#04x, got %#04x", tls.VersionTLS13, got)
	}
	for _, inst := range draftVersionInstants {
		ci := pullClientInfo(c, inst.now)
		if ci.TLSVersion != "TLS 1.3" {
			t.Errorf("%s, TLSVersion: want TLS 1.3, got %s", inst.name, ci.TLSVersion)
		}
		if ci.Rating != okay {
			t.Errorf("%s, Rating: want %s, got %s", inst.name, okay, ci.Rating)
		}
	}
}

// A draft version listed beside the real TLS 1.3 gets a TLS 1.3 handshake, and
// the same report as a client that lists TLS 1.3 alone.
func TestDraftVersionBesideTLS13ChangesNothing(t *testing.T) {
	plain := connectDraftVersionTLS13(t, []uint16{tls.VersionTLS13, tls.VersionTLS12})
	tests := []struct {
		name     string
		versions []uint16
	}{
		{"DraftFirst", []uint16{draftVersionTLS13Draft28, tls.VersionTLS13, tls.VersionTLS12}},
		{"DraftLast", []uint16{tls.VersionTLS13, tls.VersionTLS12, draftVersionTLS13Draft28}},
	}
	// This client offers x25519 alone, so it turns Improvable and then Bad
	// for having no post-quantum key agreement, with or without a draft.
	wantRatings := []rating{okay, improvable, bad}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := connectDraftVersionTLS13(t, tc.versions)
			for i, inst := range draftVersionInstants {
				want := pullClientInfo(plain, inst.now)
				got := pullClientInfo(c, inst.now)
				if got.TLSVersion != "TLS 1.3" {
					t.Errorf("%s, TLSVersion: want TLS 1.3, got %s", inst.name, got.TLSVersion)
				}
				if got.Rating != wantRatings[i] {
					t.Errorf("%s, Rating: want %s, got %s", inst.name, wantRatings[i], got.Rating)
				}
				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("%s, report with a draft version listed differs from the one without (-without +with):\n%s", inst.name, diff)
				}
			}
		})
	}
}

func draftVersionU16s(vals ...uint16) []byte {
	var b []byte
	for _, v := range vals {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	return b
}

func draftVersionU8Len(data []byte) []byte {
	return append([]byte{uint8(len(data))}, data...)
}

func draftVersionU16Len(data []byte) []byte {
	return append(draftVersionU16s(uint16(len(data))), data...)
}

func draftVersionExt(typ uint16, data []byte) []byte {
	return append(draftVersionU16s(typ), draftVersionU16Len(data)...)
}

// draftVersionHello returns a ClientHello as a handshake message. Neither TLS
// client in these tests has a setting for its supported_versions list, so the
// hello is written by hand.
func draftVersionHello(t *testing.T, suite uint16, exts []byte) []byte {
	t.Helper()
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("rand.Read: %s", err)
	}
	var body []byte
	body = append(body, draftVersionU16s(tls.VersionTLS12)...) // legacy_version
	body = append(body, random...)
	body = append(body, 0) // no session id
	body = append(body, draftVersionU16Len(draftVersionU16s(suite))...)
	body = append(body, draftVersionU8Len([]byte{0})...) // compression: none
	body = append(body, draftVersionU16Len(exts)...)

	// A handshake message: type 1, client_hello, and a 3 byte length.
	msg := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...)
}

// draftVersionTLS12Hello is a ClientHello that the zcrypto/tls client can
// finish an ECDHE handshake from, as its Config.ExternalClientHello. It lists
// a post-quantum group that TLS 1.2 can't use, and x25519.
func draftVersionTLS12Hello(t *testing.T, versions []uint16) []byte {
	t.Helper()
	var exts []byte
	exts = append(exts, draftVersionExt(10, draftVersionU16Len(draftVersionU16s(draftVersionX25519MLKEM768, uint16(ztls.X25519))))...) // supported_groups
	exts = append(exts, draftVersionExt(11, draftVersionU8Len([]byte{0}))...)                                                          // ec_point_formats: uncompressed
	exts = append(exts, draftVersionExt(13, draftVersionU16Len(draftVersionU16s(0x0804, 0x0401)))...)                                  // signature_algorithms: rsa_pss_rsae_sha256, rsa_pkcs1_sha256
	if len(versions) != 0 {
		exts = append(exts, draftVersionExt(43, draftVersionU8Len(draftVersionU16s(versions...)))...) // supported_versions
	}
	return draftVersionHello(t, ztls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, exts)
}

// connectDraftVersionTLS13 finishes a TLS 1.3 handshake with serverConf as a
// client that sends the given supported_versions list, and returns the
// server's side of it. It is the least of a TLS 1.3 client that the server
// will finish with: x25519, TLS_AES_128_GCM_SHA256, and no look at the
// server's certificate.
func connectDraftVersionTLS13(t *testing.T, versions []uint16) *tls.Conn {
	t.Helper()
	li, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.Listen: %s", err)
	}
	defer li.Close()

	type result struct {
		conn *tls.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		nc, err := li.Accept()
		if err != nil {
			ch <- result{err: err}
			return
		}
		nc.SetDeadline(time.Now().Add(5 * time.Second))
		c := tls.Server(nc, serverConf)
		ch <- result{conn: c, err: c.Handshake()}
	}()

	client, err := net.DialTimeout("tcp", li.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("net.Dial: %s", err)
	}
	// The client's side stays open until the test is done, so the server
	// can write its session tickets.
	t.Cleanup(func() { client.Close() })
	client.SetDeadline(time.Now().Add(5 * time.Second))

	clientErr := draftVersionTLS13Handshake(t, client, versions)
	res := <-ch
	if res.conn != nil {
		t.Cleanup(func() { res.conn.Close() })
	}
	if clientErr != nil {
		t.Fatalf("client's TLS 1.3 handshake: %s (server's: %v)", clientErr, res.err)
	}
	if res.err != nil {
		t.Fatalf("server's TLS 1.3 handshake: %s", res.err)
	}
	if got := res.conn.ConnectionState().Version; got != tls.VersionTLS13 {
		t.Fatalf("negotiated version: want %#04x, got %#04x", tls.VersionTLS13, got)
	}
	return res.conn
}

// draftVersionTLS13Handshake is the client's side of RFC 8446's handshake up
// to its own Finished message.
func draftVersionTLS13Handshake(t *testing.T, conn net.Conn, versions []uint16) error {
	t.Helper()
	const (
		recordChangeCipherSpec = 20
		recordHandshake        = 22
		recordApplicationData  = 23
		handshakeServerHello   = 2
		handshakeFinished      = 20
		extensionKeyShare      = 51
	)
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	keyShare := append(draftVersionU16s(uint16(tls.X25519)), draftVersionU16Len(priv.PublicKey().Bytes())...)

	var exts []byte
	exts = append(exts, draftVersionExt(10, draftVersionU16Len(draftVersionU16s(uint16(tls.X25519))))...) // supported_groups
	exts = append(exts, draftVersionExt(13, draftVersionU16Len(draftVersionU16s(0x0804, 0x0403)))...)     // signature_algorithms: rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256
	exts = append(exts, draftVersionExt(43, draftVersionU8Len(draftVersionU16s(versions...)))...)         // supported_versions
	exts = append(exts, draftVersionExt(extensionKeyShare, draftVersionU16Len(keyShare))...)
	hello := draftVersionHello(t, tls.TLS_AES_128_GCM_SHA256, exts)

	record := func(typ byte, data []byte) []byte {
		return append([]byte{typ, 3, 3, byte(len(data) >> 8), byte(len(data))}, data...)
	}
	if _, err := conn.Write(record(recordHandshake, hello)); err != nil {
		return err
	}
	readRecord := func() (hdr, data []byte, err error) {
		hdr = make([]byte, 5)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return nil, nil, err
		}
		data = make([]byte, binary.BigEndian.Uint16(hdr[3:]))
		_, err = io.ReadFull(conn, data)
		return hdr, data, err
	}

	// The ServerHello, which Go's server sends as one record of its own.
	hdr, serverHello, err := readRecord()
	if err != nil {
		return err
	}
	if hdr[0] != recordHandshake || len(serverHello) < 4 || serverHello[0] != handshakeServerHello {
		return fmt.Errorf("want a ServerHello, got record type %d: %x", hdr[0], serverHello)
	}
	// Past the message header, legacy_version and random, then the echoed
	// session id, the cipher suite and the compression method.
	rest := serverHello[4+2+32:]
	rest = rest[1+int(rest[0]):]
	rest = rest[2+1+2:]
	var serverShare []byte
	for len(rest) >= 4 {
		typ, n := binary.BigEndian.Uint16(rest), int(binary.BigEndian.Uint16(rest[2:]))
		if typ == extensionKeyShare {
			// A group, a length, and the key.
			serverShare = rest[4+4 : 4+n]
		}
		rest = rest[4+n:]
	}
	if serverShare == nil {
		return errors.New("no key_share in the ServerHello")
	}
	pub, err := ecdh.X25519().NewPublicKey(serverShare)
	if err != nil {
		return err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return err
	}

	// RFC 8446, section 7.1.
	expandLabel := func(secret []byte, label string, context []byte, n int) []byte {
		info := draftVersionU16s(uint16(n))
		info = append(info, draftVersionU8Len([]byte("tls13 "+label))...)
		info = append(info, draftVersionU8Len(context)...)
		out, err := hkdf.Expand(sha256.New, secret, string(info), n)
		if err != nil {
			t.Fatalf("hkdf.Expand: %s", err)
		}
		return out
	}
	extract := func(secret, salt []byte) []byte {
		out, err := hkdf.Extract(sha256.New, secret, salt)
		if err != nil {
			t.Fatalf("hkdf.Extract: %s", err)
		}
		return out
	}
	zeros := make([]byte, sha256.Size)
	emptyHash := sha256.Sum256(nil)
	transcript := sha256.New()
	transcript.Write(hello)
	transcript.Write(serverHello)
	early := extract(zeros, nil)
	handshakeSecret := extract(shared, expandLabel(early, "derived", emptyHash[:], sha256.Size))
	clientSecret := expandLabel(handshakeSecret, "c hs traffic", transcript.Sum(nil), sha256.Size)
	serverSecret := expandLabel(handshakeSecret, "s hs traffic", transcript.Sum(nil), sha256.Size)

	aead := func(secret []byte) (cipher.AEAD, []byte) {
		block, err := aes.NewCipher(expandLabel(secret, "key", nil, 16))
		if err != nil {
			t.Fatalf("aes.NewCipher: %s", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("cipher.NewGCM: %s", err)
		}
		return gcm, expandLabel(secret, "iv", nil, 12)
	}
	nonce := func(iv []byte, seq uint64) []byte {
		n := make([]byte, 12)
		binary.BigEndian.PutUint64(n[4:], seq)
		for i := range n {
			n[i] ^= iv[i]
		}
		return n
	}

	// The rest of the server's flight, up to and with its Finished message.
	serverAEAD, serverIV := aead(serverSecret)
	var flight []byte
	finishedSeen := false
	for seq := uint64(0); !finishedSeen; {
		hdr, data, err := readRecord()
		if err != nil {
			return err
		}
		if hdr[0] == recordChangeCipherSpec {
			continue
		}
		if hdr[0] != recordApplicationData {
			return fmt.Errorf("want an encrypted record, got record type %d: %x", hdr[0], data)
		}
		plain, err := serverAEAD.Open(nil, nonce(serverIV, seq), data, hdr)
		if err != nil {
			return fmt.Errorf("decrypting record %d of the server's flight: %w", seq, err)
		}
		seq++
		// The record's real type is its last byte that isn't padding.
		for len(plain) > 0 && plain[len(plain)-1] == 0 {
			plain = plain[:len(plain)-1]
		}
		if len(plain) == 0 || plain[len(plain)-1] != recordHandshake {
			return fmt.Errorf("want a handshake record in the server's flight, got %x", plain)
		}
		flight = append(flight, plain[:len(plain)-1]...)
		for len(flight) >= 4 {
			n := 4 + int(flight[1])<<16 + int(flight[2])<<8 + int(flight[3])
			if len(flight) < n {
				break
			}
			transcript.Write(flight[:n])
			if flight[0] == handshakeFinished {
				finishedSeen = true
			}
			flight = flight[n:]
		}
	}

	mac := hmac.New(sha256.New, expandLabel(clientSecret, "finished", nil, sha256.Size))
	mac.Write(transcript.Sum(nil))
	verify := mac.Sum(nil)
	finished := append([]byte{handshakeFinished, 0, 0, byte(len(verify))}, verify...)
	finished = append(finished, recordHandshake)
	clientAEAD, clientIV := aead(clientSecret)
	hdr = []byte{recordApplicationData, 3, 3, 0, byte(len(finished) + clientAEAD.Overhead())}
	_, err = conn.Write(clientAEAD.Seal(hdr, nonce(clientIV, 0), finished, hdr))
	return err
}
