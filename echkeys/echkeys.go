// Package echkeys makes and reads the file that holds howsmyssl's Encrypted
// Client Hello (ECH) server keys.
//
// The file is PEM, in the layout of draft-farrell-tls-pemesni that OpenSSL's
// ECH support also uses: a "PRIVATE KEY" block holding a PKCS #8 X25519
// private key, then an "ECHCONFIG" block holding the ECHConfigList (RFC 9849)
// that clients are given, usually in the "ech" parameter of an HTTPS DNS
// record. Every ECHConfig in the list must be for that one private key.
//
// To rotate keys, a file may hold more than one such pair. The server accepts
// ECH from clients holding any of them, but only the first pair is the current
// key: its ECHConfigs alone are sent as retry configs to clients whose ECH
// offer was rejected. The pairs after it are older keys, kept until clients
// have stopped using them.
package echkeys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	tls "github.com/jmhodges/howsmyssl/tls1274"
	"golang.org/x/crypto/cryptobyte"
)

const (
	// echVersion is the ECHConfig version of RFC 9849, which is also the
	// encrypted_client_hello extension's code point.
	echVersion = 0xfe0d

	kemX25519HKDFSHA256 = 0x0020
	kdfHKDFSHA256       = 0x0001
	aeadAES128GCM       = 0x0001
	aeadChaCha20Poly    = 0x0003

	privateKeyBlock = "PRIVATE KEY"
	echConfigBlock  = "ECHCONFIG"
)

// LoadFile reads an ECH key file and returns the keys to put in a
// tls.Config's EncryptedClientHelloKeys.
func LoadFile(path string) ([]tls.EncryptedClientHelloKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	keys, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("echkeys: %s: %w", path, err)
	}
	return keys, nil
}

// Parse reads the contents of an ECH key file. Each ECHConfig in it becomes
// one key. Only the first pair's keys are sent as retry configs.
func Parse(data []byte) ([]tls.EncryptedClientHelloKey, error) {
	pairs, err := parsePairs(data)
	if err != nil {
		return nil, err
	}
	var keys []tls.EncryptedClientHelloKey
	for i, p := range pairs {
		for _, c := range p.configs {
			keys = append(keys, tls.EncryptedClientHelloKey{
				Config:      c,
				PrivateKey:  p.priv.Bytes(),
				SendAsRetry: i == 0,
			})
		}
	}
	return keys, nil
}

// keyPair is one PRIVATE KEY block and the ECHCONFIG block after it.
type keyPair struct {
	priv    *ecdh.PrivateKey
	configs [][]byte
}

func parsePairs(data []byte) ([]keyPair, error) {
	var pairs []keyPair
	var privDER []byte // a PRIVATE KEY block still waiting for its ECHCONFIG
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case privateKeyBlock:
			if privDER != nil {
				return nil, fmt.Errorf("PRIVATE KEY block %d has no ECHCONFIG block after it", len(pairs))
			}
			privDER = block.Bytes
		case echConfigBlock:
			if privDER == nil {
				return nil, fmt.Errorf("ECHCONFIG block %d has no PRIVATE KEY block before it", len(pairs))
			}
			p, err := parsePair(privDER, block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("key %d: %w", len(pairs), err)
			}
			pairs = append(pairs, p)
			privDER = nil
		default:
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("data after the last PEM block")
	}
	if privDER != nil {
		return nil, fmt.Errorf("PRIVATE KEY block %d has no ECHCONFIG block after it", len(pairs))
	}
	if len(pairs) == 0 {
		return nil, errors.New("no PRIVATE KEY and ECHCONFIG blocks")
	}
	return pairs, nil
}

func parsePair(privDER, configList []byte) (keyPair, error) {
	k, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return keyPair{}, fmt.Errorf("parsing PRIVATE KEY: %w", err)
	}
	priv, ok := k.(*ecdh.PrivateKey)
	if !ok || priv.Curve() != ecdh.X25519() {
		return keyPair{}, errors.New("PRIVATE KEY is not an X25519 key")
	}
	pub := priv.PublicKey().Bytes()

	configs, err := splitConfigList(configList)
	if err != nil {
		return keyPair{}, err
	}
	for i, c := range configs {
		if err := checkConfig(c, pub); err != nil {
			return keyPair{}, fmt.Errorf("ECHConfig %d: %w", i, err)
		}
	}
	return keyPair{priv: priv, configs: configs}, nil
}

// AddKey makes a new key, as Generate does, and returns a key file with it as
// the current key, followed by every key of the existing file, which are then
// still accepted but no longer sent as retry configs. The new key's config ID
// differs from those of the existing keys.
func AddKey(existing []byte, publicName string) (keyFile, configList []byte, err error) {
	pairs, err := parsePairs(existing)
	if err != nil {
		return nil, nil, err
	}
	var used [256]bool
	n := 0
	for _, p := range pairs {
		for _, c := range p.configs {
			if !used[c[4]] {
				used[c[4]] = true
				n++
			}
		}
	}
	if n == len(used) {
		return nil, nil, errors.New("every config ID is in use")
	}
	keyFile, configList, err = generate(publicName, &used)
	if err != nil {
		return nil, nil, err
	}
	return append(keyFile, existing...), configList, nil
}

// Generate makes a new X25519 ECH key whose ECHConfig names publicName as the
// client-facing server. It returns the key file's contents and the
// ECHConfigList to publish for clients.
func Generate(publicName string) (keyFile, configList []byte, err error) {
	return generate(publicName, new([256]bool))
}

// generate is Generate, with a config ID that used doesn't mark.
func generate(publicName string, used *[256]bool) (keyFile, configList []byte, err error) {
	if err := checkPublicName([]byte(publicName)); err != nil {
		return nil, nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	var id [1]byte
	for {
		if _, err := rand.Read(id[:]); err != nil {
			return nil, nil, err
		}
		if !used[id[0]] {
			break
		}
	}

	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(echVersion)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(id[0])
			b.AddUint16(kemX25519HKDFSHA256)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(priv.PublicKey().Bytes())
			})
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(kdfHKDFSHA256)
				b.AddUint16(aeadAES128GCM)
				b.AddUint16(kdfHKDFSHA256)
				b.AddUint16(aeadChaCha20Poly)
			})
			b.AddUint8(0) // maximum_name_length: let clients pad as they see fit
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(publicName))
			})
			b.AddUint16(0) // no extensions
		})
	})
	configList, err = b.Bytes()
	if err != nil {
		return nil, nil, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyFile = append(pem.EncodeToMemory(&pem.Block{Type: privateKeyBlock, Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: echConfigBlock, Bytes: configList})...)
	return keyFile, configList, nil
}

// splitConfigList returns each ECHConfig of an ECHConfigList, with its
// version and length, as EncryptedClientHelloKey.Config wants it.
func splitConfigList(list []byte) ([][]byte, error) {
	s := cryptobyte.String(list)
	var body cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&body) || !s.Empty() {
		return nil, errors.New("malformed ECHConfigList")
	}
	var configs [][]byte
	for !body.Empty() {
		start := body
		var version uint16
		var contents cryptobyte.String
		if !body.ReadUint16(&version) || !body.ReadUint16LengthPrefixed(&contents) {
			return nil, errors.New("malformed ECHConfigList")
		}
		if version != echVersion {
			return nil, fmt.Errorf("ECHConfig version %#04x is not %#04x", version, echVersion)
		}
		configs = append(configs, start[:len(start)-len(body)])
	}
	if len(configs) == 0 {
		return nil, errors.New("empty ECHConfigList")
	}
	return configs, nil
}

// checkConfig makes sure an ECHConfig is one the server can use with the
// given X25519 public key.
func checkConfig(config, pub []byte) error {
	s := cryptobyte.String(config)
	var version, kem uint16
	var contents, pk, suites, publicName, exts cryptobyte.String
	var configID, maxNameLen uint8
	if !s.ReadUint16(&version) || !s.ReadUint16LengthPrefixed(&contents) ||
		!contents.ReadUint8(&configID) ||
		!contents.ReadUint16(&kem) ||
		!contents.ReadUint16LengthPrefixed(&pk) ||
		!contents.ReadUint16LengthPrefixed(&suites) ||
		!contents.ReadUint8(&maxNameLen) ||
		!contents.ReadUint8LengthPrefixed(&publicName) ||
		!contents.ReadUint16LengthPrefixed(&exts) ||
		!contents.Empty() {
		return errors.New("malformed")
	}
	if kem != kemX25519HKDFSHA256 {
		return fmt.Errorf("KEM %#04x is not DHKEM(X25519, HKDF-SHA256)", kem)
	}
	if !bytes.Equal(pk, pub) {
		return errors.New("public key does not match the PRIVATE KEY")
	}
	if len(suites) == 0 || len(suites)%4 != 0 {
		return errors.New("malformed cipher suites")
	}
	return checkPublicName(publicName)
}

// checkPublicName checks that name is a DNS name with at least two labels of
// letters, digits and hyphens, as clients (Go's among them) want before they
// use an ECHConfig, and that its last label isn't all digits, which RFC 9849
// has clients treat as an IPv4 address and ignore.
func checkPublicName(name []byte) error {
	if len(name) == 0 || len(name) > 253 {
		return errors.New("public name must be 1 to 253 bytes long")
	}
	labels := strings.Split(string(name), ".")
	if len(labels) < 2 {
		return fmt.Errorf("public name %q must have at least two labels", name)
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("public name %q is not a valid DNS name", name)
		}
		for _, r := range l {
			if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '-' {
				return fmt.Errorf("public name %q is not a valid DNS name", name)
			}
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return fmt.Errorf("public name %q must not end in a numeric label", name)
	}
	return nil
}
