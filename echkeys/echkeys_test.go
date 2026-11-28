package echkeys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateThenLoad(t *testing.T) {
	keyFile, configList, err := Generate("public.example.com")
	if err != nil {
		t.Fatalf("Generate: %s", err)
	}
	path := filepath.Join(t.TempDir(), "ech.pem")
	if err := os.WriteFile(path, keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile: %s", err)
	}
	if len(keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(keys))
	}
	k := keys[0]
	// The list is the one config with a two-byte length in front.
	if !bytes.Equal(configList[2:], k.Config) {
		t.Errorf("Config is not the ECHConfigList's only entry")
	}
	if len(k.PrivateKey) != 32 {
		t.Errorf("PrivateKey: want 32 bytes of X25519 key, got %d", len(k.PrivateKey))
	}
	if !k.SendAsRetry {
		t.Errorf("SendAsRetry: want true")
	}
	if !bytes.Contains(k.Config, []byte("public.example.com")) {
		t.Errorf("Config does not name the public name")
	}

	keyFile2, _, err := Generate("public.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(keyFile, keyFile2) {
		t.Errorf("two calls to Generate made the same key")
	}
}

func TestGenerateRejectsBadPublicNames(t *testing.T) {
	for _, name := range []string{"", "localhost", "192.0.2.1", "a..example.com", "-a.example.com", "a_b.example.com", "example.123", strings.Repeat("a.", 127) + "com"} {
		if _, _, err := Generate(name); err == nil {
			t.Errorf("Generate(%q): want an error", name)
		}
	}
}

func TestParseErrors(t *testing.T) {
	good, _, err := Generate("public.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var keyBlock, configBlock []byte
	rest := good
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		switch b.Type {
		case privateKeyBlock:
			keyBlock = pem.EncodeToMemory(b)
		case echConfigBlock:
			configBlock = pem.EncodeToMemory(b)
		}
	}

	otherKey, _, err := Generate("public.example.com")
	if err != nil {
		t.Fatal(err)
	}
	otherKeyBlock, _ := pem.Decode(otherKey)

	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256DER, err := x509.MarshalPKCS8PrivateKey(p256)
	if err != nil {
		t.Fatal(err)
	}
	configDER, _ := pem.Decode(configBlock)
	wrongKEM := bytes.Clone(configDER.Bytes)
	wrongKEM[7], wrongKEM[8] = 0x00, 0x10 // DHKEM(P-256, HKDF-SHA256)

	cat := func(bs ...[]byte) []byte { return bytes.Join(bs, nil) }
	block := func(typ string, b []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}) }

	tests := map[string][]byte{
		"empty":             nil,
		"no key":            configBlock,
		"no config":         keyBlock,
		"two keys":          cat(keyBlock, keyBlock, configBlock),
		"two configs":       cat(keyBlock, configBlock, configBlock),
		"config first":      cat(configBlock, keyBlock),
		"second key alone":  cat(keyBlock, configBlock, keyBlock),
		"bad second key":    cat(keyBlock, configBlock, pem.EncodeToMemory(otherKeyBlock), configBlock),
		"other block":       cat(keyBlock, configBlock, block("CERTIFICATE", []byte{1})),
		"trailing junk":     cat(keyBlock, configBlock, []byte("junk")),
		"not PKCS8":         cat(block(privateKeyBlock, []byte{1, 2, 3}), configBlock),
		"P-256 key":         cat(block(privateKeyBlock, p256DER), configBlock),
		"mismatched key":    cat(pem.EncodeToMemory(otherKeyBlock), configBlock),
		"empty list":        cat(keyBlock, block(echConfigBlock, []byte{0, 0})),
		"short list":        cat(keyBlock, block(echConfigBlock, []byte{0, 5, 0xfe})),
		"wrong KEM":         cat(keyBlock, block(echConfigBlock, wrongKEM)),
		"wrong ECH version": cat(keyBlock, block(echConfigBlock, []byte{0, 4, 0xfe, 0x0a, 0, 0})),
	}
	for name, data := range tests {
		if _, err := Parse(data); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := Parse(good); err != nil {
		t.Errorf("the good file: %s", err)
	}
}

func TestAddKey(t *testing.T) {
	oldFile, oldList, err := Generate("public.example.com")
	if err != nil {
		t.Fatal(err)
	}
	newFile, newList, err := AddKey(oldFile, "public.example.com")
	if err != nil {
		t.Fatalf("AddKey: %s", err)
	}
	if !bytes.HasSuffix(newFile, oldFile) {
		t.Errorf("the new file does not end with the old file")
	}
	keys, err := Parse(newFile)
	if err != nil {
		t.Fatalf("Parse: %s", err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(keys))
	}
	if !bytes.Equal(keys[0].Config, newList[2:]) || !keys[0].SendAsRetry {
		t.Errorf("first key: want the new config, sent as retry; got SendAsRetry %t", keys[0].SendAsRetry)
	}
	if !bytes.Equal(keys[1].Config, oldList[2:]) || keys[1].SendAsRetry {
		t.Errorf("second key: want the old config, not sent as retry; got SendAsRetry %t", keys[1].SendAsRetry)
	}
	if bytes.Equal(keys[0].PrivateKey, keys[1].PrivateKey) {
		t.Errorf("the new key is the old key")
	}
	if keys[0].Config[4] == keys[1].Config[4] {
		t.Errorf("both keys have config ID %d", keys[0].Config[4])
	}

	// A third key keeps both old ones, in order.
	third, _, err := AddKey(newFile, "public.example.com")
	if err != nil {
		t.Fatalf("AddKey on a two-key file: %s", err)
	}
	keys3, err := Parse(third)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys3) != 3 || !bytes.Equal(keys3[1].Config, keys[0].Config) || !bytes.Equal(keys3[2].Config, keys[1].Config) {
		t.Errorf("a third key did not keep the two older ones in order")
	}
	ids := map[byte]bool{}
	for _, k := range keys3 {
		ids[k.Config[4]] = true
	}
	if len(ids) != 3 {
		t.Errorf("config IDs repeat: %v", ids)
	}

	if _, _, err := AddKey([]byte("junk"), "public.example.com"); err == nil {
		t.Errorf("AddKey on a bad file: want an error")
	}
	if _, _, err := AddKey(oldFile, "localhost"); err == nil {
		t.Errorf("AddKey with a bad public name: want an error")
	}
}
