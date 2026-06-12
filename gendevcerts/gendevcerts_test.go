package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// TestGeneratedLeafChainsToCA guards the exact bug that broke
// `curl --cacert ./config/development_ca_cert.pem`: the generated leaf shared
// an identical subject DN with the CA and carried no Authority Key Id, so
// OpenSSL/curl treated it as a self-signed root (verify error 18) and never
// chained it to the CA. Go's own verifier is lenient about this case and
// happily verifies the handshake, so the TLS tests in the main package can't
// catch it — we assert the OpenSSL-relevant invariants here instead.
func TestGeneratedLeafChainsToCA(t *testing.T) {
	dir := t.TempDir()

	caCert, caKey, err := generateCACert(dir)
	if err != nil {
		t.Fatalf("generateCACert: %s", err)
	}
	if err := generateLeafCert(dir, caCert, caKey); err != nil {
		t.Fatalf("generateLeafCert: %s", err)
	}

	ca := loadCert(t, filepath.Join(dir, "development_ca_cert.pem"))
	leaf := loadCert(t, filepath.Join(dir, "development_cert.pem"))

	// A leaf whose subject DN equals its issuer DN looks self-signed to
	// OpenSSL/curl, which short-circuits with verify error 18 instead of
	// chaining to the CA.
	if bytes.Equal(leaf.RawSubject, leaf.RawIssuer) {
		t.Errorf("leaf subject DN equals issuer DN (%q); OpenSSL/curl will treat it as self-signed", leaf.Subject)
	}

	// The leaf must carry an Authority Key Id that points at the CA's Subject
	// Key Id, giving a standard, chainable link.
	if len(leaf.AuthorityKeyId) == 0 {
		t.Errorf("leaf has no Authority Key Id")
	} else if !bytes.Equal(leaf.AuthorityKeyId, ca.SubjectKeyId) {
		t.Errorf("leaf Authority Key Id %x does not match CA Subject Key Id %x", leaf.AuthorityKeyId, ca.SubjectKeyId)
	}

	// And it must actually verify against the CA as the only trusted root, for
	// the hostname it's served on.
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:   roots,
		DNSName: "localhost",
	}); err != nil {
		t.Errorf("leaf does not verify against the CA: %s", err)
	}
}

func loadCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s): %s", path, err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("no PEM block in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate(%s): %s", path, err)
	}
	return cert
}
