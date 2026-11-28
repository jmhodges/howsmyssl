package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

var dirName = flag.String("d", "", "dir name to generate files in")

func main() {
	flag.Parse()
	if *dirName == "" {
		log.Fatalf("the non-empty -d parameter is required")
	}
	caCert, caKey, err := generateCACert(*dirName)
	// caCert, err := makeCerts(nil, *dirName, "development_ca")
	if err != nil {
		log.Fatalf("unable to make CA certificates: %s", err)
	}
	err = generateLeafCert(*dirName, caCert, caKey)
	// _, err = makeCerts(caCert, *dirName, "development")
	if err != nil {
		log.Fatalf("unable to make leaf certificates: %s", err)
	}
}

func generateCACert(dir string) (*x509.Certificate, *rsa.PrivateKey, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			CommonName:    "howsmyssl development CA",
			Organization:  []string{"ORGANIZATION_NAME"},
			Country:       []string{"COUNTRY_CODE"},
			Province:      []string{"PROVINCE"},
			Locality:      []string{"CITY"},
			StreetAddress: []string{"ADDRESS"},
			PostalCode:    []string{"POSTAL_CODE"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	pub := &priv.PublicKey
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create ca failed: %s", err)
	}

	// Parse the freshly-created cert so the leaf is signed against a parent
	// that carries the Go-generated Subject Key Id. That makes
	// CreateCertificate populate the leaf's Authority Key Id, giving a
	// standard, chainable AKID->SKID link.
	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ca failed: %s", err)
	}

	if err := writePEM(filepath.Join(dir, "development_ca_cert.pem"), 0644, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes}); err != nil {
		return nil, nil, fmt.Errorf("write ca cert pem failed: %w", err)
	}
	log.Println("written development_ca_cert.pem")

	if err := writePEM(filepath.Join(dir, "development_ca_key.pem"), 0600, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return nil, nil, fmt.Errorf("write ca key pem failed: %w", err)
	}
	log.Println("written development_ca_key.pem")

	return caCert, priv, nil
}

func generateLeafCert(dir string, caCert *x509.Certificate, caKey *rsa.PrivateKey) error {
	// Prepare certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:    "localhost",
			Organization:  []string{"ORGANIZATION_NAME"},
			Country:       []string{"COUNTRY_CODE"},
			Province:      []string{"PROVINCE"},
			Locality:      []string{"CITY"},
			StreetAddress: []string{"ADDRESS"},
			PostalCode:    []string{"POSTAL_CODE"},
		},
		DNSNames:    []string{"localhost"},
		NotBefore:   time.Now().Add(-1 * time.Minute),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	pub := &priv.PublicKey

	cert_b, err := x509.CreateCertificate(rand.Reader, cert, caCert, pub, caKey)
	if err != nil {
		return err
	}

	if err := writePEM(filepath.Join(dir, "development_cert.pem"), 0644, &pem.Block{Type: "CERTIFICATE", Bytes: cert_b}); err != nil {
		return fmt.Errorf("write cert pem failed: %w", err)
	}
	log.Println("written development_cert.pem")

	if err := writePEM(filepath.Join(dir, "development_key.pem"), 0600, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		return fmt.Errorf("write key pem failed: %w", err)
	}
	log.Println("written development_key.pem")
	return nil
}

// writePEM writes block to path, truncating any file already there. It
// returns the error from Close as well as from Encode, since a failed Close
// on a writable file can mean the PEM never made it to disk.
func writePEM(path string, perm os.FileMode, block *pem.Block) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, f.Close())
	}()
	return pem.Encode(f, block)
}
