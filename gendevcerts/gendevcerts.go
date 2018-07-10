package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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

	certOut, err := os.Create(filepath.Join(dir, "development_ca_cert.pem"))
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	certOut.Close()
	log.Println("written development_ca_cert.pem")

	keyOut, err := os.OpenFile(filepath.Join(dir, "development_ca_key.pem"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Println("written development_ca_key.pem")

	return ca, priv, nil
}

func generateLeafCert(dir string, caCert *x509.Certificate, caKey *rsa.PrivateKey) error {
	// Prepare certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"ORGANIZATION_NAME"},
			Country:       []string{"COUNTRY_CODE"},
			Province:      []string{"PROVINCE"},
			Locality:      []string{"CITY"},
			StreetAddress: []string{"ADDRESS"},
			PostalCode:    []string{"POSTAL_CODE"},
		},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
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

	certOut, err := os.Create(filepath.Join(dir, "development_cert.pem"))
	if err != nil {
		return err
	}

	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: cert_b})
	certOut.Close()
	log.Println("written development_cert.pem")

	keyOut, err := os.OpenFile(filepath.Join(dir, "development_key.pem"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	log.Println("written development_key.pem")
	return keyOut.Close()
}
