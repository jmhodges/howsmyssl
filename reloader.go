package main

import (
	"log"
	"sync"
	"time"

	tls "github.com/jmhodges/howsmyssl/tls120"
)

func newKeypairReloader(certPath, keyPath string) (*keypairReloader, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	kpr := &keypairReloader{
		certPath: certPath,
		keyPath:  keyPath,
		cert:     &cert,
	}
	return kpr, nil
}

func reloadKeypairForever(kpr *keypairReloader, tick *time.Ticker) {
	for range tick.C {
		if err := kpr.maybeReload(); err != nil {
			log.Printf("error when attempting reload of TLS keypair: %s", err)
		}
	}
}

type keypairReloader struct {
	certMu   sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

func (kpr *keypairReloader) maybeReload() error {
	newCert, err := tls.LoadX509KeyPair(kpr.certPath, kpr.keyPath)
	if err != nil {
		return err
	}
	kpr.certMu.Lock()
	defer kpr.certMu.Unlock()
	kpr.cert = &newCert
	return nil
}

func (kpr *keypairReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	kpr.certMu.RLock()
	defer kpr.certMu.RUnlock()
	return kpr.cert, nil
}
