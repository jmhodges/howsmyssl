package howhttptest_test

import (
	"net/http"
	"testing"

	howhttptest "github.com/jmhodges/howsmyssl/howhttp/httptest"
)

func TestServer_CertificateAndRootCAs(t *testing.T) {
	srv := howhttptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	if srv.Certificate() == nil {
		t.Fatal("Certificate() returned nil")
	}
	if srv.RootCAs() == nil {
		t.Fatal("RootCAs() returned nil")
	}
	// Both config builders should reference the same pool.
	if srv.ClientTLSConfig().RootCAs != srv.RootCAs() {
		t.Error("ClientTLSConfig().RootCAs != RootCAs()")
	}
	if srv.ClientTLS1262Config().RootCAs != srv.RootCAs() {
		t.Error("ClientTLS1262Config().RootCAs != RootCAs()")
	}
}
