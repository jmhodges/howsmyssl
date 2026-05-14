package howhttp_test

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jmhodges/howsmyssl/howhttp"
	howhttptest "github.com/jmhodges/howsmyssl/howhttp/httptest"
	tls1262 "github.com/jmhodges/howsmyssl/tls1262"
)

func TestServer_HTTP11(t *testing.T) {
	srv := howhttptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	}))
	defer srv.Close()

	tlsConf := srv.ClientTLSConfig()
	tlsConf.NextProtos = []string{"http/1.1"}
	c := &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConf},
	}

	resp, err := c.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("Get: %s", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 1 {
		t.Errorf("ProtoMajor = %d, want 1", resp.ProtoMajor)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %s", err)
	}
	if string(b) != "hello" {
		t.Errorf("body = %q, want %q", b, "hello")
	}
}

func TestServer_HTTP2(t *testing.T) {
	srv := howhttptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello")
	}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("Get: %s", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Errorf("ProtoMajor = %d, want 2 (ALPN should negotiate h2)", resp.ProtoMajor)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %s", err)
	}
	if string(b) != "hello" {
		t.Errorf("body = %q, want %q", b, "hello")
	}
}

func TestServer_SmuggledConnReachable(t *testing.T) {
	srv := howhttptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := howhttp.SmuggledConn(r.Context()); !ok {
			http.Error(w, "no smuggled conn", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("Get: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestServer_RawTLS1262Client(t *testing.T) {
	srv := howhttptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "raw")
	}))
	defer srv.Close()

	conf := srv.ClientTLS1262Config()
	conf.NextProtos = []string{"http/1.1"}

	addr := strings.TrimPrefix(srv.URL, "https://")
	c, err := tls1262.Dial("tcp", addr, conf)
	if err != nil {
		t.Fatalf("Dial: %s", err)
	}
	defer c.Close()

	if _, err := io.WriteString(c, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("WriteString: %s", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatalf("ReadResponse: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %s", err)
	}
	if string(b) != "raw" {
		t.Errorf("body = %q, want %q", b, "raw")
	}
}
