package h3

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/quic"
)

// testCert makes a self-signed certificate for localhost.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

type testServer struct {
	srv  *Server
	ep   *quic.Endpoint
	addr string
	pool *x509.CertPool
	done chan error
}

func startServer(t *testing.T, srv *Server) *testServer {
	t.Helper()
	cert, pool := testCert(t)
	ep, err := quic.Listen("udp", "127.0.0.1:0", &quic.Config{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
			MinVersion:   tls.VersionTLS13,
		},
	})
	if err != nil {
		t.Fatalf("quic.Listen: %s", err)
	}
	ts := &testServer{srv: srv, ep: ep, addr: ep.LocalAddr().String(), pool: pool, done: make(chan error, 1)}
	go func() { ts.done <- srv.Serve(ep) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		select {
		case err := <-ts.done:
			if err != http.ErrServerClosed {
				t.Errorf("Serve after Shutdown: want http.ErrServerClosed, got %v", err)
			}
		case <-ctx.Done():
			t.Errorf("Serve did not return after Shutdown")
		}
	})
	return ts
}

func (ts *testServer) dial(t *testing.T) *quic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cep, err := quic.Listen("udp", "127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("client quic.Listen: %s", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		cep.Close(ctx)
	})
	conn, err := cep.Dial(ctx, "udp", ts.addr, &quic.Config{
		TLSConfig: &tls.Config{
			ServerName: "localhost",
			RootCAs:    ts.pool,
			NextProtos: []string{"h3"},
			MinVersion: tls.VersionTLS13,
		},
	})
	if err != nil {
		t.Fatalf("Dial: %s", err)
	}
	return conn
}

func (ts *testServer) client(t *testing.T) *ClientConn {
	t.Helper()
	cc, err := NewClientConn(context.Background(), ts.dial(t))
	if err != nil {
		t.Fatalf("NewClientConn: %s", err)
	}
	return cc
}

func get(t *testing.T, cc *ClientConn, method, path string, h http.Header) (*http.Response, string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "https://localhost"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, vs := range h {
		req.Header[k] = vs
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, "", err
	}
	b, err := io.ReadAll(resp.Body)
	return resp, string(b), err
}

func TestServeRequests(t *testing.T) {
	var mu sync.Mutex
	var seen []*http.Request
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r)
		mu.Unlock()
		switch r.URL.Path {
		case "/hello":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Connection", "close")
			w.Header().Set("X-Test", "yes")
			fmt.Fprintf(w, "hello %s %s", r.Method, r.URL.RawQuery)
		case "/teapot":
			w.WriteHeader(http.StatusTeapot)
			io.WriteString(w, "short and stout")
		case "/empty":
		case "/sniff":
			io.WriteString(w, "<html><body>hi</body></html>")
		}
	})
	ts := startServer(t, &Server{Handler: h})
	cc := ts.client(t)

	resp, body, err := get(t, cc, "GET", "/hello?a=b", http.Header{"User-Agent": {"h3-test"}, "Cookie": {"a=1", "b=2"}})
	if err != nil {
		t.Fatalf("GET /hello: %s", err)
	}
	if resp.StatusCode != 200 || body != "hello GET a=b" {
		t.Errorf("GET /hello: got %d %q", resp.StatusCode, body)
	}
	if resp.Header.Get("X-Test") != "yes" || resp.Header.Get("Content-Type") != "text/plain" {
		t.Errorf("GET /hello: headers %v", resp.Header)
	}
	if _, ok := resp.Header["Connection"]; ok {
		t.Errorf("GET /hello: Connection header sent over HTTP/3")
	}
	if resp.Header.Get("Date") == "" {
		t.Errorf("GET /hello: no Date header")
	}

	// Several requests on one connection.
	resp, body, err = get(t, cc, "GET", "/teapot", nil)
	if err != nil || resp.StatusCode != http.StatusTeapot || body != "short and stout" {
		t.Errorf("GET /teapot: %v %q %v", resp, body, err)
	}
	resp, body, err = get(t, cc, "HEAD", "/hello", nil)
	if err != nil || resp.StatusCode != 200 || body != "" {
		t.Errorf("HEAD /hello: %v %q %v", resp, body, err)
	}
	resp, body, err = get(t, cc, "GET", "/empty", nil)
	if err != nil || resp.StatusCode != 200 || body != "" {
		t.Errorf("GET /empty: %v %q %v", resp, body, err)
	}
	resp, _, err = get(t, cc, "GET", "/sniff", nil)
	if err != nil || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Errorf("GET /sniff: Content-Type %q, err %v", resp.Header.Get("Content-Type"), err)
	}

	mu.Lock()
	defer mu.Unlock()
	r := seen[0]
	if r.Proto != "HTTP/3.0" || r.ProtoMajor != 3 {
		t.Errorf("Proto: got %s", r.Proto)
	}
	if r.Host != "localhost" || r.RequestURI != "/hello?a=b" {
		t.Errorf("Host %q, RequestURI %q", r.Host, r.RequestURI)
	}
	if r.Header.Get("User-Agent") != "h3-test" || r.Header.Get("Cookie") != "a=1; b=2" {
		t.Errorf("request headers: %v", r.Header)
	}
	if r.TLS == nil || r.TLS.Version != tls.VersionTLS13 || r.TLS.NegotiatedProtocol != "h3" {
		t.Errorf("request TLS state: %+v", r.TLS)
	}
	if r.RemoteAddr == "" {
		t.Errorf("no RemoteAddr")
	}
}

func TestConnContext(t *testing.T) {
	type key struct{}
	var calls int
	var mu sync.Mutex
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, r.Context().Value(key{}).(string))
	})
	ts := startServer(t, &Server{
		Handler: h,
		ConnContext: func(ctx context.Context, conn *quic.Conn) (context.Context, error) {
			mu.Lock()
			defer mu.Unlock()
			calls++
			if calls > 1 {
				return nil, errors.New("only one connection")
			}
			return context.WithValue(ctx, key{}, "from the connection"), nil
		},
	})
	_, body, err := get(t, ts.client(t), "GET", "/", nil)
	if err != nil || body != "from the connection" {
		t.Errorf("first connection: %q %v", body, err)
	}

	conn := ts.dial(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = conn.Wait(ctx)
	var cce *quic.ConnectionCloseError
	if !errors.As(err, &cce) || cce.Code != errCodeInternal {
		t.Errorf("refused connection: want close with H3_INTERNAL_ERROR, got %v", err)
	}
}

// rawRequest writes b on a new stream and returns the error the stream's
// read side ends with.
func rawRequest(t *testing.T, conn *quic.Conn, b []byte) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := conn.NewStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st.SetReadContext(ctx)
	st.Write(b)
	st.CloseWrite()
	return io.ReadAll(st)
}

func headersFrame(fields ...headerField) []byte {
	block := appendFieldSection(nil, fields)
	return append(appendFrameHeader(nil, frameHeaders, uint64(len(block))), block...)
}

func TestMalformedRequests(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	})
	ts := startServer(t, &Server{Handler: h, MaxHeaderBytes: 1024})
	conn := ts.dial(t)

	good := []headerField{{":method", "GET"}, {":scheme", "https"}, {":authority", "localhost"}, {":path", "/"}}
	tests := []struct {
		name string
		req  []byte
		code uint64
	}{
		{"missing path", headersFrame(good[:3]...), errCodeMessage},
		{"uppercase name", headersFrame(append(good[:4:4], headerField{"X-Upper", "v"})...), errCodeMessage},
		{"connection header", headersFrame(append(good[:4:4], headerField{"connection", "close"})...), errCodeMessage},
		{"pseudo after regular", headersFrame(headerField{"x-a", "b"}, good[0], good[1], good[2], good[3]), errCodeMessage},
		{"unknown pseudo", headersFrame(append(good[:4:4], headerField{":protocol", "websocket"})...), errCodeMessage},
		{"connect", headersFrame(headerField{":method", "CONNECT"}, good[2]), errCodeMessage},
		{"header section too large", headersFrame(append(good[:4:4], headerField{"x-big", strings.Repeat("a", 2000)})...), errCodeExcessiveLoad},
		{"dynamic table reference", append(appendFrameHeader(nil, frameHeaders, 3), 0, 0, 0x80), errCodeQPACKDecompression},
		{"no headers before end", nil, errCodeRequestIncomplete},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rawRequest(t, conn, tc.req)
			var se quic.StreamError
			if !errors.As(err, &se) || uint64(se) != tc.code {
				t.Errorf("want stream reset with %#x, got %v", tc.code, err)
			}
		})
	}

	// Unknown and reserved-for-extension frame types before HEADERS are
	// skipped.
	grease := append(appendFrameHeader(nil, 0x21, 3), 'a', 'b', 'c')
	body, err := rawRequest(t, conn, append(grease, headersFrame(good...)...))
	if err != nil || !strings.Contains(string(body), "ok") {
		t.Errorf("request after an unknown frame: %q %v", body, err)
	}
}

func TestFrameBeforeHeadersClosesConnection(t *testing.T) {
	ts := startServer(t, &Server{Handler: http.NotFoundHandler()})
	conn := ts.dial(t)
	rawRequest(t, conn, append(appendFrameHeader(nil, frameData, 1), 'x'))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := conn.Wait(ctx)
	var cce *quic.ConnectionCloseError
	if !errors.As(err, &cce) || cce.Code != errCodeFrameUnexpected {
		t.Errorf("want close with H3_FRAME_UNEXPECTED, got %v", err)
	}
}

func TestControlStreamMustStartWithSettings(t *testing.T) {
	ts := startServer(t, &Server{Handler: http.NotFoundHandler()})
	conn := ts.dial(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := conn.NewSendOnlyStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st.Write(appendFrameHeader([]byte{streamControl}, frameGoAway, 1))
	st.Write([]byte{0})
	st.Flush()
	err = conn.Wait(ctx)
	var cce *quic.ConnectionCloseError
	if !errors.As(err, &cce) || cce.Code != errCodeMissingSettings {
		t.Errorf("want close with H3_MISSING_SETTINGS, got %v", err)
	}
}

func TestRequestBody(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		fmt.Fprintf(w, "%d:%s", r.ContentLength, b)
	})
	ts := startServer(t, &Server{Handler: h})
	conn := ts.dial(t)
	req := headersFrame(headerField{":method", "POST"}, headerField{":scheme", "https"},
		headerField{":authority", "localhost"}, headerField{":path", "/"}, headerField{"content-length", "11"})
	req = append(append(req, appendFrameHeader(nil, frameData, 5)...), "hello"...)
	req = append(req, appendFrameHeader(nil, 0x21, 0)...) // an unknown frame between DATA frames
	req = append(req, appendFrameHeader(nil, frameData, 0)...)
	req = append(append(req, appendFrameHeader(nil, frameData, 6)...), " world"...)
	req = append(req, headersFrame(headerField{"x-trailer", "t"})...)
	resp, err := rawRequest(t, conn, req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(resp), "11:hello world") {
		t.Errorf("response: %q", resp)
	}
}

func TestHandlerPanicResetsStream(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	})
	ts := startServer(t, &Server{Handler: h})
	_, _, err := get(t, ts.client(t), "GET", "/", nil)
	var se quic.StreamError
	if !errors.As(err, &se) || uint64(se) != errCodeInternal {
		t.Errorf("want stream reset with H3_INTERNAL_ERROR, got %v", err)
	}
}

func TestReadTimeout(t *testing.T) {
	ts := startServer(t, &Server{Handler: http.NotFoundHandler(), ReadTimeout: 100 * time.Millisecond})
	conn := ts.dial(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	st, err := conn.NewStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	st.SetReadContext(ctx)
	// Half a frame header, then nothing.
	st.Write([]byte{frameHeaders})
	st.Flush()
	_, err = io.ReadAll(st)
	var se quic.StreamError
	if !errors.As(err, &se) || uint64(se) != errCodeRequestIncomplete {
		t.Errorf("want stream reset with H3_REQUEST_INCOMPLETE, got %v", err)
	}
}
