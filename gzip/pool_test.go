package gzip

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testBody returns a compressible body of about n bytes that differs by seed.
func testBody(seed, n int) []byte {
	var b bytes.Buffer
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, `{"seed":%d,"i":%d,"cipher":"TLS_AES_128_GCM_SHA256"},`, seed, i)
	}
	return b.Bytes()[:n]
}

// chunkedHandler writes body in chunks of chunk bytes as text/plain.
func chunkedHandler(body []byte, chunk int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		for b := body; len(b) > 0; {
			n := min(chunk, len(b))
			if _, err := w.Write(b[:n]); err != nil {
				panic(err)
			}
			b = b[n:]
		}
	})
}

// newWriterOutput is what gzip.NewWriter makes of body written in chunks of
// chunk bytes, the output of the handler before writers were pooled.
func newWriterOutput(t *testing.T, body []byte, chunk int) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	for b := body; len(b) > 0; {
		n := min(chunk, len(b))
		if _, err := gz.Write(b[:n]); err != nil {
			t.Fatal(err)
		}
		b = b[n:]
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestPooledWriterOutputUnchanged checks that the compressed bytes of each
// response are the same as a fresh gzip.NewWriter makes, response after
// response, so a reused writer carries nothing over from the one before.
func TestPooledWriterOutputUnchanged(t *testing.T) {
	cases := []struct {
		size, chunk int
	}{
		{1, 1},
		{16, 16},
		{2600, 512},
		{300 << 10, 4096},
		{11 << 10, 1},
		{5, 5},
		{300 << 10, 300 << 10},
	}
	// Twice through, so every case also runs on a writer that a different
	// case used last.
	for round := 0; round < 2; round++ {
		for i, c := range cases {
			body := testBody(round*100+i, c.size)
			h := GZIPHandler(chunkedHandler(body, c.chunk), nil)
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("Accept-Encoding", "gzip")
			h.ServeHTTP(w, r)
			if got := w.Result().Header.Get("Content-Encoding"); got != "gzip" {
				t.Fatalf("round %d, case %d: Content-Encoding = %q, want gzip", round, i, got)
			}
			want := newWriterOutput(t, body, c.chunk)
			if !bytes.Equal(w.Body.Bytes(), want) {
				t.Errorf("round %d, case %d (%d bytes in chunks of %d): compressed body differs from gzip.NewWriter's: got %d bytes, want %d", round, i, c.size, c.chunk, w.Body.Len(), len(want))
			}
		}
	}
}

// TestWriteAfterHandlerReturns checks that a Write through the response
// writer after the handler returned fails, instead of reaching the gzip
// writer that went back to the pool.
func TestWriteAfterHandlerReturns(t *testing.T) {
	var kept http.ResponseWriter
	h := GZIPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte("hello")); err != nil {
			t.Errorf("Write: %s", err)
		}
		kept = w
	}), nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(w, r)
	before := w.Body.Len()

	if _, err := kept.Write([]byte("late")); !errors.Is(err, errWriteAfterReturn) {
		t.Errorf("late Write error = %v, want %v", err, errWriteAfterReturn)
	}
	if w.Body.Len() != before {
		t.Errorf("late Write changed the response body")
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Errorf("body = %q, want hello", got)
	}
}

// TestPooledWritersConcurrentHTTP2 runs many compressed responses at once as
// streams of one HTTP/2 connection, each with its own body, and checks every
// client gets exactly its own body. Run with -race.
func TestPooledWritersConcurrentHTTP2(t *testing.T) {
	const streams = 64
	h := GZIPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var seed, size int
		if _, err := fmt.Sscanf(r.URL.Query().Get("s"), "%d-%d", &seed, &size); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		chunkedHandler(testBody(seed, size), 1000).ServeHTTP(w, r)
	}), nil)
	s := httptest.NewUnstartedServer(h)
	s.EnableHTTP2 = true
	s.StartTLS()
	defer s.Close()

	tr := s.Client().Transport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = true
	tr.DisableCompression = true
	client := &http.Client{Transport: tr}
	defer tr.CloseIdleConnections()

	var wg sync.WaitGroup
	errs := make(chan error, streams)
	for i := range streams {
		wg.Go(func() {
			size := 100 + (i*7919)%(40<<10)
			req, err := http.NewRequest("GET", fmt.Sprintf("%s/?s=%d-%d", s.URL, i, size), nil)
			if err != nil {
				errs <- err
				return
			}
			req.Header.Set("Accept-Encoding", "gzip")
			res, err := client.Do(req)
			if err != nil {
				errs <- err
				return
			}
			defer res.Body.Close()
			if res.ProtoMajor != 2 {
				errs <- fmt.Errorf("stream %d: got %s, want HTTP/2", i, res.Proto)
				return
			}
			if ce := res.Header.Get("Content-Encoding"); ce != "gzip" {
				errs <- fmt.Errorf("stream %d: Content-Encoding = %q", i, ce)
				return
			}
			zr, err := gzip.NewReader(res.Body)
			if err != nil {
				errs <- fmt.Errorf("stream %d: %w", i, err)
				return
			}
			got, err := io.ReadAll(zr)
			if err != nil {
				errs <- fmt.Errorf("stream %d: %w", i, err)
				return
			}
			if want := testBody(i, size); !bytes.Equal(got, want) {
				errs <- fmt.Errorf("stream %d: body of %d bytes isn't its own (want %d bytes)", i, len(got), len(want))
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// discardResponseWriter is an http.ResponseWriter that keeps nothing, so the
// benchmark counts the gzip layer's allocations and little else.
type discardResponseWriter struct {
	hdr http.Header
}

func (w *discardResponseWriter) Header() http.Header         { return w.hdr }
func (w *discardResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *discardResponseWriter) WriteHeader(int)             {}

// BenchmarkGZIPHandler measures the allocations of one compressed response
// of a small JSON body. Compare -benchmem's B/op with and without pooling.
func BenchmarkGZIPHandler(b *testing.B) {
	for _, size := range []int{2 << 10, 10 << 10} {
		b.Run(fmt.Sprintf("body=%dKB", size>>10), func(b *testing.B) {
			body := []byte(strings.Repeat(`{"cipher":"TLS_AES_128_GCM_SHA256"},`, size/36+1))[:size]
			h := GZIPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Write(body)
			}), nil)
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("Accept-Encoding", "gzip")
			w := &discardResponseWriter{hdr: make(http.Header)}
			b.ReportAllocs()
			for b.Loop() {
				clear(w.hdr)
				h.ServeHTTP(w, r)
			}
		})
	}
}

// finishedSpy is an http.ResponseWriter, with the optional methods that
// http.ResponseController looks for, that fails the test if any of them is
// called once the handler has returned.
type finishedSpy struct {
	*httptest.ResponseRecorder
	t        *testing.T
	finished bool
}

func (s *finishedSpy) check(method string) {
	if s.finished {
		s.t.Errorf("%s reached the underlying ResponseWriter after the handler returned", method)
	}
}

func (s *finishedSpy) Header() http.Header {
	s.check("Header")
	return s.ResponseRecorder.Header()
}

func (s *finishedSpy) Write(b []byte) (int, error) {
	s.check("Write")
	return s.ResponseRecorder.Write(b)
}

func (s *finishedSpy) WriteHeader(code int) {
	s.check("WriteHeader")
	s.ResponseRecorder.WriteHeader(code)
}

func (s *finishedSpy) Flush() {
	s.check("Flush")
	s.ResponseRecorder.Flush()
}

func (s *finishedSpy) FlushError() error {
	s.check("FlushError")
	s.ResponseRecorder.Flush()
	return nil
}

func (s *finishedSpy) SetReadDeadline(time.Time) error {
	s.check("SetReadDeadline")
	return nil
}

func (s *finishedSpy) SetWriteDeadline(time.Time) error {
	s.check("SetWriteDeadline")
	return nil
}

func (s *finishedSpy) EnableFullDuplex() error {
	s.check("EnableFullDuplex")
	return nil
}

func (s *finishedSpy) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	s.check("Hijack")
	return nil, nil, errors.New("finishedSpy can't hijack")
}

// TestCallsAfterHandlerReturns checks that nothing done through the response
// writer after the handler returned reaches the underlying ResponseWriter,
// which net/http no longer lets anyone use by then, whether or not the
// response was compressed.
func TestCallsAfterHandlerReturns(t *testing.T) {
	for _, contentType := range []string{"text/plain", "image/png"} {
		t.Run(contentType, func(t *testing.T) {
			var kept http.ResponseWriter
			h := GZIPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", contentType)
				if _, err := w.Write([]byte("hello")); err != nil {
					t.Errorf("Write: %s", err)
				}
				kept = w
			}), nil)
			spy := &finishedSpy{ResponseRecorder: httptest.NewRecorder(), t: t}
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("Accept-Encoding", "gzip")
			h.ServeHTTP(spy, r)
			spy.finished = true

			rc := http.NewResponseController(kept)
			if err := rc.Flush(); err == nil {
				t.Errorf("late Flush returned no error")
			}
			if err := rc.SetReadDeadline(time.Now()); err == nil {
				t.Errorf("late SetReadDeadline returned no error")
			}
			if err := rc.SetWriteDeadline(time.Now()); err == nil {
				t.Errorf("late SetWriteDeadline returned no error")
			}
			if err := rc.EnableFullDuplex(); err == nil {
				t.Errorf("late EnableFullDuplex returned no error")
			}
			if _, _, err := rc.Hijack(); err == nil {
				t.Errorf("late Hijack returned no error")
			}
			if f, ok := kept.(http.Flusher); ok {
				f.Flush()
			}
			if _, err := kept.Write([]byte("late")); err == nil {
				t.Errorf("late Write returned no error")
			}
			kept.WriteHeader(http.StatusInternalServerError)
			kept.Header().Set("X-Late", "1")
		})
	}
}
