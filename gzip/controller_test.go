package gzip

import (
	"compress/gzip"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestResponseControllerThroughGzip checks that http.ResponseController can
// reach the underlying ResponseWriter through the gzip wrapper, and that a
// Flush sends the compressed bytes written so far to the client instead of
// leaving them buffered in the gzip writer.
func TestResponseControllerThroughGzip(t *testing.T) {
	first := "first chunk of the body"
	second := "second chunk of the body"
	clientRead := make(chan struct{})
	handlerErrs := make(chan error, 1)

	h := GZIPHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			rc := http.NewResponseController(w)
			if err := rc.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
				handlerErrs <- err
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			if _, err := w.Write([]byte(first)); err != nil {
				handlerErrs <- err
				return
			}
			if err := rc.Flush(); err != nil {
				handlerErrs <- err
				return
			}
			// Wait for the client to have decoded the first chunk. If the
			// Flush left it in the gzip writer's buffer, the client never
			// sees it and this times out.
			select {
			case <-clientRead:
			case <-time.After(5 * time.Second):
				handlerErrs <- errors.New("client never read the flushed chunk")
				return
			}
			if _, err := w.Write([]byte(second)); err != nil {
				handlerErrs <- err
				return
			}
			handlerErrs <- nil
		}), nil)
	s := httptest.NewServer(h)
	defer s.Close()

	req, err := http.NewRequest("GET", s.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	// Keep the transport from transparently decompressing so we can check
	// the Content-Encoding and decode the stream ourselves.
	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if got := res.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}

	readDone := make(chan error, 1)
	var zr *gzip.Reader
	go func() {
		var err error
		zr, err = gzip.NewReader(res.Body)
		if err != nil {
			readDone <- err
			return
		}
		buf := make([]byte, len(first))
		if _, err := io.ReadFull(zr, buf); err != nil {
			readDone <- err
			return
		}
		if string(buf) != first {
			readDone <- errors.New("first chunk was " + string(buf))
			return
		}
		readDone <- nil
	}()
	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("reading the flushed chunk: %s", err)
		}
	case err := <-handlerErrs:
		t.Fatalf("handler finished before the client read the flushed chunk: %v", err)
	}
	close(clientRead)

	if err := <-handlerErrs; err != nil {
		t.Fatalf("handler: %s", err)
	}
	rest, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("reading the rest of the body: %s", err)
	}
	if string(rest) != second {
		t.Errorf("rest of body = %q, want %q", rest, second)
	}
}

// TestResponseControllerThroughUncompressed checks Flush through the wrapper
// when the filter turned compression off for the response.
func TestResponseControllerThroughUncompressed(t *testing.T) {
	h := GZIPHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "image/png")
			if _, err := w.Write([]byte("not compressed")); err != nil {
				t.Errorf("Write: %s", err)
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Errorf("Flush: %s", err)
			}
		}), nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(w, r)
	if !w.Flushed {
		t.Errorf("underlying ResponseWriter was not flushed")
	}
	if got := w.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want none", got)
	}
	if got := w.Body.String(); got != "not compressed" {
		t.Errorf("body = %q", got)
	}
}

// TestFlushBeforeWrite checks that a Flush before any Write still decides on
// compression first, so the headers sent by the Flush match the body that
// follows.
func TestFlushBeforeWrite(t *testing.T) {
	h := GZIPHandler(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Errorf("Flush: %s", err)
			}
			if _, err := w.Write([]byte("hello")); err != nil {
				t.Errorf("Write: %s", err)
			}
		}), nil)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	h.ServeHTTP(w, r)
	if got := w.Result().Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip", got)
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" {
		t.Errorf("body = %q, want hello", body)
	}
}
