package main

import (
	"context"
	"expvar"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	howhttptest "github.com/jmhodges/howsmyssl/howhttp/httptest"
)

// recordHandler is a slog.Handler that keeps the attributes of each record it
// is given, with the group names joined into the keys as slog.TextHandler does.
type recordHandler struct {
	mu      *sync.Mutex
	records *[]map[string]slog.Value
	prefix  string
}

func newRecordHandler() *recordHandler {
	return &recordHandler{mu: &sync.Mutex{}, records: &[]map[string]slog.Value{}}
}

func (rh *recordHandler) Enabled(context.Context, slog.Level) bool { return true }

func (rh *recordHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := map[string]slog.Value{"msg": slog.StringValue(r.Message)}
	r.Attrs(func(a slog.Attr) bool {
		attrs[rh.prefix+a.Key] = a.Value
		return true
	})
	rh.mu.Lock()
	defer rh.mu.Unlock()
	*rh.records = append(*rh.records, attrs)
	return nil
}

func (rh *recordHandler) WithAttrs([]slog.Attr) slog.Handler { return rh }

func (rh *recordHandler) WithGroup(name string) slog.Handler {
	return &recordHandler{mu: rh.mu, records: rh.records, prefix: rh.prefix + name + "."}
}

func (rh *recordHandler) all() []map[string]slog.Value {
	rh.mu.Lock()
	defer rh.mu.Unlock()
	return append([]map[string]slog.Value(nil), *rh.records...)
}

// waitForOneRecord returns the only record in rh. The log line is written
// after the handler returns, which can be just after the client has finished
// reading the response, so it waits a little for it to show up.
func waitForOneRecord(t *testing.T, rh *recordHandler) map[string]slog.Value {
	t.Helper()
	var records []map[string]slog.Value
	for i := 0; i < 500 && len(records) == 0; i++ {
		records = rh.all()
		if len(records) == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if len(records) != 1 {
		t.Fatalf("want exactly 1 log record per request, got %d: %v", len(records), records)
	}
	return records[0]
}

func TestLogHandlerFields(t *testing.T) {
	const okBody = "hello, howsmyssl"
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Millisecond)
		io.WriteString(w, okBody)
	})
	mux.HandleFunc("/empty", func(w http.ResponseWriter, r *http.Request) {})
	mux.Handle("/redirect", commonRedirect("example.com"))
	mux.HandleFunc("/flush", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		io.WriteString(w, "a")
		// Flushing only works if the http.ResponseController can find the
		// real ResponseWriter through logResponseWriter.Unwrap.
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("unable to Flush through the logging ResponseWriter: %s", err)
		}
		io.WriteString(w, "b")
	})

	notFoundRec := httptest.NewRecorder()
	http.NotFound(notFoundRec, httptest.NewRequest("GET", "/nope", nil))
	notFoundLen := int64(notFoundRec.Body.Len())

	tests := []struct {
		name       string
		path       string
		headers    map[string]string
		wantStatus int
		wantBytes  int64
		wantAttrs  map[string]string
	}{
		{
			name:       "200 with request headers",
			path:       "/ok?a=b",
			headers:    map[string]string{"Referer": "https://example.com/from", "Origin": "https://example.com", "User-Agent": "logtest/1.0"},
			wantStatus: http.StatusOK,
			wantBytes:  int64(len(okBody)),
			wantAttrs: map[string]string{
				"requests.requestURL":     "/ok?a=b",
				"requests.referrerHeader": "https://example.com/from",
				"requests.originHeader":   "https://example.com",
				"requests.userAgent":      "logtest/1.0",
			},
		},
		{
			name:       "404 without request headers",
			path:       "/nope",
			headers:    map[string]string{"User-Agent": ""},
			wantStatus: http.StatusNotFound,
			wantBytes:  notFoundLen,
			wantAttrs: map[string]string{
				"requests.requestURL":     "/nope",
				"requests.referrerHeader": "noreferrer",
				"requests.originHeader":   "noorigin",
				"requests.userAgent":      "nouseragent",
			},
		},
		{
			// commonRedirect changes r.URL, but the log should have the URL
			// the client asked for.
			name:       "301 from a handler that modifies the request URL",
			path:       "/redirect?a=b",
			wantStatus: http.StatusMovedPermanently,
			wantBytes:  int64(len("<a href=\"https://example.com/redirect?a=b\">Moved Permanently</a>.\n\n")),
			wantAttrs:  map[string]string{"requests.requestURL": "/redirect?a=b"},
		},
		{
			name:       "implicit 200 when the handler writes nothing",
			path:       "/empty",
			wantStatus: http.StatusOK,
			wantBytes:  0,
		},
		{
			name:       "explicit status and a flush between writes",
			path:       "/flush",
			wantStatus: http.StatusAccepted,
			wantBytes:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rh := newRecordHandler()
			h := logHandler{mux, slog.New(rh).WithGroup("requests"), "https"}
			srv := httptest.NewServer(h)
			defer srv.Close()

			req, err := http.NewRequest("GET", srv.URL+tt.path, nil)
			if err != nil {
				t.Fatalf("unable to make request: %s", err)
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			client := srv.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("unable to do request: %s", err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatalf("unable to read response body: %s", err)
			}
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("response status: want %d, got %d", tt.wantStatus, resp.StatusCode)
			}
			if int64(len(body)) != tt.wantBytes {
				t.Errorf("response body length: want %d, got %d", tt.wantBytes, len(body))
			}

			rec := waitForOneRecord(t, rh)

			wantAttrs := map[string]string{
				"msg":                  "request",
				"requests.host":        "127.0.0.1",
				"requests.proto":       "https",
				"requests.tlsVersion":  "none",
				"requests.httpVersion": "HTTP/1.1",
				"requests.status":      strconv.Itoa(tt.wantStatus),
				"requests.bytes":       strconv.FormatInt(tt.wantBytes, 10),
			}
			for k, v := range tt.wantAttrs {
				wantAttrs[k] = v
			}
			for k, want := range wantAttrs {
				got, ok := rec[k]
				if !ok {
					t.Errorf("log record is missing %q: %v", k, rec)
					continue
				}
				if got.String() != want {
					t.Errorf("log record %q: want %q, got %q", k, want, got.String())
				}
			}
			if got := rec["requests.status"].Kind(); got != slog.KindInt64 {
				t.Errorf("requests.status kind: want %s, got %s", slog.KindInt64, got)
			}
			if got := rec["requests.bytes"].Kind(); got != slog.KindInt64 {
				t.Errorf("requests.bytes kind: want %s, got %s", slog.KindInt64, got)
			}
			dur, ok := rec["requests.duration"]
			if !ok || dur.Kind() != slog.KindDuration {
				t.Fatalf("requests.duration: want a duration, got %v (present: %t)", dur, ok)
			}
			if dur.Duration() <= 0 || dur.Duration() > time.Minute {
				t.Errorf("requests.duration: want a small positive duration, got %s", dur.Duration())
			}
			if tt.path == "/ok?a=b" && dur.Duration() < time.Millisecond {
				t.Errorf("requests.duration: want at least the handler's 1ms sleep, got %s", dur.Duration())
			}
			// Every key that was logged before status, bytes and duration were
			// added has to still be there.
			if len(rec) != 12 {
				t.Errorf("want 12 fields in the log record (msg and 11 attributes), got %d: %v", len(rec), rec)
			}
		})
	}
}

func TestLogHandlerPanic(t *testing.T) {
	rh := newRecordHandler()
	h := logHandler{
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			panic(http.ErrAbortHandler)
		}),
		slog.New(rh).WithGroup("requests"),
		"http",
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Errorf("logHandler swallowed the inner handler's panic")
			}
		}()
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/boom", nil))
	}()
	records := rh.all()
	if len(records) != 1 {
		t.Fatalf("want exactly 1 log record for a panicking request, got %d: %v", len(records), records)
	}
	if got := records[0]["requests.status"].Int64(); got != 0 {
		t.Errorf("requests.status for a panic before any write: want 0, got %d", got)
	}
	if got := records[0]["requests.proto"].String(); got != "http" {
		t.Errorf("requests.proto: want %q, got %q", "http", got)
	}
}

// TestLogHandlerTLSMux checks the log line of the real HTTPS mux over a real
// TLS connection, gzip layer included.
func TestLogHandlerTLSMux(t *testing.T) {
	index = loadIndex()
	stats := newStatusStats(new(expvar.Map).Init())
	staticHandler := makeStaticHandler(stats)

	tests := []struct {
		path       string
		wantStatus int
	}{
		{"/", http.StatusOK},
		{"/s/nope.css", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rh := newRecordHandler()
			tm := tlsMux("", "www.howsmyssl.com", "www.howsmyssl.com", staticHandler, handleWeb, nil, slog.New(rh).WithGroup("requests"), newTestLogger(t))
			srv := howhttptest.NewServer(tm)
			defer srv.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "GET", srv.URL+tt.path, nil)
			if err != nil {
				t.Fatalf("NewRequest: %s", err)
			}
			// Setting Accept-Encoding ourselves stops the client from
			// decompressing the body, so its length is what went on the wire.
			req.Header.Set("Accept-Encoding", "gzip")
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("Do: %s", err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				t.Fatalf("ReadAll: %s", err)
			}
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("response status: want %d, got %d", tt.wantStatus, resp.StatusCode)
			}
			if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
				t.Errorf("Content-Encoding: want %q, got %q", "gzip", got)
			}

			rec := waitForOneRecord(t, rh)
			if got := rec["requests.status"].Int64(); got != int64(tt.wantStatus) {
				t.Errorf("requests.status: want %d, got %d", tt.wantStatus, got)
			}
			if got := rec["requests.bytes"].Int64(); got != int64(len(body)) || got == 0 {
				t.Errorf("requests.bytes: want the %d bytes of the body as sent, got %d", len(body), got)
			}
			if got := rec["requests.tlsVersion"].String(); got != "TLS 1.3" {
				t.Errorf("requests.tlsVersion: want %q, got %q", "TLS 1.3", got)
			}
			if got := rec["requests.httpVersion"].String(); got != resp.Proto {
				t.Errorf("requests.httpVersion: want %q, got %q", resp.Proto, got)
			}
			if got := rec["requests.proto"].String(); got != "https" {
				t.Errorf("requests.proto: want %q, got %q", "https", got)
			}
			if got := rec["requests.requestURL"].String(); got != tt.path {
				t.Errorf("requests.requestURL: want %q, got %q", tt.path, got)
			}
		})
	}
}
