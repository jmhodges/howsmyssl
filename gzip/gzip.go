package gzip

import (
	"bufio"
	"compress/gzip"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Thanks to Andrew Gerrand for inspiration:
// https://groups.google.com/d/msg/golang-nuts/eVnTcMwNVjM/4vYU8id9Q2UJ
//
// Also, node's Connect library implementation of the compress middleware:
// https://github.com/senchalabs/connect/blob/master/lib/middleware/compress.js
//
// And StackOverflow's explanation of Vary: Accept-Encoding header:
// http://stackoverflow.com/questions/7848796/what-does-varyaccept-encoding-mean

// Internal gzipped writer that satisfies both the (body) writer in gzipped format,
// and maintains the rest of the ResponseWriter interface for header manipulation.
type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
	r        *http.Request // Keep a hold of the Request, for the filter function
	filtered bool          // Has the request been run through the filter function?
	dogzip   bool          // Should we do GZIP compression for this request?
	filterFn func(http.ResponseWriter, *http.Request) bool
}

// gzipWriterPool holds gzip writers for reuse across responses. A
// gzip.Writer allocates over a megabyte of compressor state, whatever the size
// of the body it compresses, so making a new one per response dominates the
// allocations of a small compressed response.
var gzipWriterPool = sync.Pool{
	New: func() any {
		return gzip.NewWriter(io.Discard)
	},
}

// getPooledGzipWriter returns a gzip writer from the pool that writes to w.
// Reset gives it the same state as gzip.NewWriter(w), so its output is the
// same.
func getPooledGzipWriter(w io.Writer) *gzip.Writer {
	gz := gzipWriterPool.Get().(*gzip.Writer)
	gz.Reset(w)
	return gz
}

// putPooledGzipWriter returns gz to the pool. Only call it once nothing can
// write to gz anymore, that is, after the handler using it has returned and gz
// has been closed. It drops gz's reference to the old destination first.
func putPooledGzipWriter(gz *gzip.Writer) {
	gz.Reset(io.Discard)
	gzipWriterPool.Put(gz)
}

// returnedResponseWriter takes the place of both the pooled gzip writer and
// the underlying http.ResponseWriter in a gzipResponseWriter once the handler
// has returned. net/http doesn't allow using a ResponseWriter after its
// handler returns, and the gzip writer may by then be serving another
// response, so a late call fails here, reaching neither of them. It has the
// optional methods that http.ResponseController looks for, so those fail too
// instead of reporting that they aren't supported.
type returnedResponseWriter struct{}

func (returnedResponseWriter) Header() http.Header { return http.Header{} }

func (returnedResponseWriter) Write([]byte) (int, error) { return 0, errWriteAfterReturn }

func (returnedResponseWriter) WriteHeader(int) {}

func (returnedResponseWriter) FlushError() error { return errWriteAfterReturn }

func (returnedResponseWriter) SetReadDeadline(time.Time) error { return errWriteAfterReturn }

func (returnedResponseWriter) SetWriteDeadline(time.Time) error { return errWriteAfterReturn }

func (returnedResponseWriter) EnableFullDuplex() error { return errWriteAfterReturn }

func (returnedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errWriteAfterReturn
}

var errWriteAfterReturn = errors.New("gzip: ResponseWriter used after the handler returned")

// Make sure the filter function is applied. The gzip writer is only taken from
// the pool once the filter has said to compress, so responses that aren't
// compressed don't hold one.
func (w *gzipResponseWriter) applyFilter() {
	if !w.filtered {
		if w.dogzip = w.filterFn(w, w.r); w.dogzip {
			w.Writer = getPooledGzipWriter(w.ResponseWriter)
			setGzipHeaders(w.Header())
		}
		w.filtered = true
	}
}

// Unambiguous Write() implementation (otherwise both ResponseWriter and Writer
// want to claim this method).
func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	w.applyFilter()
	if w.dogzip {
		// Write compressed
		return w.Writer.Write(b)
	}
	// Write uncompressed
	return w.ResponseWriter.Write(b)
}

// Intercept the WriteHeader call to correctly set the GZIP headers.
func (w *gzipResponseWriter) WriteHeader(code int) {
	w.applyFilter()
	w.ResponseWriter.WriteHeader(code)
}

// Implement WrapWriter interface
func (w *gzipResponseWriter) WrappedWriter() http.ResponseWriter {
	return w.ResponseWriter
}

// Unwrap returns the underlying http.ResponseWriter so that
// http.ResponseController can reach its optional methods (deadlines, Hijack,
// EnableFullDuplex) through this wrapper.
func (w *gzipResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// FlushError flushes the compressed bytes buffered in the gzip writer to the
// underlying http.ResponseWriter, and then flushes that. Without it,
// http.ResponseController would find Flush on the underlying writer through
// Unwrap and skip the gzip writer's buffer, sending nothing new to the client.
//
// http.ResponseController prefers FlushError over Flush and Unwrap, so this
// is what it calls.
func (w *gzipResponseWriter) FlushError() error {
	// Decide on compression before the headers go out with the flush, so
	// they match the body that follows.
	w.applyFilter()
	if w.dogzip {
		if f, ok := w.Writer.(interface{ Flush() error }); ok {
			if err := f.Flush(); err != nil {
				return err
			}
		}
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

// Flush implements http.Flusher for callers that type assert for it instead
// of using http.ResponseController. Use FlushError to see errors.
func (w *gzipResponseWriter) Flush() {
	_ = w.FlushError()
}

var (
	defaultFilterTypes = [...]string{
		"text",
		"javascript",
		"json",
	}
)

// Default filter to check if the response should be GZIPped.
// By default, all text (html, css, xml, ...), javascript and json
// content types are candidates for GZIP.
func defaultFilter(w http.ResponseWriter, r *http.Request) bool {
	hdr := w.Header()
	for _, tp := range defaultFilterTypes {
		ok := HeaderMatch(hdr, "Content-Type", HmContains, tp)
		if ok {
			return true
		}
	}
	return false
}

// GZIPHandlerFunc is the same as GZIPHandler, it is just a convenience
// signature that accepts a func(http.ResponseWriter, *http.Request) instead of
// a http.Handler interface. It saves the boilerplate http.HandlerFunc() cast.
func GZIPHandlerFunc(h http.HandlerFunc, filterFn func(http.ResponseWriter, *http.Request) bool) http.HandlerFunc {
	return GZIPHandler(h, filterFn)
}

// Gzip compression HTTP handler. If the client supports it, it compresses the response
// written by the wrapped handler. The filter function is called when the response is about
// to be written to determine if compression should be applied. If this argument is nil,
// the default filter will GZIP only content types containing /json|text|javascript/.
func GZIPHandler(h http.Handler, filterFn func(http.ResponseWriter, *http.Request) bool) http.HandlerFunc {
	if filterFn == nil {
		filterFn = defaultFilter
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := getGzipWriter(w); ok {
			// Self-awareness, gzip handler is already set up
			h.ServeHTTP(w, r)
			return
		}
		hdr := w.Header()
		setVaryHeader(hdr)

		// Do nothing on a HEAD request
		if r.Method == "HEAD" {
			h.ServeHTTP(w, r)
			return
		}
		if !acceptsGzip(r.Header) {
			// No gzip support from the client, return uncompressed
			h.ServeHTTP(w, r)
			return
		}

		// Prepare a gzip response container. Its gzip writer comes from the
		// pool when the filter first decides to compress.
		gzw := &gzipResponseWriter{
			ResponseWriter: w,
			r:              r,
			filterFn:       filterFn,
		}
		h.ServeHTTP(gzw, r)
		// Iff the handler completed successfully (no panic) and GZIP was indeed used, close the gzip writer,
		// which seems to generate a Write to the underlying writer. The
		// handler has returned, so nothing else writes to the gzip writer and
		// it can go back to the pool. On a panic, it is left for the garbage
		// collector instead.
		if gzw.dogzip {
			gz := gzw.Writer.(*gzip.Writer)
			gz.Close()
			gzw.Writer = returnedResponseWriter{}
			putPooledGzipWriter(gz)
		}
		// Keep anything done through gzw from here on, like a Flush or a
		// deadline through http.ResponseController, off the finished
		// ResponseWriter, and from taking a gzip writer from the pool.
		gzw.filtered = true
		gzw.ResponseWriter = returnedResponseWriter{}
	}
}

// Add the vary by "accept-encoding" header if it is not already set.
func setVaryHeader(hdr http.Header) {
	if !HeaderMatch(hdr, "Vary", HmContains, "accept-encoding") {
		hdr.Add("Vary", "Accept-Encoding")
	}
}

// Checks if the client accepts GZIP-encoded responses.
func acceptsGzip(hdr http.Header) bool {
	ok := HeaderMatch(hdr, "Accept-Encoding", HmContains, "gzip")
	if !ok {
		ok = HeaderMatch(hdr, "Accept-Encoding", HmEquals, "*")
	}
	return ok
}

func setGzipHeaders(hdr http.Header) {
	// The content-type will be explicitly set somewhere down the path of handlers
	hdr.Set("Content-Encoding", "gzip")
	hdr.Del("Content-Length")
}

// Helper function to retrieve the gzip writer.
func getGzipWriter(w http.ResponseWriter) (*gzipResponseWriter, bool) {
	gz, ok := GetResponseWriter(w, func(tst http.ResponseWriter) bool {
		_, ok := tst.(*gzipResponseWriter)
		return ok
	})
	if ok {
		return gz.(*gzipResponseWriter), true
	}
	return nil, false
}
