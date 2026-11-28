// Package h3 is a small HTTP/3 (RFC 9114) server on top of
// golang.org/x/net/quic.
//
// It does what howsmyssl's few GET endpoints need and no more: no server
// push, no QPACK dynamic table (RFC 9204) in either direction, no extended
// CONNECT, and no CONNECT at all. Each request is served by an ordinary
// http.Handler.
package h3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/quic"
)

// DefaultMaxHeaderBytes is the default limit on the size of a request's
// header section, as RFC 9114 Section 4.2.2 counts it.
const DefaultMaxHeaderBytes = 64 << 10

// Server serves HTTP/3 requests on the connections a quic.Endpoint accepts.
type Server struct {
	// Handler serves each request.
	Handler http.Handler

	// ConnContext, if not nil, is called once for each new connection after
	// its handshake. The context it returns is the parent of the contexts of
	// the connection's requests. If it returns an error, the connection is
	// closed with H3_INTERNAL_ERROR and none of its requests are served.
	ConnContext func(ctx context.Context, conn *quic.Conn) (context.Context, error)

	// ReadTimeout bounds how long reading a request's header section may
	// take. Zero means no limit.
	ReadTimeout time.Duration

	// WriteTimeout bounds how long a request may take, from the start of
	// reading it to the end of writing its response. Zero means no limit.
	WriteTimeout time.Duration

	// MaxHeaderBytes limits a request's header section. Zero means
	// DefaultMaxHeaderBytes.
	MaxHeaderBytes int

	// ErrorLog logs errors from serving connections. Nil means the log
	// package's standard logger.
	ErrorLog *log.Logger

	closing atomic.Bool
	mu      sync.Mutex
	ep      *quic.Endpoint
}

// Serve accepts connections from ep and serves them until ep is closed or
// Shutdown is called. After Shutdown, it returns http.ErrServerClosed.
func (s *Server) Serve(ep *quic.Endpoint) error {
	s.mu.Lock()
	s.ep = ep
	s.mu.Unlock()
	for {
		conn, err := ep.Accept(context.Background())
		if err != nil {
			if s.closing.Load() {
				return http.ErrServerClosed
			}
			return err
		}
		go s.serveConn(conn)
	}
}

// Shutdown closes the endpoint given to Serve, closing its connections, and
// waits until their peers acknowledge that or ctx is done.
func (s *Server) Shutdown(ctx context.Context) error {
	s.closing.Store(true)
	s.mu.Lock()
	ep := s.ep
	s.mu.Unlock()
	if ep == nil {
		return nil
	}
	return ep.Close(ctx)
}

func (s *Server) logf(format string, args ...any) {
	if s.ErrorLog != nil {
		s.ErrorLog.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func (s *Server) maxHeaderBytes() int {
	if s.MaxHeaderBytes > 0 {
		return s.MaxHeaderBytes
	}
	return DefaultMaxHeaderBytes
}

// abortConn closes conn with an HTTP/3 error code.
func abortConn(conn *quic.Conn, code uint64, reason string) {
	conn.Abort(&quic.ConnectionCloseError{Code: code, Reason: reason})
}

func (s *Server) serveConn(conn *quic.Conn) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if s.ConnContext != nil {
		var err error
		ctx, err = s.ConnContext(ctx, conn)
		if err != nil {
			s.logf("h3: closing connection from %s: %s", conn.RemoteAddr(), err)
			abortConn(conn, errCodeInternal, "")
			return
		}
	}

	// Our control stream carries an empty SETTINGS frame: every setting we
	// care about, the QPACK dynamic table capacity above all, has the
	// default of zero that we want.
	ctrl, err := conn.NewSendOnlyStream(ctx)
	if err != nil {
		abortConn(conn, errCodeInternal, "")
		return
	}
	ctrl.Write(appendFrameHeader([]byte{streamControl}, frameSettings, 0))
	ctrl.Flush()

	cs := &connState{conn: conn}
	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		if st.IsReadOnly() {
			go s.serveUniStream(cs, st)
		} else {
			go s.serveRequest(ctx, conn, st)
		}
	}
}

// connState is what a connection's streams share.
type connState struct {
	conn        *quic.Conn
	sawControl  atomic.Bool
	sawEncoder  atomic.Bool
	sawDecoder  atomic.Bool
	sawSettings atomic.Bool
}

func (s *Server) serveUniStream(cs *connState, st *quic.Stream) {
	typ, err := readVarint(st)
	if err != nil {
		st.CloseRead()
		return
	}
	switch typ {
	case streamControl:
		if cs.sawControl.Swap(true) {
			abortConn(cs.conn, errCodeStreamCreation, "second control stream")
			return
		}
		if err := readControlStream(st); err != nil {
			var he *h3Error
			if errors.As(err, &he) {
				abortConn(cs.conn, he.code, he.msg)
			}
		}
	case streamPush:
		// Only servers push.
		abortConn(cs.conn, errCodeStreamCreation, "push stream from a client")
	case streamQPACKEncoder, streamQPACKDecoder:
		seen := &cs.sawEncoder
		if typ == streamQPACKDecoder {
			seen = &cs.sawDecoder
		}
		if seen.Swap(true) {
			abortConn(cs.conn, errCodeStreamCreation, "second QPACK stream")
			return
		}
		// With a dynamic table capacity of zero, nothing a peer can say on
		// these streams changes how we decode or encode, so we drop it.
		io.Copy(io.Discard, st)
	default:
		// RFC 9114 Section 6.2: a stream of an unknown type is aborted.
		st.StopSending(errCodeStreamCreation)
	}
}

// readControlStream reads the peer's control stream until it ends. It
// returns an *h3Error for what is a connection error.
func readControlStream(st *quic.Stream) error {
	first := true
	for {
		typ, n, err := readFrameHeader(st)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return &h3Error{errCodeClosedCriticalStream, "control stream closed"}
			}
			return err
		}
		if first && typ != frameSettings {
			return &h3Error{errCodeMissingSettings, "control stream did not start with SETTINGS"}
		}
		if !first && typ == frameSettings {
			return &h3Error{errCodeFrameUnexpected, "second SETTINGS frame"}
		}
		first = false
		switch {
		case typ == frameData, typ == frameHeaders, typ == framePushPromise, isReservedHTTP2Frame(typ):
			return &h3Error{errCodeFrameUnexpected, fmt.Sprintf("frame type %#x on the control stream", typ)}
		}
		// SETTINGS, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH and unknown frames ask
		// nothing of a server that keeps no table, pushes nothing and serves
		// each request on its own.
		if err := discard(st, n); err != nil {
			return &h3Error{errCodeFrame, "truncated frame on the control stream"}
		}
	}
}

func (s *Server) serveRequest(connCtx context.Context, conn *quic.Conn, st *quic.Stream) {
	ctx, cancel := context.WithCancel(connCtx)
	defer cancel()
	if s.WriteTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, s.WriteTimeout)
		defer cancel()
	}
	st.SetWriteContext(ctx)
	readCtx := ctx
	if s.ReadTimeout > 0 {
		var readCancel context.CancelFunc
		readCtx, readCancel = context.WithTimeout(ctx, s.ReadTimeout)
		defer readCancel()
	}
	st.SetReadContext(readCtx)

	req, err := s.readRequest(ctx, conn, st)
	if err != nil {
		var he *h3Error
		switch {
		case errors.As(err, &he) && he.code == errCodeFrameUnexpected:
			abortConn(conn, he.code, he.msg)
		case errors.As(err, &he):
			st.StopSending(he.code)
			st.Reset(he.code)
		default:
			st.StopSending(errCodeRequestIncomplete)
			st.Reset(errCodeRequestIncomplete)
		}
		return
	}
	// The body is read with the request's whole time limit, not the header
	// section's.
	st.SetReadContext(ctx)

	w := &responseWriter{st: st, req: req, header: make(http.Header)}
	defer func() {
		if v := recover(); v != nil {
			st.StopSending(errCodeInternal)
			st.Reset(errCodeInternal)
			if v == http.ErrAbortHandler {
				return
			}
			buf := make([]byte, 64<<10)
			buf = buf[:runtime.Stack(buf, false)]
			s.logf("h3: panic serving %s: %v\n%s", conn.RemoteAddr(), v, buf)
		}
	}()
	s.Handler.ServeHTTP(w, req)
	w.finish()
}

// readRequest reads a request's header section and returns the request,
// whose Body reads the rest of the stream.
func (s *Server) readRequest(ctx context.Context, conn *quic.Conn, st *quic.Stream) (*http.Request, error) {
	maxBytes := s.maxHeaderBytes()
	var block []byte
	for block == nil {
		typ, n, err := readFrameHeader(st)
		if err != nil {
			return nil, err
		}
		switch {
		case typ == frameHeaders:
			// A field section is never smaller than its encoding, so an
			// encoding over the limit decodes to more than it.
			if n > uint64(maxBytes) {
				return nil, &h3Error{errCodeExcessiveLoad, "header section too large"}
			}
			block = make([]byte, n)
			if _, err := io.ReadFull(st, block); err != nil {
				return nil, err
			}
		case typ == frameData, typ == frameSettings, typ == frameGoAway, typ == frameMaxPushID,
			typ == frameCancelPush, typ == framePushPromise, isReservedHTTP2Frame(typ):
			return nil, &h3Error{errCodeFrameUnexpected, fmt.Sprintf("frame type %#x before a request's HEADERS", typ)}
		default:
			if err := discard(st, n); err != nil {
				return nil, err
			}
		}
	}
	fields, err := decodeFieldSection(block, maxBytes)
	if err != nil {
		if errors.Is(err, errHeaderTooLarge) {
			return nil, &h3Error{errCodeExcessiveLoad, "header section too large"}
		}
		// RFC 9204 Section 2.2.3 makes a decoding error a connection error,
		// but our decoder holds no state that a bad section could corrupt,
		// so failing only this request is enough.
		return nil, &h3Error{errCodeQPACKDecompression, err.Error()}
	}

	req, err := newRequest(fields)
	if err != nil {
		return nil, &h3Error{errCodeMessage, err.Error()}
	}
	req.RemoteAddr = conn.RemoteAddr().String()
	tlsState := conn.ConnectionState()
	req.TLS = &tlsState
	req.Body = &bodyReader{st: st}
	return req.WithContext(ctx), nil
}

// connectionSpecific are the header fields RFC 9114 Section 4.2 forbids.
var connectionSpecific = map[string]bool{
	"connection":        true,
	"keep-alive":        true,
	"proxy-connection":  true,
	"transfer-encoding": true,
	"upgrade":           true,
}

// newRequest makes a request from its decoded header section, checking it as
// RFC 9114 Sections 4.2 and 4.3 say.
func newRequest(fields []headerField) (*http.Request, error) {
	var method, scheme, authority, path string
	h := make(http.Header)
	pseudoDone := false
	for _, f := range fields {
		if strings.HasPrefix(f.Name, ":") {
			if pseudoDone {
				return nil, errors.New("pseudo-header after a header field")
			}
			var p *string
			switch f.Name {
			case ":method":
				p = &method
			case ":scheme":
				p = &scheme
			case ":authority":
				p = &authority
			case ":path":
				p = &path
			default:
				return nil, fmt.Errorf("unknown pseudo-header %q", f.Name)
			}
			if *p != "" {
				return nil, fmt.Errorf("repeated pseudo-header %q", f.Name)
			}
			*p = f.Value
			continue
		}
		pseudoDone = true
		if !httpguts.ValidHeaderFieldName(f.Name) || strings.ToLower(f.Name) != f.Name {
			return nil, fmt.Errorf("invalid header field name %q", f.Name)
		}
		if !httpguts.ValidHeaderFieldValue(f.Value) {
			return nil, fmt.Errorf("invalid value for header field %q", f.Name)
		}
		if connectionSpecific[f.Name] || (f.Name == "te" && f.Value != "trailers") {
			return nil, fmt.Errorf("connection-specific header field %q", f.Name)
		}
		h.Add(http.CanonicalHeaderKey(f.Name), f.Value)
	}
	if method == "" || scheme == "" || path == "" {
		return nil, errors.New("missing :method, :scheme or :path")
	}
	if method == http.MethodConnect {
		return nil, errors.New("CONNECT is not supported")
	}
	if cookies := h.Values("Cookie"); len(cookies) > 1 {
		// RFC 9114 Section 4.2.1.
		h.Set("Cookie", strings.Join(cookies, "; "))
	}
	host := h.Get("Host")
	h.Del("Host")
	if authority == "" {
		authority = host
	}
	if authority == "" {
		return nil, errors.New("no :authority or Host")
	}
	u, err := url.ParseRequestURI(path)
	if err != nil {
		return nil, fmt.Errorf("bad :path: %s", err)
	}
	contentLength := int64(-1)
	if cl := h.Get("Content-Length"); cl != "" {
		contentLength, err = strconv.ParseInt(cl, 10, 64)
		if err != nil || contentLength < 0 {
			return nil, errors.New("bad content-length")
		}
	}
	return &http.Request{
		Method:        method,
		URL:           u,
		Proto:         "HTTP/3.0",
		ProtoMajor:    3,
		Header:        h,
		Host:          authority,
		RequestURI:    path,
		ContentLength: contentLength,
	}, nil
}

// bodyReader reads the DATA frames of a request or response stream.
type bodyReader struct {
	st        *quic.Stream
	remaining uint64 // left in the current DATA frame
	done      bool
	err       error
}

func (b *bodyReader) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	for b.remaining == 0 {
		if b.done {
			b.err = io.EOF
			return 0, io.EOF
		}
		typ, n, err := readFrameHeader(b.st)
		if err != nil {
			b.err = err
			return 0, err
		}
		switch {
		case typ == frameData:
			b.remaining = n
		case typ == frameHeaders:
			// Trailers end the message. We don't use them.
			if err := discard(b.st, n); err != nil {
				b.err = err
				return 0, err
			}
			b.done = true
		case typ == frameSettings, typ == frameGoAway, typ == frameMaxPushID,
			typ == frameCancelPush, typ == framePushPromise, isReservedHTTP2Frame(typ):
			b.err = &h3Error{errCodeFrameUnexpected, fmt.Sprintf("frame type %#x in a message body", typ)}
			return 0, b.err
		default:
			if err := discard(b.st, n); err != nil {
				b.err = err
				return 0, err
			}
		}
	}
	if uint64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.st.Read(p)
	b.remaining -= uint64(n)
	if err == io.EOF {
		if b.remaining != 0 {
			err = io.ErrUnexpectedEOF
		} else {
			b.done = true
			err = nil
		}
	}
	if err != nil {
		b.err = err
	}
	return n, err
}

func (b *bodyReader) Close() error { return nil }

// responseWriter writes a response as a HEADERS frame and DATA frames.
type responseWriter struct {
	st          *quic.Stream
	req         *http.Request
	header      http.Header
	wroteHeader bool
	status      int
	err         error
	buf         []byte
}

var (
	_ http.ResponseWriter = (*responseWriter)(nil)
	_ http.Flusher        = (*responseWriter)(nil)
)

func (w *responseWriter) Header() http.Header { return w.header }

func (w *responseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	if code < 100 || code > 999 {
		panic(fmt.Sprintf("h3: invalid WriteHeader code %v", code))
	}
	if code == http.StatusSwitchingProtocols {
		// RFC 9114 Section 4.5: HTTP/3 has no 101.
		code = http.StatusInternalServerError
	}
	informational := code < 200
	if !informational {
		w.wroteHeader = true
		w.status = code
		if w.header.Get("Date") == "" {
			w.header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
		}
	}
	w.writeHeaders(code)
}

func (w *responseWriter) writeHeaders(code int) {
	fields := []headerField{{":status", strconv.Itoa(code)}}
	keys := make([]string, 0, len(w.header))
	for k := range w.header {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		name := strings.ToLower(k)
		if connectionSpecific[name] || !httpguts.ValidHeaderFieldName(name) {
			continue
		}
		for _, v := range w.header[k] {
			if !httpguts.ValidHeaderFieldValue(v) {
				continue
			}
			fields = append(fields, headerField{name, v})
		}
	}
	block := appendFieldSection(nil, fields)
	w.buf = appendFrameHeader(w.buf[:0], frameHeaders, uint64(len(block)))
	w.buf = append(w.buf, block...)
	w.write(w.buf)
}

func (w *responseWriter) write(b []byte) {
	if w.err != nil {
		return
	}
	_, w.err = w.st.Write(b)
}

func (w *responseWriter) bodyAllowed() bool {
	return w.req.Method != http.MethodHead &&
		w.status != http.StatusNoContent && w.status != http.StatusNotModified
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		if w.header.Get("Content-Type") == "" && w.header.Get("Content-Encoding") == "" && len(p) > 0 {
			w.header.Set("Content-Type", http.DetectContentType(p))
		}
		w.WriteHeader(http.StatusOK)
	}
	if !w.bodyAllowed() {
		if w.req.Method == http.MethodHead {
			return len(p), nil
		}
		return 0, http.ErrBodyNotAllowed
	}
	if w.err != nil {
		return 0, w.err
	}
	if len(p) == 0 {
		return 0, nil
	}
	w.buf = appendFrameHeader(w.buf[:0], frameData, uint64(len(p)))
	w.write(w.buf)
	w.write(p)
	if w.err != nil {
		return 0, w.err
	}
	return len(p), nil
}

// Flush sends what has been written so far.
func (w *responseWriter) Flush() { w.FlushError() }

// FlushError sends what has been written so far.
func (w *responseWriter) FlushError() error {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.err != nil {
		return w.err
	}
	return w.st.Flush()
}

// finish ends the response after the handler returns.
func (w *responseWriter) finish() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	// RFC 9114 Section 4.1: a server with a complete response may stop
	// reading the request with H3_NO_ERROR. That does nothing when the
	// request has already ended, which is the usual case for a GET.
	w.st.StopSending(errCodeNoError)
	if w.err != nil {
		w.st.Reset(errCodeInternal)
		return
	}
	// CloseWrite sends the rest of the buffer and the end of the stream
	// without waiting for the peer's acknowledgement. The connection stays
	// open, so QUIC still resends what is lost.
	w.st.CloseWrite()
}
