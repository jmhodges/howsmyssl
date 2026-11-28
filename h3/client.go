package h3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"

	"golang.org/x/net/quic"
)

// ClientConn is a minimal HTTP/3 client on one QUIC connection. It exists to
// test Server and the handlers behind it: it sends requests without bodies
// and reads whole responses.
type ClientConn struct {
	conn *quic.Conn
}

// NewClientConn opens the client's control stream on conn and starts
// dropping what the server sends on its own unidirectional streams.
func NewClientConn(ctx context.Context, conn *quic.Conn) (*ClientConn, error) {
	ctrl, err := conn.NewSendOnlyStream(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := ctrl.Write(appendFrameHeader([]byte{streamControl}, frameSettings, 0)); err != nil {
		return nil, err
	}
	if err := ctrl.Flush(); err != nil {
		return nil, err
	}
	go func() {
		for {
			st, err := conn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			go io.Copy(io.Discard, st)
		}
	}()
	return &ClientConn{conn: conn}, nil
}

// RoundTrip sends req, which must have no body, and returns the response.
// The response's Body reads the rest of the stream.
func (c *ClientConn) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	st, err := c.conn.NewStream(ctx)
	if err != nil {
		return nil, err
	}
	st.SetReadContext(ctx)
	st.SetWriteContext(ctx)
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	fields := []headerField{
		{":method", req.Method},
		{":scheme", "https"},
		{":authority", host},
		{":path", req.URL.RequestURI()},
	}
	for k, vs := range req.Header {
		for _, v := range vs {
			fields = append(fields, headerField{strings.ToLower(k), v})
		}
	}
	block := appendFieldSection(nil, fields)
	b := appendFrameHeader(nil, frameHeaders, uint64(len(block)))
	b = append(b, block...)
	if _, err := st.Write(b); err != nil {
		return nil, err
	}
	if err := st.CloseWrite(); err != nil {
		return nil, err
	}

	for {
		typ, n, err := readFrameHeader(st)
		if err != nil {
			return nil, err
		}
		if typ != frameHeaders {
			if err := discard(st, n); err != nil {
				return nil, err
			}
			continue
		}
		if n > DefaultMaxHeaderBytes {
			return nil, errHeaderTooLarge
		}
		block := make([]byte, n)
		if _, err := io.ReadFull(st, block); err != nil {
			return nil, err
		}
		fields, err := decodeFieldSection(block, DefaultMaxHeaderBytes)
		if err != nil {
			return nil, err
		}
		resp, err := newResponse(fields)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 200 {
			continue
		}
		resp.Request = req
		resp.Body = &bodyReader{st: st}
		return resp, nil
	}
}

func newResponse(fields []headerField) (*http.Response, error) {
	if len(fields) == 0 || fields[0].Name != ":status" {
		return nil, errors.New("h3: response without :status first")
	}
	code, err := strconv.Atoi(fields[0].Value)
	if err != nil || code < 100 || code > 999 {
		return nil, fmt.Errorf("h3: bad :status %q", fields[0].Value)
	}
	h := make(http.Header)
	for _, f := range fields[1:] {
		if strings.HasPrefix(f.Name, ":") {
			return nil, fmt.Errorf("h3: pseudo-header %q in a response", f.Name)
		}
		h.Add(textproto.CanonicalMIMEHeaderKey(f.Name), f.Value)
	}
	resp := &http.Response{
		Status:        fields[0].Value + " " + http.StatusText(code),
		StatusCode:    code,
		Proto:         "HTTP/3.0",
		ProtoMajor:    3,
		Header:        h,
		ContentLength: -1,
	}
	if cl := h.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil {
			resp.ContentLength = n
		}
	}
	return resp, nil
}
