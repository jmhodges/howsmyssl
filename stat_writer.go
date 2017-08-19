package main

import (
	"bufio"
	"errors"
	"expvar"
	"net"
	"net/http"
)

var (
	_               http.Hijacker = &statWriter{}
	errNotAHijacker               = errors.New("statWriter: given ResponseWriter was not a Hijacker")
)

type statusStats struct {
	status1xx *expvar.Int
	status2xx *expvar.Int
	status3xx *expvar.Int
	status4xx *expvar.Int
	status5xx *expvar.Int
}

func newStatusStats(outer *expvar.Map) *statusStats {
	m := new(expvar.Map).Init()
	outer.Set("statuses", m)
	status1xx := &expvar.Int{}
	status2xx := &expvar.Int{}
	status3xx := &expvar.Int{}
	status4xx := &expvar.Int{}
	status5xx := &expvar.Int{}
	m.Set("1xx", status1xx)
	m.Set("2xx", status2xx)
	m.Set("3xx", status3xx)
	m.Set("4xx", status4xx)
	m.Set("5xx", status5xx)
	return &statusStats{
		status1xx,
		status2xx,
		status3xx,
		status4xx,
		status5xx,
	}
}

type statWriter struct {
	w         http.ResponseWriter
	stats     *statusStats
	writtenTo bool
}

func (sw *statWriter) WriteHeader(statusCode int) {
	switch {
	case statusCode > 499:
		sw.stats.status5xx.Add(1)
	case statusCode > 399:
		sw.stats.status4xx.Add(1)
	case statusCode > 299:
		sw.stats.status3xx.Add(1)
	case statusCode > 199:
		sw.stats.status2xx.Add(1)
	default:
		sw.stats.status1xx.Add(1)
	}
	sw.writtenTo = true
	sw.w.WriteHeader(statusCode)
}

func (sw *statWriter) Write(bs []byte) (int, error) {
	if !sw.writtenTo {
		sw.stats.status2xx.Add(1)
		sw.writtenTo = true
	}

	return sw.w.Write(bs)
}

func (sw *statWriter) Header() http.Header {
	return sw.w.Header()
}

func (sw *statWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := sw.w.(http.Hijacker)
	if !ok {
		return nil, nil, errNotAHijacker
	}
	return hj.Hijack()
}
