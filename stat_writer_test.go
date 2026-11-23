package main

import (
	"expvar"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestStatWriterResponseController checks that http.ResponseController can
// reach the underlying ResponseWriter through statWriter.
func TestStatWriterResponseController(t *testing.T) {
	stats := newStatusStats(new(expvar.Map).Init())
	rec := httptest.NewRecorder()
	sw := &statWriter{w: rec, stats: stats}
	if err := http.NewResponseController(sw).Flush(); err != nil {
		t.Fatalf("Flush through statWriter: %s", err)
	}
	if !rec.Flushed {
		t.Errorf("underlying ResponseWriter was not flushed")
	}
}
