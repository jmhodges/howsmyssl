package main

import (
	"context"
	origtls "crypto/tls"
	"encoding/json"
	"expvar"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	howhttptest "github.com/jmhodges/howsmyssl/howhttp/httptest"
	tls "github.com/jmhodges/howsmyssl/tls1274"
	ztls "github.com/zmap/zcrypto/tls"
)

// The December 14th, 2026 cutover is 10 AM in America/Los_Angeles, which is
// PST (UTC-8) on that date.
var (
	justBeforeDecemberCutover = time.Date(2026, 12, 14, 17, 59, 59, 999999999, time.UTC)
	atDecemberCutover         = time.Date(2026, 12, 14, 18, 0, 0, 0, time.UTC)
	pacific                   = time.FixedZone("PST", -8*60*60)
)

func TestDecemberCutoverConstants(t *testing.T) {
	want := time.Date(2026, 12, 14, 10, 0, 0, 0, pacific)
	if !tls12BadCutover.Equal(want) {
		t.Errorf("tls12BadCutover: want %s, got %s", want, tls12BadCutover)
	}
	if !noPQBadCutover.Equal(want) {
		t.Errorf("noPQBadCutover: want %s, got %s", want, noPQBadCutover)
	}
}

func TestDecemberCutoverBoundary(t *testing.T) {
	clients := []struct {
		name       string
		conn       func(t *testing.T) *tls.Conn
		wantBefore rating
		wantAfter  rating
	}{
		{
			name: "TLS13WithPQ",
			conn: func(t *testing.T) *tls.Conn {
				return connectZtls(t, &ztls.Config{CurvePreferences: []ztls.CurveID{0x11ec, ztls.X25519}})
			},
			wantBefore: okay,
			wantAfter:  okay,
		},
		{
			name: "TLS13NoPQ",
			conn: func(t *testing.T) *tls.Conn {
				return connect(t, &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}})
			},
			wantBefore: improvable,
			wantAfter:  bad,
		},
		{
			name: "TLS12WithPQ",
			conn: func(t *testing.T) *tls.Conn {
				return connectZtls(t, &ztls.Config{
					MaxVersion:       ztls.VersionTLS12,
					CurvePreferences: []ztls.CurveID{0x11ec, ztls.X25519},
				})
			},
			wantBefore: improvable,
			wantAfter:  bad,
		},
		{
			name: "TLS12NoPQ",
			conn: func(t *testing.T) *tls.Conn {
				return connect(t, &tls.Config{
					MaxVersion:       tls.VersionTLS12,
					CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
				})
			},
			wantBefore: improvable,
			wantAfter:  bad,
		},
		{
			name: "TLS11",
			conn: func(t *testing.T) *tls.Conn {
				return connect(t, &tls.Config{
					MinVersion:   tls.VersionTLS11,
					MaxVersion:   tls.VersionTLS11,
					CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
				})
			},
			wantBefore: improvable,
			wantAfter:  bad,
		},
	}
	instants := []struct {
		name   string
		now    time.Time
		before bool
	}{
		{"JustBefore", justBeforeDecemberCutover, true},
		{"At", atDecemberCutover, false},
		{"JustAfter", atDecemberCutover.Add(time.Nanosecond), false},
		{"JustBeforeInPacific", justBeforeDecemberCutover.In(pacific), true},
		{"AtInPacific", time.Date(2026, 12, 14, 10, 0, 0, 0, pacific), false},
		// 10 AM read as UTC instead of PT would flip eight hours early.
		{"TenAMUTC", time.Date(2026, 12, 14, 10, 0, 0, 0, time.UTC), true},
		{"MonthLater", time.Date(2027, 1, 14, 0, 0, 0, 0, time.UTC), false},
	}
	for _, cl := range clients {
		t.Run(cl.name, func(t *testing.T) {
			c := cl.conn(t)
			for _, in := range instants {
				t.Run(in.name, func(t *testing.T) {
					want := cl.wantAfter
					if in.before {
						want = cl.wantBefore
					}
					ci := pullClientInfo(c, in.now)
					if ci.Rating != want {
						t.Errorf("Rating: want %s, got %s", want, ci.Rating)
					}
					if ci.TLS12BadCutoverPassed == in.before {
						t.Errorf("TLS12BadCutoverPassed: want %t, got %t", !in.before, ci.TLS12BadCutoverPassed)
					}
					if ci.NoPQBadCutoverPassed == in.before {
						t.Errorf("NoPQBadCutoverPassed: want %t, got %t", !in.before, ci.NoPQBadCutoverPassed)
					}
					if !ci.TLS12ImprovableCutoverPassed || !ci.NoPQImprovableCutoverPassed {
						t.Errorf("June cutovers should have passed: TLS12ImprovableCutoverPassed %t, NoPQImprovableCutoverPassed %t", ci.TLS12ImprovableCutoverPassed, ci.NoPQImprovableCutoverPassed)
					}
				})
			}
		})
	}
}

// TestDecemberCutoverHandlers drives the web page, the JSON API and JSONP
// through the same mux and handlers production uses, with the rating clock
// pinned on either side of the December cutover.
func TestDecemberCutoverHandlers(t *testing.T) {
	index = loadIndex()
	origClock := ratingClock
	t.Cleanup(func() { ratingClock = origClock })

	stats := newStatusStats(new(expvar.Map).Init())
	am := &allowMaps{
		AllowTheseDomains: make(map[string]bool),
		AllowSubdomainsOn: make(map[string]bool),
		BlockedDomains:    make(map[string]bool),
	}
	ama := &atomic.Pointer[allowMaps]{}
	ama.Store(am)
	oa := newOriginAllower(ama, "testhostname", nullLogClient{}, new(expvar.Map).Init(), newTestLogger(t))
	tm := tlsMux("", "www.howsmyssl.com", "www.howsmyssl.com", makeStaticHandler(stats), handleWeb, oa, newTestLogger(t), newTestLogger(t))
	srv := howhttptest.NewServer(tm)
	defer srv.Close()

	type side struct {
		rating rating
		// Collapsed-whitespace snippets the web page must and must not hold.
		want, notWant []string
	}
	clients := []struct {
		name          string
		conf          func(*origtls.Config)
		before, after side
	}{
		{
			name: "Modern",
			conf: func(*origtls.Config) {},
			before: side{
				rating:  okay,
				want:    []string{`<span class="label okay">Good</span> Your client supports post-quantum key agreement.`},
				notWant: []string{`label bad`},
			},
			after: side{
				rating:  okay,
				want:    []string{`<span class="label okay">Good</span> Your client supports post-quantum key agreement.`},
				notWant: []string{`label bad`},
			},
		},
		{
			name: "TLS13NoPQ",
			conf: func(c *origtls.Config) { c.CurvePreferences = []origtls.CurveID{origtls.X25519} },
			before: side{
				rating: improvable,
				want: []string{
					`<span class="label improvable">Improvable</span> Your client does not support post-quantum key agreement.`,
					`clients without post-quantum key agreement are marked as Improvable. On December 14th, 2026 at 10 AM PT, they will be marked as Bad.`,
				},
				notWant: []string{`label bad`},
			},
			after: side{
				rating: bad,
				want: []string{
					`<span class="label bad">Bad</span> Your client does not support post-quantum key agreement.`,
					`As of December 14th, 2026 at 10 AM PT, clients without post-quantum key agreement are marked as Bad.`,
				},
				notWant: []string{`will be marked as Bad`, `will be marked as Improvable`},
			},
		},
		{
			name: "TLS12",
			conf: func(c *origtls.Config) { c.MaxVersion = origtls.VersionTLS12 },
			before: side{
				rating: improvable,
				want: []string{
					`<span class="label improvable">Improvable</span> Your client is using TLS 1.2.`,
					`On December 14th, 2026, TLS 1.2 clients will be marked as Bad.`,
					`<span class="label improvable">Improvable</span> Your client does not support post-quantum key agreement.`,
				},
				notWant: []string{`label bad`},
			},
			after: side{
				rating: bad,
				want: []string{
					`<span class="label bad">Bad</span> Your client is using TLS 1.2.`,
					`<span class="label bad">Bad</span> Your client does not support post-quantum key agreement.`,
					`As of December 14th, 2026 at 10 AM PT, clients without post-quantum key agreement are marked as Bad.`,
				},
				notWant: []string{`will be marked as Bad`, `will be marked as Improvable`},
			},
		},
	}

	get := func(t *testing.T, c *http.Client, path string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		r, err := http.NewRequestWithContext(ctx, "GET", srv.URL+path, nil)
		if err != nil {
			t.Fatalf("NewRequest: %s", err)
		}
		resp, err := c.Do(r)
		if err != nil {
			t.Fatalf("Get %s: %s", path, err)
		}
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll: %s", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status: want %d, got %d", path, http.StatusOK, resp.StatusCode)
		}
		return string(b)
	}
	apiRating := func(t *testing.T, body string) rating {
		t.Helper()
		var ci struct {
			Rating rating `json:"rating"`
		}
		if err := json.Unmarshal([]byte(body), &ci); err != nil {
			t.Fatalf("unmarshal %q: %s", body, err)
		}
		return ci.Rating
	}

	for _, cl := range clients {
		t.Run(cl.name, func(t *testing.T) {
			tlsConf := srv.ClientTLSConfig()
			cl.conf(tlsConf)
			c := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf, ForceAttemptHTTP2: true}}
			defer c.CloseIdleConnections()

			for _, in := range []struct {
				name string
				now  time.Time
				want side
			}{
				{"JustBefore", justBeforeDecemberCutover, cl.before},
				{"At", atDecemberCutover, cl.after},
			} {
				t.Run(in.name, func(t *testing.T) {
					ratingClock = func() time.Time { return in.now }

					if got := apiRating(t, get(t, c, "/a/check")); got != in.want.rating {
						t.Errorf("JSON rating: want %s, got %s", in.want.rating, got)
					}

					jsonp := get(t, c, "/a/check?callback=parseTLS")
					inner, ok := strings.CutPrefix(jsonp, "parseTLS(")
					if !ok {
						t.Fatalf("JSONP body: want parseTLS(...), got %q", jsonp)
					}
					inner, ok = strings.CutSuffix(inner, ");")
					if !ok {
						t.Fatalf("JSONP body: want parseTLS(...);, got %q", jsonp)
					}
					if got := apiRating(t, inner); got != in.want.rating {
						t.Errorf("JSONP rating: want %s, got %s", in.want.rating, got)
					}

					page := strings.Join(strings.Fields(get(t, c, "/")), " ")
					hero := `<span class="hero-unit-` + string(ratingSpan(in.want.rating)) + `">` + string(in.want.rating) + `</span>`
					if !strings.Contains(page, hero) {
						t.Errorf("web page: missing %q", hero)
					}
					for _, s := range in.want.want {
						if !strings.Contains(page, s) {
							t.Errorf("web page: missing %q", s)
						}
					}
					for _, s := range in.want.notWant {
						if strings.Contains(page, s) {
							t.Errorf("web page: should not contain %q", s)
						}
					}
				})
			}
		})
	}
}
