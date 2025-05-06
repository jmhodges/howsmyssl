package main

import (
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cloud.google.com/go/logging"

	topk "github.com/dgryski/go-topk"
	"golang.org/x/exp/slog"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
)

type originAllower struct {
	ns       *expvar.Map
	hostname string
	gclog    logClient

	ama *atomic.Pointer[allowMaps]

	metricsMu          *sync.RWMutex
	topKAllDomains     *topk.Stream
	topKOfflistDomains *topk.Stream

	errLogger *slog.Logger
}

type logClient interface {
	Log(logging.Entry)
	Flush() error
}

func newOriginAllower(ama *atomic.Pointer[allowMaps], hostname string, gclog logClient, ns *expvar.Map, allowErrLogger *slog.Logger) *originAllower {
	metricsMu := &sync.RWMutex{}
	topKAllDomains := topk.New(100)
	topKOfflistDomains := topk.New(100)
	lifetime := new(expvar.Map).Init()
	ns.Set("lifetime", lifetime)
	lifetime.Set("top_all_domains", expvar.Func(func() any {
		metricsMu.RLock()
		defer metricsMu.RUnlock()
		return topKAllDomains.Keys()
	}))
	lifetime.Set("top_offlist_domains", expvar.Func(func() any {
		metricsMu.RLock()
		defer metricsMu.RUnlock()
		return topKOfflistDomains.Keys()
	}))

	oa := &originAllower{
		ama:                ama,
		ns:                 ns,
		hostname:           hostname,
		gclog:              gclog,
		metricsMu:          metricsMu,
		topKAllDomains:     topKAllDomains,
		topKOfflistDomains: topKOfflistDomains,
		errLogger:          allowErrLogger,
	}
	return oa
}

func (oa *originAllower) Allow(r *http.Request) (string, bool) {
	origin := r.Header.Get("Origin")
	referrer := r.Header.Get("Referer")

	apiKey := r.FormValue("key")
	userAgent := r.Header.Get("User-Agent")

	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		oa.errLogger.ErrorContext(r.Context(), "error splitting RemoteAddr as host:port", "RemoteAddr", r.RemoteAddr, "err", err)
		remoteIP = "0.0.0.0"
	}
	entry := &apiLogEntry{
		DetectedDomain:     "",
		DetectedFullDomain: "",
		Allowed:            false,
		APIKey:             apiKey,
		Headers: headers{
			Origin:    origin,
			Referrer:  referrer,
			UserAgent: userAgent,
		},
	}
	defer func() {
		go oa.countRequest(entry, r, remoteIP)
	}()

	if origin == "" && referrer == "" {
		entry.Allowed = true
		return "", true
	}
	if origin != "" {
		etldplus1, fullDomain, ok := oa.checkDomain(r.Context(), origin)
		entry.DetectedDomain = etldplus1
		entry.DetectedFullDomain = fullDomain
		entry.Allowed = ok
		if !ok {
			entry.RejectionReason = rejectionConfig
		}
		return etldplus1, ok
	}
	if referrer != "" {
		etldplus1, fullDomain, ok := oa.checkDomain(r.Context(), referrer)
		entry.DetectedDomain = etldplus1
		entry.DetectedFullDomain = fullDomain
		entry.Allowed = ok
		if !ok {
			entry.RejectionReason = rejectionConfig
		}
		return etldplus1, ok
	}

	return "", false
}

// checkDomain checks if the detected domain from the request headers and
// whether domain is allowed to make requests against howsmyssl's API.
func (oa *originAllower) checkDomain(ctx context.Context, d string) (string, string, bool) {
	d = strings.ToLower(d)
	etldplus1, fullDomain, err := effectiveDomain(d)

	if err != nil {
		return "", "", false
	}
	am := oa.ama.Load()
	if am.AllowTheseDomains[fullDomain] {
		return etldplus1, fullDomain, true
	}

	if fullDomain != etldplus1 {
		dom := nextDomain(fullDomain)
		for {
			if am.AllowSubdomainsOn[dom] {
				return etldplus1, fullDomain, true
			}
			if dom == etldplus1 {
				break
			}
			dom = nextDomain(dom)
			if dom == "" {
				oa.errLogger.ErrorContext(ctx, "when fullDomain isn't eTLD+1, got an empty string domain. Bug?", "etldplus1", etldplus1, "fullDomain", fullDomain)
				break
			}
		}
	}

	dom := fullDomain
	for {
		if am.BlockedDomains[dom] {
			return etldplus1, fullDomain, false
		}
		if dom == etldplus1 {
			break
		}
		dom = nextDomain(dom)
		if dom == "" {
			oa.errLogger.ErrorContext(ctx, "when checking fullDomain, got an empty string domain. Bug?", "etldplus1", etldplus1, "fullDomain", fullDomain)
			break
		}
	}

	return etldplus1, fullDomain, true
}

func nextDomain(dom string) string {
	i := strings.Index(dom, ".")
	if i == -1 {
		return ""
	}
	ni := i + 1
	if ni == len(dom) {
		return ""
	}
	return dom[ni:]
}

func (oa *originAllower) countRequest(entry *apiLogEntry, r *http.Request, remoteIP string) {
	oa.gclog.Log(logging.Entry{
		Payload:     entry,
		HTTPRequest: &logging.HTTPRequest{Request: r, RemoteIP: remoteIP},
		Labels: map[string]string{
			"server_hostname": oa.hostname,
			"app":             "howsmyssl",
		},
	})

	if entry.DetectedDomain == "" {
		return
	}

	oa.metricsMu.Lock()
	defer oa.metricsMu.Unlock()
	oa.topKAllDomains.Insert(entry.DetectedDomain, 1)
	if !entry.Allowed {
		oa.topKOfflistDomains.Insert(entry.DetectedDomain, 1)
	}
}

func effectiveDomain(str string) (string, string, error) {
	if str == "localhost" {
		return "localhost", "localhost", nil
	}
	u, err := url.Parse(str)
	if err != nil {
		return "", "", err
	}
	host := u.Host
	if host == "" {
		return "", "", fmt.Errorf("unparsable domain string %#v", str)
	}
	h2, _, err := net.SplitHostPort(host)
	if err == nil {
		host = h2
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return host, host, nil
	}
	if host == "localhost" {
		return "localhost", "localhost", nil
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return "", "", err
	}
	return d, host, nil
}

func loadAllowMaps(fp string) (*allowMaps, error) {
	f, err := os.Open(fp)
	if err != nil {
		return nil, fmt.Errorf("unable to open allowlists config file %#v: %s", fp, err)
	}
	defer f.Close()
	al := &allowLists{}
	err = json.NewDecoder(f).Decode(al)
	if err != nil {
		return nil, fmt.Errorf("unable to parse allowlists config file %#v: %s", fp, err)
	}

	am := &allowMaps{
		AllowTheseDomains: make(map[string]bool, len(al.AllowTheseDomains)),
		AllowSubdomainsOn: make(map[string]bool, len(al.AllowSubdomainsOn)),
		BlockedDomains:    make(map[string]bool, len(al.BlockedDomains)),
	}

	for _, dom := range al.AllowTheseDomains {
		am.AllowTheseDomains[dom] = true
	}
	for _, dom := range al.AllowSubdomainsOn {
		am.AllowSubdomainsOn[dom] = true
	}
	for _, dom := range al.BlockedDomains {
		am.BlockedDomains[dom] = true
	}
	return am, nil
}

func reloadAllowMapsForever(allowListsFile string, ama *atomic.Pointer[allowMaps], tick *time.Ticker) {
	for range tick.C {
		am, err := loadAllowMaps(allowListsFile)
		if err != nil {
			log.Printf("unable to reload allowlists at %#v: %s", allowListsFile, err)
		}
		ama.Store(am)
	}
}

type rejectionReason string

const rejectionConfig = rejectionReason("config")

type apiLogEntry struct {
	DetectedDomain     string          `json:"detected_domain"`
	DetectedFullDomain string          `json:"detected_full_domain"`
	Allowed            bool            `json:"allowed"`
	APIKey             string          `json:"api_key"`
	RejectionReason    rejectionReason `json:"rejection_reason"`
	Headers            headers         `json:"headers"`
}

type headers struct {
	Origin    string `json:"origin"`
	Referrer  string `json:"referrer"`
	UserAgent string `json:"user_agent"`
}

func loadGoogleServiceAccount(fp string) *googleConfig {
	bs, err := os.ReadFile(fp)
	if err != nil {
		log.Fatalf("unable to read Google service account config %#v: %s", fp, err)
	}
	c := &googleConfig{}
	err = json.Unmarshal(bs, c)
	if err != nil {
		log.Fatalf("unable to parse project ID from Google service account config %#v: %s", fp, err)
	}
	if c.ProjectID == "" {
		log.Fatalf("blank project ID in Google service account config %#v: %s", fp, err)
	}
	jwtConf, err := google.JWTConfigFromJSON(bs, logging.WriteScope)
	if err != nil {
		log.Fatalf("unable to parse Google service account config %#v: %s", fp, err)
	}
	c.conf = jwtConf
	return c
}

type googleConfig struct {
	ProjectID string `json:"project_id"`

	conf *jwt.Config
}

var _ logClient = nullLogClient{}

type nullLogClient struct{}

func (n nullLogClient) Log(e logging.Entry) {
}

func (n nullLogClient) Flush() error {
	return nil
}

type allowLists struct {
	AllowTheseDomains []string `json:"allow_these_domains"`
	AllowSubdomainsOn []string `json:"allow_subdomains_on"`
	BlockedDomains    []string `json:"blocked_domains"`
}

type allowMaps struct {
	AllowTheseDomains map[string]bool
	AllowSubdomainsOn map[string]bool
	BlockedDomains    map[string]bool
}
