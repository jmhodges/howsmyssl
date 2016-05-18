package main

import (
	"encoding/json"
	"expvar"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	// FIXME vendorize this
	"google.golang.org/cloud/logging"

	topk "github.com/dgryski/go-topk"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jwt"
)

type originAllower struct {
	m        map[string]struct{}
	ns       *expvar.Map
	hostname string
	gclog    logClient

	mu                 *sync.RWMutex
	topKAllDomains     *topk.Stream
	topKOfflistDomains *topk.Stream
}

// FIXME flush on shutdown
type logClient interface {
	Log(logging.Entry) error
	Flush() error
}

func newOriginAllower(allowedDomains []string, hostname string, gclog logClient, ns *expvar.Map) (*originAllower, error) {
	mu := &sync.RWMutex{}
	topKAllDomains := topk.New(100)
	topKOfflistDomains := topk.New(100)
	lifetime := new(expvar.Map).Init()
	ns.Set("lifetime", lifetime)
	lifetime.Set("top_all_domains", expvar.Func(func() interface{} {
		mu.RLock()
		defer mu.RUnlock()
		return topKAllDomains.Keys()
	}))
	lifetime.Set("top_offlist_domains", expvar.Func(func() interface{} {
		mu.RLock()
		defer mu.RUnlock()
		return topKOfflistDomains.Keys()
	}))

	oa := &originAllower{
		m:                  make(map[string]struct{}),
		ns:                 ns,
		hostname:           hostname,
		gclog:              gclog,
		mu:                 mu,
		topKAllDomains:     topKAllDomains,
		topKOfflistDomains: topKOfflistDomains,
	}
	for _, d := range allowedDomains {
		if d == "localhost" {
			oa.m[d] = struct{}{}
			continue
		}
		d, err := publicsuffix.EffectiveTLDPlusOne(d)
		if err != nil {
			return nil, err
		}
		oa.m[d] = struct{}{}
	}
	return oa, nil
}

func (oa *originAllower) Allow(r *http.Request) (string, bool) {
	origin := r.Header.Get("Origin")
	referrer := r.Header.Get("Referer")

	apiKey := r.FormValue("key")
	userAgent := r.Header.Get("User-Agent")

	entry := &apiLogEntry{
		DetectedDomain: "",
		Allowed:        false,
		APIKey:         apiKey,
		Headers: headers{
			Origin:    origin,
			Referrer:  referrer,
			UserAgent: userAgent,
		},
	}
	defer func() {
		go oa.countRequest(entry)
	}()

	if origin == "" && referrer == "" {
		entry.Allowed = true
		return "", true
	}
	if origin != "" {
		domain, ok := oa.checkDomain(origin)
		entry.DetectedDomain = domain
		entry.Allowed = ok
		if !ok {
			entry.RejectionReason = rejectionConfig
		}
		return domain, ok
	}
	if referrer != "" {
		domain, ok := oa.checkDomain(referrer)
		entry.DetectedDomain = domain
		entry.Allowed = ok
		if !ok {
			entry.RejectionReason = rejectionConfig
		}
		return domain, ok
	}

	return "", false
}

// checkDomain checks if the detected domain from the request headers and
// whether domain is allowed to make requests against howsmyssl's API.
func (oa *originAllower) checkDomain(d string) (string, bool) {
	domain, err := effectiveDomain(d)
	if err != nil {
		// TODO(jmhodges): replace this len check with false when we use top-k
		return "", len(oa.m) == 0
	}
	_, ok := oa.m[domain]
	// TODO(jmhodges): remove this len check when we use top-k
	return domain, ok || len(oa.m) == 0
}

func (oa *originAllower) countRequest(entry *apiLogEntry) {
	oa.gclog.Log(logging.Entry{
		Payload: entry,
		Labels: map[string]string{
			"server_hostname": oa.hostname,
			"app":             "howsmyssl",
		},
	})

	if entry.DetectedDomain == "" {
		return
	}

	oa.mu.Lock()
	defer oa.mu.Unlock()
	oa.topKAllDomains.Insert(entry.DetectedDomain, 1)
	if !entry.Allowed {
		oa.topKOfflistDomains.Insert(entry.DetectedDomain, 1)
	}
}

func effectiveDomain(str string) (string, error) {
	u, err := url.Parse(str)
	if err != nil {
		return "", err
	}
	host := u.Host
	if host == "" {
		return "", fmt.Errorf("unparsable domain string %#v", str)
	}
	i := strings.Index(host, ":")
	if i >= 0 {
		host = host[:i]
	}

	if host == "localhost" {
		return "localhost", nil
	}
	d, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return "", err
	}
	return d, nil
}

func loadAllowedOriginsConfig(fp string) *originsConfig {
	f, err := os.Open(fp)
	if err != nil {
		log.Fatalf("unable to open allowed origins config file %#v: %s", fp, err)
	}
	defer f.Close()
	jc := &originsConfig{}
	err = json.NewDecoder(f).Decode(jc)
	if err != nil {
		log.Fatalf("unable to parse allowed origins config file %#v: %s", fp, err)
	}
	for _, a := range jc.AllowedOrigins {
		if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") {
			log.Fatalf("allowed origins config file (%#v) should have just domains without the leading scheme. That is, %#v should not have the protocol scheme at its beginning.", fp, a)
		}
	}
	return jc
}

type originsConfig struct {
	// AllowedOrigins is a slice of domains like "example.com" (that is, without the
	// leading protocol)
	AllowedOrigins []string `json:"allowed_origins"`
}

type rejectionReason string

const rejectionConfig = rejectionReason("config")

type apiLogEntry struct {
	DetectedDomain  string          `json:"detected_domain"`
	Allowed         bool            `json:"allowed"`
	APIKey          string          `json:"api_key"`
	RejectionReason rejectionReason `json:"rejection_reason"`
	Headers         headers         `json:"headers"`
}

type headers struct {
	Origin    string `json:"origin"`
	Referrer  string `json:"referrer"`
	UserAgent string `json:"user_agent"`
}

func loadGoogleServiceAccount(fp string) *googleConfig {
	bs, err := ioutil.ReadFile(fp)
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
	jwtConf, err := google.JWTConfigFromJSON(bs, logging.Scope)
	if err != nil {
		log.Fatalf("unable to parse Google service account config %#v: %s", fp, err)
	}
	c.conf = jwtConf
	return c
}

type googleConfig struct {
	ProjectID string `json:"project_id"`

	conf *jwt.Config `json:"-"`
}

var _ logClient = nullLogClient{}

type nullLogClient struct{}

func (n nullLogClient) Log(e logging.Entry) error {
	return nil
}

func (n nullLogClient) Flush() error {
	return nil
}
