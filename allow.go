package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type originAllower struct {
	m map[string]struct{}
}

func newOriginAllower(allowedDomains []string) (*originAllower, error) {
	oa := &originAllower{m: make(map[string]struct{})}
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
	if (origin == "" && referrer == "") || len(oa.m) == 0 {
		return "", true
	}
	if origin != "" {
		d, err := effectiveDomain(origin)
		if err != nil {
			return "", false
		}
		_, originOK := oa.m[d]
		return d, originOK
	}
	if referrer != "" {
		d, err := effectiveDomain(referrer)
		if err != nil {
			return "", false
		}
		_, referrerOK := oa.m[d]
		return d, referrerOK
	}

	return "", false
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
