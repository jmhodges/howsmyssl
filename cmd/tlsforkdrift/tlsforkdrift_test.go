package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestForkVersion(t *testing.T) {
	tests := []struct {
		imports []string
		want    string
		wantErr bool
	}{
		{[]string{"crypto/tls", "github.com/jmhodges/howsmyssl/tls1274", "net/http"}, "1.27.4", false},
		{[]string{"github.com/jmhodges/howsmyssl/tls12610"}, "1.26.10", false},
		{[]string{"github.com/jmhodges/howsmyssl/tls1300"}, "1.30.0", false},
		// Not the fork itself.
		{[]string{"github.com/jmhodges/howsmyssl/tls1274/internal/godebug"}, "", true},
		{[]string{"crypto/tls", "github.com/jmhodges/howsmyssl/howhttp"}, "", true},
		// Two forks coexist between the pull requests of a port, but the
		// main package should only ever import one.
		{[]string{"github.com/jmhodges/howsmyssl/tls1272", "github.com/jmhodges/howsmyssl/tls1274"}, "", true},
	}
	for _, tt := range tests {
		got, err := forkVersion(tt.imports)
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("forkVersion(%v) = %q, %v; want %q, error %t", tt.imports, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestNewerReleases(t *testing.T) {
	all := []string{"1.20", "1.20.1", "1.26.0", "1.26.9", "1.26.10", "1.27rc1", "1.27.0", "1.27.3", "1.27.4", "1.28rc1"}
	tests := []struct {
		base    string
		all     []string
		want    []string
		wantErr bool
	}{
		{"1.27.4", all, nil, false},
		{"1.27.3", all, []string{"1.27.4"}, false},
		// 10 is newer than 9, and the next minor line is compared too.
		{"1.26.9", all, []string{"1.26.10", "1.27.4"}, false},
		{"1.26.10", all, []string{"1.27.4"}, false},
		{"1.20", all, []string{"1.20.1", "1.27.4"}, false},
		// A release candidate is never a target.
		{"1.27.4", append(slices.Clone(all), "1.28rc2"), nil, false},
		{"1.27.4", append(slices.Clone(all), "1.28.0"), []string{"1.28.0"}, false},
		{"1.27.9", all, nil, true},
		{"1.27rc1", all, nil, true},
		{"tls1274", all, nil, true},
	}
	for _, tt := range tests {
		got, err := newerReleases(tt.base, tt.all)
		if !slices.Equal(got, tt.want) || (err != nil) != tt.wantErr {
			t.Errorf("newerReleases(%q) = %v, %v; want %v, error %t", tt.base, got, err, tt.want, tt.wantErr)
		}
	}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestChangedFiles(t *testing.T) {
	base := map[string]string{
		"crypto/tls/common.go":                       "old",
		"crypto/tls/conn.go":                         "same",
		"crypto/tls/tls.go":                          "gone in target",
		"crypto/tls/internal/fips140tls/fipstls.go":  "old",
		"crypto/internal/fips140/tls12/tls12.go":     "old",
		"crypto/internal/fips140/tls13/tls13.go":     "same",
		"crypto/tls/conn_test.go":                    "old",
		"crypto/tls/testdata/Client-TLSv12-AES128":   "old",
		"crypto/tls/fipsonly/fipsonly.go":            "old",
		"crypto/tls/defaults_boring.go":              "old",
		"crypto/x509/verify.go":                      "old",
		"crypto/internal/fips140/tls12/cast_test.go": "old",
	}
	target := map[string]string{
		"crypto/tls/common.go":                       "new",
		"crypto/tls/conn.go":                         "same",
		"crypto/tls/new.go":                          "only in target",
		"crypto/tls/internal/fips140tls/fipstls.go":  "new",
		"crypto/internal/fips140/tls12/tls12.go":     "new",
		"crypto/internal/fips140/tls13/tls13.go":     "same",
		"crypto/tls/conn_test.go":                    "new",
		"crypto/tls/testdata/Client-TLSv12-AES128":   "new",
		"crypto/tls/fipsonly/fipsonly.go":            "new",
		"crypto/tls/defaults_boring.go":              "new",
		"crypto/x509/verify.go":                      "new",
		"crypto/internal/fips140/tls12/cast_test.go": "new",
	}
	got, err := changedFiles(writeTree(t, base), writeTree(t, target))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"crypto/internal/fips140/tls12/tls12.go",
		"crypto/tls/common.go",
		"crypto/tls/internal/fips140tls/fipstls.go",
		"crypto/tls/new.go (added)",
		"crypto/tls/tls.go (removed)",
	}
	if !slices.Equal(got, want) {
		t.Errorf("changedFiles = %q, want %q", got, want)
	}

	// What the fork doesn't keep can change without the fork being behind.
	target["crypto/tls/common.go"] = "old"
	target["crypto/tls/tls.go"] = "gone in target"
	target["crypto/tls/internal/fips140tls/fipstls.go"] = "old"
	target["crypto/internal/fips140/tls12/tls12.go"] = "old"
	delete(target, "crypto/tls/new.go")
	got, err = changedFiles(writeTree(t, base), writeTree(t, target))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("changedFiles = %q, want none", got)
	}

	if _, err := changedFiles(t.TempDir(), writeTree(t, target)); err == nil {
		t.Error("changedFiles with an empty base tree: want an error, got none")
	}
}
