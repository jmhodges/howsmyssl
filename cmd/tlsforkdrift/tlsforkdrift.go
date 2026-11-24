// tlsforkdrift says whether a Go release newer than the one our crypto/tls
// fork (./tls<goversion>/) was copied from has changed crypto/tls.
//
// Dependabot bumps the Go image and govulncheck reads the standard library,
// but neither can see a copied package, so nothing else notices when the fork
// falls behind upstream. This compares Go's own sources at the fork's version
// with Go's own sources at the newest release. It never reads the fork's
// files: what the fork changed on purpose is docs/FORKING_CRYPTO_TLS.md's
// business.
//
// It exits 0 when upstream is unchanged, 1 when it changed, and 2 when the
// check itself could not be made.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

const procedureDoc = "docs/FORKING_CRYPTO_TLS.md"

// upstreamDirs are the directories under GOROOT/src that the fork is made
// from: crypto/tls itself (which holds internal/fips140tls) and the two KDF
// packages the procedure copies into tls<ver>/internal/fips140/.
var upstreamDirs = []string{
	"crypto/tls",
	"crypto/internal/fips140/tls12",
	"crypto/internal/fips140/tls13",
}

func main() {
	base := flag.String("base", "", "Go version to compare from, like 1.27.4 (default: the version of the tls<goversion> fork the main package imports)")
	flag.Parse()
	changed, err := run(*base, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tlsforkdrift:", err)
		os.Exit(2)
	}
	if changed {
		os.Exit(1)
	}
}

func run(base string, out io.Writer) (changed bool, err error) {
	origin := "given with -base"
	if base == "" {
		origin = "which the crypto/tls fork was copied from"
		imports, err := goOutput("", "list", "-mod=vendor", "-f", `{{join .Imports "\n"}}`, "github.com/jmhodges/howsmyssl")
		if err != nil {
			return false, err
		}
		base, err = forkVersion(strings.Fields(imports))
		if err != nil {
			return false, err
		}
	}
	// Run outside the module so its vendor directory and go.mod don't get a
	// say in these lookups.
	list, err := goOutput(os.TempDir(), "list", "-m", "-versions", "go")
	if err != nil {
		return false, err
	}
	targets, err := newerReleases(base, strings.Fields(list))
	if err != nil {
		return false, err
	}
	if len(targets) == 0 {
		fmt.Fprintf(out, "Go %s, %s, is the newest Go release. Nothing to compare.\n", base, origin)
		return false, nil
	}
	baseRoot, err := goroot(base)
	if err != nil {
		return false, err
	}
	for _, target := range targets {
		targetRoot, err := goroot(target)
		if err != nil {
			return false, err
		}
		files, err := changedFiles(filepath.Join(baseRoot, "src"), filepath.Join(targetRoot, "src"))
		if err != nil {
			return false, err
		}
		if len(files) == 0 {
			fmt.Fprintf(out, "Go %s leaves crypto/tls as it was in Go %s, %s. No re-fork is needed for it.\n\n", target, base, origin)
			continue
		}
		changed = true
		fmt.Fprintf(out, "Go %s changed crypto/tls since Go %s, %s. These upstream files differ:\n\n", target, base, origin)
		for _, f := range files {
			fmt.Fprintf(out, "- `%s`\n", f)
		}
		fmt.Fprintf(out, "\nSee what changed with:\n\n```sh\nold=$(GOTOOLCHAIN=go%s go env GOROOT)/src\nnew=$(GOTOOLCHAIN=go%s go env GOROOT)/src\n", base, target)
		for _, dir := range upstreamDirs {
			fmt.Fprintf(out, "diff -ru -x testdata -x '*_test.go' $old/%s $new/%s\n", dir, dir)
		}
		fmt.Fprint(out, "```\n\n")
	}
	if changed {
		fmt.Fprintf(out, "%s is the procedure for porting the fork to a newer Go.\n", procedureDoc)
	}
	return changed, nil
}

var forkImport = regexp.MustCompile(`^github\.com/jmhodges/howsmyssl/tls1([0-9]{2})([0-9]+)$`)

// forkVersion finds the fork among the main package's imports and turns its
// name back into a Go version: tls1274 is Go 1.27.4. The name has no dots, so
// this assumes Go 1 with a two-digit minor version, which holds from Go 1.10
// to Go 1.99.
func forkVersion(imports []string) (string, error) {
	var found []string
	for _, imp := range imports {
		if m := forkImport.FindStringSubmatch(imp); m != nil {
			found = append(found, fmt.Sprintf("1.%s.%s", m[1], m[2]))
		}
	}
	if len(found) != 1 {
		return "", fmt.Errorf("want exactly one tls<goversion> fork imported by the main package, found %d: %v", len(found), found)
	}
	return found[0], nil
}

var stableRelease = regexp.MustCompile(`^([0-9]+)\.([0-9]+)(?:\.([0-9]+))?$`)

// parseRelease returns the numbers of a stable release, like 1.27.4 or 1.20.
// Release candidates and betas are not ok.
func parseRelease(v string) (nums [3]int, ok bool) {
	m := stableRelease.FindStringSubmatch(v)
	if m == nil {
		return nums, false
	}
	for i, s := range m[1:] {
		if s == "" {
			continue
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			return nums, false
		}
		nums[i] = n
	}
	return nums, true
}

// newerReleases picks, out of every Go version there is, the stable releases
// worth comparing base with: the newest one in base's own minor line, since
// that is where security fixes for it land, and the newest one overall. They
// are often the same release. It returns none when base is the newest.
func newerReleases(base string, all []string) ([]string, error) {
	b, ok := parseRelease(base)
	if !ok {
		return nil, fmt.Errorf("%q is not a stable Go release like 1.27.4", base)
	}
	if !slices.Contains(all, base) {
		return nil, fmt.Errorf("Go %s is not among the %d Go versions the go command lists", base, len(all))
	}
	newestInLine, newest := b, b
	names := map[[3]int]string{}
	for _, v := range all {
		n, ok := parseRelease(v)
		if !ok {
			continue
		}
		names[n] = v
		if slices.Compare(n[:], newest[:]) > 0 {
			newest = n
		}
		if n[0] == b[0] && n[1] == b[1] && n[2] > newestInLine[2] {
			newestInLine = n
		}
	}
	var targets []string
	for _, n := range [][3]int{newestInLine, newest} {
		if n != b && !slices.Contains(targets, names[n]) {
			targets = append(targets, names[n])
		}
	}
	return targets, nil
}

// goroot returns the GOROOT of the given Go version. The go command downloads
// that toolchain if it has to, and a toolchain comes with its src directory.
func goroot(version string) (string, error) {
	cmd := exec.Command("go", "env", "GOROOT")
	cmd.Dir = os.TempDir()
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=go"+version)
	out, err := output(cmd)
	return strings.TrimSpace(out), err
}

func goOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	return output(cmd)
}

func output(cmd *exec.Cmd) (string, error) {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%s: %w: %s", strings.Join(cmd.Args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

// skipped reports whether the procedure's step A1 deletes this file or
// directory from the fork. A change to one of them can't put the fork behind.
func skipped(name string, isDir bool) bool {
	if isDir {
		return name == "testdata" || name == "fipsonly"
	}
	return strings.HasSuffix(name, "_test.go") || name == "defaults_boring.go"
}

// changedFiles lists the files under upstreamDirs that differ between two
// GOROOT/src trees, or that only one of them has.
func changedFiles(baseSrc, targetSrc string) ([]string, error) {
	base, err := readTree(baseSrc)
	if err != nil {
		return nil, err
	}
	target, err := readTree(targetSrc)
	if err != nil {
		return nil, err
	}
	var changed []string
	for name, content := range base {
		other, ok := target[name]
		if !ok {
			changed = append(changed, name+" (removed)")
		} else if !bytes.Equal(content, other) {
			changed = append(changed, name)
		}
	}
	for name := range target {
		if _, ok := base[name]; !ok {
			changed = append(changed, name+" (added)")
		}
	}
	slices.Sort(changed)
	return changed, nil
}

func readTree(src string) (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, dir := range upstreamDirs {
		root := filepath.Join(src, filepath.FromSlash(dir))
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// A release that doesn't have one of these directories at
				// all shows up as its files being added or removed.
				if path == root && errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			if skipped(d.Name(), d.IsDir()) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(src, path)
			if err != nil {
				return err
			}
			files[filepath.ToSlash(rel)] = content
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no crypto/tls sources under %s", src)
	}
	return files, nil
}
