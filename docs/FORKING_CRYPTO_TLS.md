# Forking Go's `crypto/tls` for howsmyssl

This document records exactly what was changed to turn Go 1.26.2's standard
`crypto/tls` package into the vendored `./tls1262/` package, so that future
versions of Go can be forked the same way.

The naming convention is `tls<goversion>`: Go **1.26.2** → package directory
`tls1262`. A future fork of Go 1.27.0 would live in `tls1270`, of 1.26.3 in
`tls1263`, and so on. The import path everywhere is
`github.com/jmhodges/howsmyssl/tls1262` (rename the last path element to match
the new directory).

## Why the fork exists

howsmyssl needs data about the client's TLS handshake that the standard library
does not expose: the raw ClientHello (offered cipher suites, compression
methods, supported versions/curves/signature algorithms, session-ticket
support) and a heuristic for whether the client performs BEAST
(1/n-1 record splitting) mitigation. It also needs to *drive* client behavior in
tests (override the `signature_algorithms` extension). None of this is reachable
through the public API, so the package is copied wholesale and edited in place.

The changes fall into two buckets:

* **Bucket A — mechanical porting** to make the copied package compile outside
  `GOROOT` (it can no longer reach `internal/…` and `crypto/internal/…`
  packages, BoringCrypto, or the FIPS module internals). These changes carry no
  behavioral intent; they are re-applied verbatim each version.
* **Bucket B — howsmyssl features**, the actual reason for the fork. Every one
  of these edits is tagged with a `// Added for howsmyssl's use` comment so it
  can be found with grep after re-copying upstream.

---

## Bucket A — Mechanical porting (repeat every version)

### A1. Copy the package, drop what doesn't belong

Copy `GOROOT/src/crypto/tls/*` into `tls<ver>/`, then **delete**:

* every `*_test.go` file (the fork is not tested against upstream's suite),
* `testdata/` (only used by the tests),
* `fipsonly/` (the `crypto/tls/fipsonly` subpackage),
* `defaults_boring.go` (the BoringCrypto build variant — the fork never builds
  under `GOEXPERIMENT=boringcrypto`).

Everything else (`alert.go`, `auth.go`, `cache.go`, `common.go`, `conn.go`,
`ech.go`, `handshake_*.go`, `key_agreement.go`, `key_schedule.go`, `prf.go`,
`quic.go`, `ticket.go`, `tls.go`, `cipher_suites.go`, `generate_cert.go`,
`common_string.go`, `bogo_config.json`) is kept. `common_string.go` is the
`stringer`-generated file and is kept as-is — no regeneration is needed because
the fork adds no new values to the stringed types.

### A2. Remove the boringcrypto build constraint from `defaults_fips140.go`

Because `defaults_boring.go` is deleted, its counterpart must always compile.
Delete the two leading lines:

```go
//go:build !boringcrypto

```

### A3. Vendor four `internal` packages under `tls<ver>/internal/`

Upstream's `crypto/tls` reaches into packages that are unimportable from a
normal module. Recreate them locally:

| Local path | Upstream origin | Treatment |
|---|---|---|
| `internal/godebug/` | `internal/godebug` | **Replaced with a ~14-line no-op stub.** `New` returns a named `*Setting`; `Value()` returns `""`; `IncNonDefault()` does nothing. Result: every GODEBUG knob takes its default. |
| `internal/fips140tls/` | `crypto/tls/internal/fips140tls` | **Copied verbatim** (it only imports the public `crypto/fips140`). |
| `internal/fips140/tls12/` | `crypto/internal/fips140/tls12` | Copied, then rewritten to drop FIPS internals (see A4). |
| `internal/fips140/tls13/` | `crypto/internal/fips140/tls13` | Copied, then rewritten to drop FIPS internals (see A4). |

### A4. Rewrite the two FIPS KDF packages to use public crypto

The copied `tls12` and `tls13` KDF packages import FIPS-module internals that
don't exist outside `GOROOT`. Rewrite them to the public standard library and
strip the FIPS service-indicator bookkeeping:

* **`internal/fips140/tls13/tls13.go`**
  * `crypto/internal/fips140/hkdf` → `crypto/hkdf`
  * `crypto/internal/fips140deps/byteorder` → `encoding/binary`
    (`byteorder.BEAppendUint16(...)` → `binary.BigEndian.AppendUint16(...)`)
  * `hkdf.Expand`/`hkdf.Extract` now return `(result, error)` instead of a bare
    value, so wrap each call and `panic("tls13: hkdf.Expand: " + err.Error())`
    on error.
  * Drop the FIPS IG comments; rename the shadowed `hash` param to `h`.
* **`internal/fips140/tls12/tls12.go`**
  * `crypto/internal/fips140/hmac` → `crypto/hmac`
  * Delete `crypto/internal/fips140`, `.../sha256`, `.../sha512` imports and the
    entire `RecordNonApproved()` / digest-type `switch` in `MasterSecret` — it
    just calls `PRF` directly now.
  * `hmac.New` wants a `func() hash.Hash`; the internal version took the generic
    `func() H` directly, so wrap it: `hmac.New(func() hash.Hash { return h() }, secret)`.
    Rename the local hmac variable from `h` to `mac` to avoid colliding with the
    renamed `h` hash constructor.

### A5. De-internalize `cipher_suites.go`

`cipher_suites.go` pulls in BoringCrypto and FIPS AES internals. Replace them
with public equivalents:

* Drop imports `crypto/internal/boring`, `crypto/internal/fips140/aes` (aliased
  `fipsaes`), and `crypto/internal/fips140/aes/gcm`.
* `internal/cpu` → `golang.org/x/sys/cpu` (adds a dependency on
  `golang.org/x/sys`, already in `go.mod`).
* `macSHA1`: the `boring.Enabled` branch that skips the constant-time hash
  collapses to `return hmac.New(newConstantTimeHash(sha1.New), key)`.
* `aeadAESGCM` and `aeadAESGCMTLS13`: the `boring.Enabled ? boring.NewGCMTLS…`
  vs `gcm.NewGCMForTLS1x(aes.(*fipsaes.Block))` fork collapses to plain
  `cipher.NewGCM(aes)`.
* Delete the stray `boring.Unreachable()` call left in the TLS 1.3 path.

### A6. Rewrite remaining internal imports throughout

In the top-level `.go` files, rewrite every remaining internal import to the
fork path or a public one:

* `internal/godebug` → `github.com/jmhodges/howsmyssl/tls<ver>/internal/godebug`
  (in `tls.go`, `defaults.go`, `common.go`, `conn.go`, `handshake_client.go`)
* `crypto/internal/fips140/tls12` → `.../tls<ver>/internal/fips140/tls12`
  (in `prf.go`)
* `crypto/internal/fips140/tls13` → `.../tls<ver>/internal/fips140/tls13`
  (in `key_schedule.go`, `handshake_client.go`, `handshake_client_tls13.go`,
  `handshake_server_tls13.go`)
* `crypto/tls/internal/fips140tls` → `.../tls<ver>/internal/fips140tls`
  (in `common.go`, `handshake_server.go`, `handshake_client.go`,
  `handshake_server_tls13.go`)
* In `handshake_server_tls13.go`, `internal/byteorder` → `encoding/binary`
  (`byteorder.LEUint32(ageAdd)` → `binary.LittleEndian.Uint32(ageAdd)`).

> Note: only the imports actually present in a given file need rewriting; the
> lists above reflect the 1.26.2 layout and may shift slightly between versions.
> After copying, `go build ./tls<ver>/...` will surface any import that still
> points at an unreachable `internal/…` path.

---

## Bucket B — howsmyssl feature edits (the point of the fork)

All of these are marked `// Added for howsmyssl's use`. After re-copying a new
upstream version, re-apply each edit and confirm the surrounding upstream code
hasn't moved out from under it.

### B1. Expose ClientHello data on `ConnectionState` (`common.go`)

Add fields to the exported `ConnectionState` struct:

```go
// Added for howsmyssl's use
ClientCipherSuites               []uint16
CompressionMethods               []uint8
NMinusOneRecordSplittingDetected bool
AbleToDetectNMinusOneSplitting   bool
SessionTicketsSupported          bool
SupportedVersions                []uint16
SupportedCurves                  []CurveID
SupportedSignatureAlgorithms     []SignatureScheme
EncryptedClientHelloOffered      bool
```

### B2. Add a client-side `signature_algorithms` override (`common.go`)

Add an exported field to `Config`:

```go
// Added for howsmyssl's use.
//
// SignatureAlgorithms, if non-nil, overrides the contents of the
// signature_algorithms extension (13) the client sends in its ClientHello.
// The list is written verbatim — no filtering by TLS version or FIPS mode —
// so callers can exercise GREASE values, draft codepoints, and
// otherwise-disabled schemes. Setting this on a server Config has no effect.
SignatureAlgorithms []SignatureScheme
```

### B3. Capture the ClientHello and detect BEAST splitting (`conn.go`)

* Add unexported fields to the `Conn` struct:

  ```go
  // Added for howsmyssl's use
  clientHello                      *clientHelloMsg
  ableToDetectNMinusOneSplitting   bool
  readOneAppDataRecord             bool
  nMinusOneRecordSplittingDetected bool
  ```

* In the record-reading path (`handleRenegotiation`/`readRecord` area, right
  after a record is decoded), record whether the **first** application-data
  record is 0 or 1 bytes long — the fingerprint of 1/n-1 BEAST mitigation:

  ```go
  if !c.readOneAppDataRecord && c.ableToDetectNMinusOneSplitting && typ == recordTypeApplicationData {
      c.readOneAppDataRecord = true
      c.nMinusOneRecordSplittingDetected = len(data) == 1 || len(data) == 0
  }
  ```

* In `ConnectionState()` (where the `state` value is assembled), copy the
  captured ClientHello fields and the BEAST flags into the exported struct:

  ```go
  if c.clientHello != nil {
      state.ClientCipherSuites = ... copy of c.clientHello.cipherSuites
      state.CompressionMethods = ... copy of c.clientHello.compressionMethods
      state.SessionTicketsSupported        = c.clientHello.ticketSupported
      state.SupportedVersions              = c.clientHello.supportedVersions
      state.SupportedCurves                = ... copy of c.clientHello.supportedCurves
      state.SupportedSignatureAlgorithms   = ... copy of c.clientHello.supportedSignatureAlgorithms
      state.EncryptedClientHelloOffered    = len(c.clientHello.encryptedClientHello) != 0
  }
  state.AbleToDetectNMinusOneSplitting = c.ableToDetectNMinusOneSplitting
  state.NMinusOneRecordSplittingDetected = c.nMinusOneRecordSplittingDetected
  ```

  The `EncryptedClientHelloOffered` line works for both the ECH cases the
  server can see: a client the server can't decrypt (or GREASE) leaves the
  outer extension body on the stashed hello, and an accepted ECH swaps in
  the decrypted inner hello, whose field holds the 1-byte inner marker —
  non-empty either way.

### B4. Server-side capture, resumption disable, BEAST cipher pick (`handshake_server.go`)

* Stash the incoming ClientHello on the conn as soon as it's read:
  `c.clientHello = clientHello`.
* Disable session resumption for TLS ≤ 1.0 so the full-handshake cipher-selection
  path (and thus BEAST detectability) always runs:

  ```go
  // Disallow resumption when client is at TLS 1.0 or below so that
  // we can be sure the checks for HasBeastVulnSuites is set correctly.
  if c.vers <= VersionTLS10 {
      hs.sessionState = nil
  }
  ```

* In cipher-suite selection (`pickCipherSuite`), for TLS 1.0 clients prefer a CBC
  suite the client offered so the connection is BEAST-observable, and set
  `c.ableToDetectNMinusOneSplitting = true` when one is chosen (loop over
  `TLS_RSA_WITH_AES_128_CBC_SHA`, `…_AES_256_CBC_SHA`, `…_AES_128_CBC_SHA256`).

### B5. Honor the `signature_algorithms` override (`handshake_client.go`)

Where the client sets `hello.supportedSignatureAlgorithms`, branch on the new
Config field:

```go
if config.SignatureAlgorithms != nil {
    hello.supportedSignatureAlgorithms = slices.Clone(config.SignatureAlgorithms)
} else {
    hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms(minVersion)
}
```

### B6. Add a client-side `encrypted_client_hello` override (`common.go`, `handshake_client.go`)

Add an exported field to `Config`:

```go
// Added for howsmyssl's use.
//
// EncryptedClientHelloOverride, if non-empty, is written verbatim as the
// body of the encrypted_client_hello extension (0xfe0d) in the client's
// ClientHello, without engaging the client's real ECH machinery — no inner
// hello is built and server acceptance is never checked, mimicking a
// GREASE ECH extension. It is ignored when EncryptedClientHelloConfigList
// is set, and the bytes must parse as a well-formed ECHClientHello or
// servers will abort the handshake. Setting this on a server Config has
// no effect.
EncryptedClientHelloOverride []byte
```

In `makeClientHello` (`handshake_client.go`), extend the
`if c.config.EncryptedClientHelloConfigList != nil` block that builds the
real ECH context with an else branch, just before the final return:

```go
} else if len(config.EncryptedClientHelloOverride) > 0 {
    // Added for howsmyssl's use. See Config.EncryptedClientHelloOverride.
    hello.encryptedClientHello = slices.Clone(config.EncryptedClientHelloOverride)
}
```

This exists so tests can exercise ECH detection: a client doing real ECH via
`EncryptedClientHelloConfigList` fails its own handshake with
`ECHRejectionError` when the server has no ECH keys, while the override
sends the extension and then proceeds like any non-ECH client. The
client-side ECH assertions all key off the `echClientContext` (nil here) or
off the server echoing the extension, so nothing else engages.

---

## Step-by-step procedure for the next version

Split the port across **three PRs** so each one is reviewable on its own and
maps onto the two buckets above: the first adds the new `tls<XYZ>` package
with *only* the mechanical Bucket A porting (so it can be verified purely by
diffing against upstream), the second applies the Bucket B feature edits and
switches the consumers over in the same change (the consumers are what
exercise the new fields, so the tests validate the features in the PR that
introduces them), and the third deletes the old package. The old and new
forks coexist between PRs; nothing imports the new package until PR 2 lands.

### PR 1 — add the new `tls<XYZ>` package (Bucket A only)

1. Pick the target Go version `X.Y.Z`; the new package dir is `tls<XYZ>`
   (e.g. `go1.27.0` → `tls1270`).
2. `GOTOOLCHAIN=goX.Y.Z go version` to fetch the toolchain, then copy
   `$(go env GOROOT)/src/crypto/tls/` into `./tls<XYZ>/`.
3. Delete the files listed in **A1** (the upstream tests, `testdata/`,
   `fipsonly/`, and the BoringCrypto build variant).
4. Apply the mechanical porting edits **A2–A6** (build tag, vendored internals,
   `cipher_suites.go`, import rewrites). Use the *new* package name in every
   rewritten import path.
5. Verify with `go build ./tls<XYZ>/...` (a clean build confirms every
   internal import was rewritten) and the diff-verify procedure below. At
   this stage every hunk must be an import rewrite or one of the A2–A5
   edits — there are no `// Added for howsmyssl's use` blocks yet, and any
   other difference from upstream is a mistake. Do **not** apply the Bucket B
   edits or change any consumers in this PR — the diff is purely additive and
   carries no behavioral intent.

### PR 2 — apply the feature edits and switch consumers (Bucket B)

1. Re-apply the feature edits **B1–B6** to the new package. The fastest way
   to find the anchor points is `grep -rn "Added for howsmyssl's use"
   tls1262/` in the *previous* fork and port each hunk.
2. Update the consumers. Don't rely on a fixed file list — grep the repo for
   the old package name (`grep -rn "tls<old>\|TLS<old>" --include="*.go" .`,
   excluding the fork directory itself and `vendor/`) and rename every hit:
   import paths and aliases (`tls "github.com/jmhodges/howsmyssl/tls<XYZ>"`
   in `client_info.go`, `howsmyssl.go`, `reloader.go`, `tls_test.go`, and
   throughout `howhttp/` and `howhttp/httptest/`), identifiers derived from
   the package name (e.g. `ClientTLS<old>Config` in `howhttp/httptest`), and
   doc comments. Also update the README's "fork of Go X.Y.Z's crypto/tls"
   line and directory reference.
3. `go build ./...` and `go test ./...`. The howsmyssl tests exercise the
   exposed fields, so a green run here is the real validation of the port.

### PR 3 — remove the old `tls<old>` package

1. Delete the old `tls<old>` directory.
2. Confirm nothing still references it
   (`grep -rn "tls<old>" --include="*.go" .` should be empty), then
   `go build ./...` and `go test ./...` once more.

### Shortcut for patch-level bumps

This shortcut speeds up the copy-and-port work; the PR split itself stays the
same. Note that files copied from the previous fork carry the Bucket B edits
with them — if you use this shortcut, strip the `// Added for howsmyssl's
use` hunks from those files for PR 1 and restore them in PR 2, so PR 1 stays
purely mechanical. When the old and new Go versions are close
(e.g. 1.26.2 → 1.26.5), diff the two upstream trees first:

```sh
diff -rq $(GOTOOLCHAIN=go<old> go env GOROOT)/src/crypto/tls \
         $(GOTOOLCHAIN=go<new> go env GOROOT)/src/crypto/tls
```

Files upstream did *not* touch can be copied straight from the previous fork
(they already contain all A and B edits) — only the upstream-changed files
need the porting treatment above, and only if they're among the files the
fork modifies. Check `crypto/internal/fips140/tls12` and `tls13` in the same
way before assuming the vendored internal packages carry over. For the
1.26.2 → 1.26.5 bump, upstream changed only `handshake_messages.go` (taken
verbatim; the fork doesn't modify it) and `key_schedule.go` (one import
rewrite per **A6**; upstream added `crypto/fips140.WithoutEnforcement` calls,
which are public API and need no porting). Finish with the diff-verify step
below either way.

## How to diff-verify a fork against upstream

To confirm a fork contains *only* the intended changes, diff it against the
matching upstream toolchain:

```sh
UP="$(go env GOROOT)/src/crypto/tls"     # with GOTOOLCHAIN=goX.Y.Z
for f in tls1262/*.go; do
    b=$(basename "$f")
    diff "$UP/$b" "$f"    # every hunk should be an import rewrite or a
                          # "// Added for howsmyssl's use" block
done
```

What this should show depends on where you are in the PR sequence: on the
PR 1 branch every hunk is a Bucket A edit (import rewrites and the A2–A5
changes) and there are no `// Added for howsmyssl's use` blocks; after PR 2
the Bucket B feature hunks appear as well.

Under Go 1.26.2 exactly twelve top-level files differ from upstream —
`cipher_suites.go`, `common.go`, `conn.go`, `defaults.go`,
`defaults_fips140.go`, `handshake_client.go`, `handshake_client_tls13.go`,
`handshake_server.go`, `handshake_server_tls13.go`, `key_schedule.go`,
`prf.go`, `tls.go` — and each hunk is accounted for above. Any *other* diff in
a future port is something to review, not to accept blindly.
