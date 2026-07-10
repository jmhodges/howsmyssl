// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls12

import (
	"crypto/hmac"
	"hash"
)

// PRF implements the TLS 1.2 pseudo-random function, as defined in RFC 5246,
// Section 5.
func PRF[H hash.Hash](h func() H, secret []byte, label string, seed []byte, keyLen int) []byte {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	result := make([]byte, keyLen)
	pHash(h, result, secret, labelAndSeed)
	return result
}

// pHash implements the P_hash function, as defined in RFC 5246, Section 5.
func pHash[H hash.Hash](h func() H, result, secret, seed []byte) {
	mac := hmac.New(func() hash.Hash { return h() }, secret)
	mac.Write(seed)
	a := mac.Sum(nil)

	for len(result) > 0 {
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		b := mac.Sum(nil)
		n := copy(result, b)
		result = result[n:]

		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
	}
}

const masterSecretLength = 48
const extendedMasterSecretLabel = "extended master secret"

// MasterSecret implements the TLS 1.2 extended master secret derivation, as
// defined in RFC 7627.
func MasterSecret[H hash.Hash](h func() H, preMasterSecret, transcript []byte) []byte {
	return PRF(h, preMasterSecret, extendedMasterSecretLabel, transcript, masterSecretLength)
}
