// boring is a stub version of crypto/internal/boring that is never enabled and
// has only the types and functions needed to compile the howsmyssl fork of
// crypto/tls. Since the BoringCrypto work in Go is only experimental and not
// enabled by default, this is fine.
package boring

import "crypto/cipher"

const Enabled = false

func Unreachable() {
	// do nothing since boring is never enabled
}

func NewGCMTLS(cipher.Block) (cipher.AEAD, error) { panic("boringcrypto: not available") }
