package crypto

import "github.com/GinMu/swtc-base-lib-go/crypto/secp256k1"

// KeyPair interface
type KeyPair interface {
	DeriveKeyPair(secret string) (*secp256k1.PrivateKey, error)
	CheckAddress(address string) bool
	GenerateSeed() (string, error)
}
