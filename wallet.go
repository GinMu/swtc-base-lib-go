package wallet

import (
	"errors"

	"github.com/GinMu/swtc-base-lib-go/constant"
	"github.com/GinMu/swtc-base-lib-go/crypto/secp256k1"
	"github.com/GinMu/swtc-base-lib-go/utils"
)

// Wallet strcut
type Wallet struct {
	priv   *secp256k1.PrivateKey
	secret string
}

// IsValidAddress validate address is valid or not
func IsValidAddress(address string) bool {
	if address == "" {
		return false
	}

	_, err := utils.DecodeBase58(constant.SWTCAccountPrefix, address)
	if err != nil {
		return false
	}
	return true
}

// IsValidSecret validate secret is valid or not
func IsValidSecret(secret string) bool {
	if secret == "" {
		return false
	}

	keyPair := &secp256k1.Secp256KeyPair{}
	_, err := keyPair.DeriveKeyPair(secret)
	if nil != err {
		return false
	}

	return true
}

// Generate wallet
func Generate() (*Wallet, error) {
	keyPair := &secp256k1.Secp256KeyPair{}
	secret, err := keyPair.GenerateSeed()
	if err != nil {
		return nil, err
	}

	return FromSecret(secret)
}

// FromSecret generate wallet by secret
func FromSecret(secret string) (*Wallet, error) {
	if secret == "" {
		return nil, errors.New("Secret cannot be empty")
	}
	keyPair := &secp256k1.Secp256KeyPair{}
	priv, err := keyPair.DeriveKeyPair(secret)
	if nil != err {
		return nil, err
	}
	wallet := new(Wallet)
	wallet.priv = priv
	wallet.secret = secret
	return wallet, nil
}

// GetPublicKey get public key
func (wallet *Wallet) GetPublicKey() string {
	return wallet.priv.PublicKey.BytesToHex()
}

// GetSecret get secret
func (wallet *Wallet) GetSecret() string {
	return wallet.secret
}

// GetAddress get address
func (wallet *Wallet) GetAddress() string {
	return wallet.priv.PublicKey.ToAddress()
}
