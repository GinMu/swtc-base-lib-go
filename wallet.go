package wallet

import (
	"errors"

	"github.com/GinMu/swtc-base-lib-go/constant"
	"github.com/GinMu/swtc-base-lib-go/crypto/secp256k1"
	"github.com/GinMu/swtc-base-lib-go/utils"
	"github.com/mr-tron/base58"
)

// SWTCAlphabet definition
var SWTCAlphabet *base58.Alphabet

func init() {
	SWTCAlphabet = base58.NewAlphabet("jpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65rkm8oFqi1tuvAxyz")
}

// Wallet strcut
type Wallet struct {
	priv          *secp256k1.PrivateKey
	secret        string
	alphabet      *base58.Alphabet
	accountPrefix uint8
}

// IsValidAddress validate swtc address is valid or not
func IsValidAddress(address string) bool {
	return IsValidConsortiumAddress(address, SWTCAlphabet, constant.SWTCAccountPrefix)
}

// IsValidConsortiumAddress validate consortium chain address is valid or not
func IsValidConsortiumAddress(address string, alphabet *base58.Alphabet, accountPrefix uint8) bool {
	if address == "" {
		return false
	}

	_, err := utils.DecodeAddress(address, alphabet, accountPrefix)
	if err != nil {
		return false
	}
	return true
}

// IsValidSecret validate swtc secret is valid or not
func IsValidSecret(secret string) bool {
	return IsValidConsortiumSecret(secret, SWTCAlphabet, constant.SWTCSeedfix)
}

// IsValidConsortiumSecret validate consortium chain secret is valid or not
func IsValidConsortiumSecret(secret string, alphabet *base58.Alphabet, seedfix uint8) bool {
	if secret == "" {
		return false
	}

	keyPair := &secp256k1.Secp256KeyPair{}
	_, err := keyPair.DeriveKeyPair(secret, alphabet, seedfix)
	if nil != err {
		return false
	}

	return true
}

// Generate swtc wallet
func Generate() (*Wallet, error) {
	return GenerateConsortium(SWTCAlphabet, constant.SWTCSeedfix, constant.SWTCAccountPrefix)
}

// GenerateConsortium to generate consortium chain wallet
func GenerateConsortium(alphabet *base58.Alphabet, seedfix uint8, accountPrefix uint8) (*Wallet, error) {
	keyPair := &secp256k1.Secp256KeyPair{}
	secret, err := keyPair.GenerateSeed(alphabet, seedfix)
	if err != nil {
		return nil, err
	}

	return FromConsortiumSecret(secret, alphabet, seedfix, accountPrefix)
}

// FromSecret generate swtc wallet by secret
func FromSecret(secret string) (*Wallet, error) {
	return FromConsortiumSecret(secret, SWTCAlphabet, constant.SWTCSeedfix, constant.SWTCAccountPrefix)
}

// FromConsortiumSecret generate consortium chain wallet by secret
func FromConsortiumSecret(secret string, alphabet *base58.Alphabet, seedfix uint8, accountPrefix uint8) (*Wallet, error) {
	if secret == "" {
		return nil, errors.New("Secret cannot be empty")
	}
	keyPair := &secp256k1.Secp256KeyPair{}
	priv, err := keyPair.DeriveKeyPair(secret, alphabet, seedfix)
	if nil != err {
		return nil, err
	}
	wallet := new(Wallet)
	wallet.priv = priv
	wallet.secret = secret
	wallet.alphabet = alphabet
	wallet.accountPrefix = accountPrefix
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
	return wallet.priv.PublicKey.ToAddress(wallet.alphabet, wallet.accountPrefix)
}
