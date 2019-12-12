package secp256k1

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/GinMu/swtc-base-lib-go/utils"
	"github.com/mr-tron/base58"

	"golang.org/x/crypto/ripemd160"
)

var (
	ec EllipticCurve
)

func init() {
	ec.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	ec.A, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000000", 16)
	ec.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	ec.G.X, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	ec.G.Y, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	ec.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	ec.H, _ = new(big.Int).SetString("01", 16)
}

// Secp256KeyPair strcut
type Secp256KeyPair struct{}

// PublicKey represents a Bitcoin public key.
type PublicKey struct {
	Point
}

// PrivateKey represents a Bitcoin private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

func derivePrivateKey(seed []byte) *big.Int {
	privateGen := scalarMultiple(seed)
	publickGen := ec.ScalarBaseMult(privateGen).Compression()
	pb := scalarMultipleDiscrim(publickGen, 0)
	return addMod(pb, privateGen, ec.N)
}

// DeriveKeyPair derive keypair by secret with alphabet and seedfix
func (*Secp256KeyPair) DeriveKeyPair(secret string, alphabet *base58.Alphabet, seedfix uint8) (*PrivateKey, error) {
	decodedBytes, err := base58.DecodeAlphabet(secret, alphabet)
	if err != nil || decodedBytes[0] != seedfix || len(decodedBytes) < 5 {
		err = fmt.Errorf("invalid input size")
		return nil, err
	}
	var priv PrivateKey
	entropy := decodedBytes[1 : len(decodedBytes)-4]
	priv.D = derivePrivateKey(entropy)
	Q := ec.ScalarBaseMult(priv.D)
	priv.X = Q.X
	priv.Y = Q.Y
	return &priv, nil
}

// GenerateSeed generate secret with alphabet & seedfix
func (*Secp256KeyPair) GenerateSeed(alphabet *base58.Alphabet, seedfix uint8) (string, error) {
	seedBytes := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, seedBytes)
	if err != nil {
		return "", err
	}
	return utils.EncodeBase58(alphabet, seedfix, seedBytes), nil
}

// CheckAddress validate address is valid or not with alphabet & account prefix
func (*Secp256KeyPair) CheckAddress(address string, alphabet *base58.Alphabet, accountPrefix uint8) bool {
	_, err := utils.DecodeBase58(alphabet, accountPrefix, address)

	if err != nil {
		return false
	}

	return true
}

// ToBytes convert to 33 bytes public key
func (pub *PublicKey) ToBytes() (b []byte) {
	x := pub.X.Bytes()

	paddedx := append(bytes.Repeat([]byte{0x00}, 32-len(x)), x...)

	if pub.Y.Bit(0) == 0 {
		return append([]byte{0x02}, paddedx...)
	}

	return append([]byte{0x03}, paddedx...)
}

// ToBytes convert private key to 32 bytes
func (priv *PrivateKey) ToBytes() (b []byte) {
	d := priv.D.Bytes()

	/* Pad D to 32 bytes */
	paddedD := append(bytes.Repeat([]byte{0x00}, 32-len(d)), d...)

	return paddedD
}

// BytesToHex convert bytes to hex
func (pub *PublicKey) BytesToHex() string {
	return strings.ToUpper(hex.EncodeToString(pub.ToBytes()))
}

// ToAddress convert public key to address with alphabet & account prefix
func (pub *PublicKey) ToAddress(alphabet *base58.Alphabet, accountPrefix uint8) (address string) {
	pubBytes := pub.ToBytes()

	/* SHA256 Hash */
	sha256H := sha256.New()
	sha256H.Reset()
	sha256H.Write(pubBytes)
	pubHash1 := sha256H.Sum(nil)

	/* RIPEMD-160 Hash */
	ripemd160H := ripemd160.New()
	ripemd160H.Reset()
	ripemd160H.Write(pubHash1)
	pubHash2 := ripemd160H.Sum(nil)
	address = utils.EncodeBase58(alphabet, accountPrefix, pubHash2)

	return address
}

func scalarMultipleDiscrim(bytes []byte, discrim uint32) *big.Int {
	var privateGen *big.Int
	var i uint32
	for i = 0; i <= 0xFFFFFFFF; i++ {
		// We hash the bytes to find a 256 bit number, looping until we are sure it
		// is less than the order of the curve.
		sh512 := utils.NewSha512()
		sh512.Add(bytes)
		// If the optional discriminator index was passed in, update the hash.
		sh512.Add32(discrim)
		sh512.Add32(i)
		privateGenBytes := sh512.Finish256()
		privateGen = new(big.Int).SetBytes(privateGenBytes)
		if privateGen.Cmp(big.NewInt(0)) == 1 && privateGen.Cmp(ec.N) == -1 {
			return privateGen
		}
	}

	return privateGen
}

func scalarMultiple(bytes []byte) *big.Int {
	var privateGen *big.Int
	var i uint32
	for i = 0; i <= 0xFFFFFFFF; i++ {
		// We hash the bytes to find a 256 bit number, looping until we are sure it
		// is less than the order of the curve.
		sh512 := utils.NewSha512()
		sh512.Add(bytes)
		sh512.Add32(i)
		privateGenBytes := sh512.Finish256()
		privateGen = new(big.Int).SetBytes(privateGenBytes)
		if privateGen.Cmp(big.NewInt(0)) == 1 && privateGen.Cmp(ec.N) == -1 {
			return privateGen
		}
	}
	return privateGen
}
