package utils

import "crypto/sha256"

// Sha256Util create sha256 and write bytes
func Sha256Util(bytes []byte) []byte {
	h := sha256.New()
	h.Write(bytes)
	return h.Sum(nil)
}
