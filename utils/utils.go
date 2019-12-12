package utils

import (
	"errors"

	"github.com/GinMu/swtc-base-lib-go/constant"
	"github.com/mr-tron/base58"
)

func bufCat0(item1 uint8, buf2 []byte) []byte {
	var buf []byte
	buf = append(buf, item1)
	buf = append(buf, buf2...)
	return buf
}

func bufCat1(buf1 []byte, buf2 []byte) []byte {
	var buf []byte
	buf = append(buf, buf1...)
	buf = append(buf, buf2...)
	return buf
}

// EncodeBase58 encode bytes to string
func EncodeBase58(version uint8, bytes []byte) string {
	buffer := bufCat0(version, bytes)
	checksum := Sha256Util(Sha256Util(buffer))[0:4]
	ret := bufCat1(buffer, checksum)
	encodedString := base58.EncodeAlphabet(ret, constant.SWTCAlphabet)
	return encodedString
}

// DecodeBase58 decode string to bytes
func DecodeBase58(version uint8, input string) (decodedBytes []byte, err error) {
	decodedBytes, err = base58.DecodeAlphabet(input, constant.SWTCAlphabet)
	if err != nil || decodedBytes[0] != version || len(decodedBytes) < 5 {
		err = errors.New("invalid input size")
		return
	}

	computed := Sha256Util(Sha256Util(decodedBytes[0 : len(decodedBytes)-4]))[0:4]
	checksum := decodedBytes[len(decodedBytes)-4:]

	for i := 0; i != 4; i++ {
		if computed[i] != checksum[i] {
			err = errors.New("invalid checksum")
			return
		}
	}

	decodedBytes = decodedBytes[1 : len(decodedBytes)-4]

	return
}

// DecodeAddress convert address to bytes
func DecodeAddress(address string) ([]byte, error) {
	decodedBytes, err := DecodeBase58(constant.SWTCAccountPrefix, address)
	if err != nil {
		return nil, err
	}

	return decodedBytes, nil
}
