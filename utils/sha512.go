package utils

import "hash"

import "crypto/sha512"

// Sha512 struct
type Sha512 struct {
	h hash.Hash
}

// NewSha512 create Sha512
func NewSha512() *Sha512 {
	s := new(Sha512)
	s.h = sha512.New()
	return s
}

// Finish sum
func (s *Sha512) Finish() []byte {
	return s.h.Sum(nil)
}

// Add write bytes
func (s *Sha512) Add(bytes []byte) (int, error) {
	return s.h.Write(bytes)
}

// Add32 write uint32
func (s *Sha512) Add32(i uint32) (int, error) {
	var b []byte
	b = append(b, byte(((i >> 24) & 0xFF)))
	b = append(b, byte(((i >> 16) & 0xFF)))
	b = append(b, byte(((i >> 8) & 0xFF)))
	b = append(b, byte((i & 0xFF)))
	return s.h.Write(b)
}

// Finish256 get 32 bytes
func (s *Sha512) Finish256() []byte {
	return s.h.Sum(nil)[0:32]
}

// Finish128 get 16 bytes
func (s *Sha512) Finish128() []byte {
	return s.h.Sum(nil)[0:16]
}
