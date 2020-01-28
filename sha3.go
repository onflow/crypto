package crypto

import (
	"hash"

	"golang.org/x/crypto/sha3"
)

// sha3_256Algo, embeds commonHasher
type sha3_256Algo struct {
	*commonHasher
	hash.Hash
}

// NewSha3_256 returns a new instance of SHA3-256 hasher
func NewSha3_256() Hasher {
	return &sha3_256Algo{
		commonHasher: &commonHasher{
			algo:       SHA3_256,
			outputSize: HashLenSha3_256},
		Hash: sha3.New256()}
}

// ComputeHash calculates and returns the SHA3-256 output of input byte array
func (s *sha3_256Algo) ComputeHash(data []byte) Hash {
	s.Reset()
	_, _ = s.Write(data)
	digest := make(Hash, 0, HashLenSha3_256)
	return s.Sum(digest)
}

// SumHash returns the SHA3-256 output and resets the hash state
func (s *sha3_256Algo) SumHash() Hash {
	digest := make(Hash, HashLenSha3_256)
	s.Sum(digest[:0])
	s.Reset()
	return digest
}

// Add adds data to the state data to be hashed
func (s *sha3_256Algo) Add(data []byte) {
	_, _ = s.Write(data)
}

// sha3_384Algo, embeds commonHasher
type sha3_384Algo struct {
	*commonHasher
	hash.Hash
}

// ComputeHash calculates and returns the SHA3-256 output of input byte array
func (s *sha3_384Algo) ComputeHash(data []byte) Hash {
	s.Reset()
	_, _ = s.Write(data)
	digest := make(Hash, 0, HashLenSha3_384)
	return s.Sum(digest)
}

// SumHash returns the SHA3-256 output and resets the hash state
func (s *sha3_384Algo) SumHash() Hash {
	digest := make(Hash, HashLenSha3_384)
	s.Sum(digest[:0])
	s.Reset()
	return digest
}

// cShake128Algo, embeds commonHasher
type cShake128Algo struct {
	*commonHasher
	sha3.ShakeHash
}

// NewSha3_384 returns a new instance of SHA3-384 hasher
func NewSha3_384() Hasher {
	return &sha3_384Algo{
		commonHasher: &commonHasher{
			algo:       SHA3_384,
			outputSize: HashLenSha3_384},
		Hash: sha3.New384()}
}

// ComputeHash calculates and returns the cSHAKE-128 output of input byte array
func (s *cShake128Algo) ComputeHash(data []byte) Hash {
	s.Reset()
	_, _ = s.Write(data)
	digest := make(Hash, s.outputSize)
	s.Read(digest)
	return digest
}

// SumHash returns the cSHAKE-128 output and resets the hash state
func (s *cShake128Algo) SumHash() Hash {
	digest := make(Hash, s.outputSize)
	s.Read(digest)
	s.Reset()
	return digest
}

func (s *cShake128Algo) Size() int {
	return s.commonHasher.outputSize
}
