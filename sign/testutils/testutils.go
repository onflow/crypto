/*
 * Flow Crypto
 *
 * Copyright Flow Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package testutils

import (
	crand "crypto/rand"
	"fmt"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onflow/crypto/hash"
	"github.com/onflow/crypto/sign"
)

const (
	KeyGenSeedMinLen = 32
	KeyGenSeedMaxLen = 256
)

func GetPRG(t *testing.T) *mrand.Rand {
	random := time.Now().UnixNano()
	t.Logf("rng seed is %d", random)
	rng := mrand.New(mrand.NewSource(random))
	return rng
}

func TestGenSignVerify(t *testing.T, salg sign.SigningAlgorithm, halg hash.Hasher) {
	t.Run(fmt.Sprintf("Generation/Signature/Verification for %s", salg), func(t *testing.T) {
		seed := make([]byte, KeyGenSeedMinLen)
		input := make([]byte, 100)
		rand := GetPRG(t)

		loops := 50
		for j := 0; j < loops; j++ {
			n, err := rand.Read(seed)
			require.Equal(t, n, KeyGenSeedMinLen)
			require.NoError(t, err)
			sk, err := sign.GeneratePrivateKey(salg, seed)
			require.NoError(t, err)
			_, err = rand.Read(input)
			require.NoError(t, err)
			s, err := sk.Sign(input, halg)
			require.NoError(t, err)
			pk := sk.PublicKey()

			// test a valid signature
			result, err := pk.Verify(s, input, halg)
			require.NoError(t, err)
			assert.True(t, result)

			// test with a different message
			input[0] ^= 1
			result, err = pk.Verify(s, input, halg)
			require.NoError(t, err)
			assert.False(t, result)
			input[0] ^= 1

			// test with a valid but different key
			seed[0] ^= 1
			wrongSk, err := sign.GeneratePrivateKey(salg, seed)
			require.NoError(t, err)
			result, err = wrongSk.PublicKey().Verify(s, input, halg)
			require.NoError(t, err)
			assert.False(t, result)

			// test a wrong signature length
			invalidLen := rand.Intn(2 * len(s)) // try random invalid lengths
			if invalidLen == len(s) {           // map to an invalid length
				invalidLen = 0
			}
			invalidSig := make([]byte, invalidLen)
			result, err = pk.Verify(invalidSig, input, halg)
			require.NoError(t, err)
			assert.False(t, result)
		}
	})
}

// the seed length constraints and the result determinicity.
func TestKeyGenSeed(t *testing.T, salg sign.SigningAlgorithm, minLen int, maxLen int) {
	t.Run("seed length check", func(t *testing.T) {
		// valid seed lengths
		seed := make([]byte, minLen)
		_, err := sign.GeneratePrivateKey(salg, seed)
		assert.NoError(t, err)
		if maxLen > 0 {
			seed = make([]byte, maxLen)
			_, err = sign.GeneratePrivateKey(salg, seed)
			assert.NoError(t, err)
		}
		// invalid seed lengths
		seed = make([]byte, minLen-1)
		_, err = sign.GeneratePrivateKey(salg, seed)
		assert.Error(t, err)
		if maxLen > 0 {
			seed = make([]byte, maxLen+1)
			_, err = sign.GeneratePrivateKey(salg, seed)
			assert.Error(t, err)
		}
	})

	t.Run("deterministic generation", func(t *testing.T) {
		// same seed results in the same key
		seed := make([]byte, minLen)
		read, err := crand.Read(seed)
		require.Equal(t, read, minLen)
		require.NoError(t, err)
		sk1, err := sign.GeneratePrivateKey(salg, seed)
		require.NoError(t, err)
		sk2, err := sign.GeneratePrivateKey(salg, seed)
		require.NoError(t, err)
		assert.True(t, sk1.Equals(sk2))
		// different seed results in a different key
		seed[0] ^= 1 // alter a seed bit
		sk2, err = sign.GeneratePrivateKey(salg, seed)
		require.NoError(t, err)
		assert.False(t, sk1.Equals(sk2))
	})
}

var BLS12381Order = []byte{0x73, 0xED, 0xA7, 0x53, 0x29, 0x9D, 0x7D, 0x48, 0x33, 0x39,
	0xD8, 0x08, 0x09, 0xA1, 0xD8, 0x05, 0x53, 0xBD, 0xA4, 0x02, 0xFF, 0xFE,
	0x5B, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01}

func TestEncodeDecode(t *testing.T, salg sign.SigningAlgorithm) {
	t.Run(fmt.Sprintf("generic encode/decode for %s", salg), func(t *testing.T) {
		rand := GetPRG(t)

		t.Run("happy path tests", func(t *testing.T) {
			loops := 50
			for j := 0; j < loops; j++ {
				// generate a private key
				seed := make([]byte, KeyGenSeedMinLen)
				read, err := rand.Read(seed)
				require.Equal(t, read, KeyGenSeedMinLen)
				require.NoError(t, err)
				sk, err := sign.GeneratePrivateKey(salg, seed)
				assert.Nil(t, err)
				seed[0] ^= 1 // alter the seed to get a new private key
				distinctSk, err := sign.GeneratePrivateKey(salg, seed)
				require.NoError(t, err)

				// check private key encoding
				skBytes := sk.Encode()
				skCheck, err := sign.DecodePrivateKey(salg, skBytes)
				require.Nil(t, err)
				if !sk.Equals(skCheck) {
					t.Logf("Private key mismatch: original=%x, decoded=%x", sk.Encode(), skCheck.Encode())
					t.Logf("Original algorithm: %v, Decoded algorithm: %v", sk.Algorithm(), skCheck.Algorithm())
					t.Logf("Original size: %d, Decoded size: %d", sk.Size(), skCheck.Size())
				}
				assert.True(t, sk.Equals(skCheck))
				skCheckBytes := skCheck.Encode()
				assert.Equal(t, skBytes, skCheckBytes)
				distinctSkBytes := distinctSk.Encode()
				assert.NotEqual(t, skBytes, distinctSkBytes)

				// check public key encoding
				pk := sk.PublicKey()
				pkBytes := pk.Encode()
				pkCheck, err := sign.DecodePublicKey(salg, pkBytes)
				require.Nil(t, err)
				if !pk.Equals(pkCheck) {
					t.Logf("Public key mismatch: original=%x, decoded=%x", pk.Encode(), pkCheck.Encode())
				}
				assert.True(t, pk.Equals(pkCheck))
				pkCheckBytes := pkCheck.Encode()
				assert.Equal(t, pkBytes, pkCheckBytes)
				distinctPkBytes := distinctSk.PublicKey().Encode()
				assert.NotEqual(t, pkBytes, distinctPkBytes)

				// same for the compressed encoding
				// skip if BLS is used and compression isn't supported
				if salg == sign.BLSBLS12381 {
					continue
				} else {
					pkComprBytes := pk.EncodeCompressed()
					pkComprCheck, err := sign.DecodePublicKeyCompressed(salg, pkComprBytes)
					require.Nil(t, err)
					assert.True(t, pk.Equals(pkComprCheck))
					pkCheckComprBytes := pkComprCheck.EncodeCompressed()
					assert.Equal(t, pkComprBytes, pkCheckComprBytes)
					distinctPkComprBytes := distinctSk.PublicKey().EncodeCompressed()
					assert.NotEqual(t, pkComprBytes, distinctPkComprBytes)
				}
			}
		})

		// test invalid private and public keys (invalid length)
		t.Run("invalid key length", func(t *testing.T) {
			// private key
			skLens := make(map[sign.SigningAlgorithm]int)
			skLens[sign.ECDSAP256] = 32
			skLens[sign.ECDSASecp256k1] = 32
			skLens[sign.BLSBLS12381] = 32

			bytes := make([]byte, skLens[salg]+1)
			sk, err := sign.DecodePrivateKey(salg, bytes)
			require.Error(t, err)
			assert.Nil(t, sk)

			// public key
			pkLens := make(map[sign.SigningAlgorithm]int)
			pkLens[sign.ECDSAP256] = 64
			pkLens[sign.ECDSASecp256k1] = 64
			pkLens[sign.BLSBLS12381] = 96

			bytes = make([]byte, pkLens[salg]+1)
			pk, err := sign.DecodePublicKey(salg, bytes)
			require.Error(t, err)
			assert.Nil(t, pk)
		})
	})
}

func TestEquals(t *testing.T, salg sign.SigningAlgorithm, otherSigAlgo sign.SigningAlgorithm) {
	t.Run(fmt.Sprintf("equals for %s", salg), func(t *testing.T) {
		rand := GetPRG(t)
		// generate a key pair
		seed := make([]byte, KeyGenSeedMinLen)
		n, err := rand.Read(seed)
		require.Equal(t, n, KeyGenSeedMinLen)
		require.NoError(t, err)

		// first pair
		sk1, err := sign.GeneratePrivateKey(salg, seed)
		require.NoError(t, err)
		pk1 := sk1.PublicKey()

		// second pair without changing the seed
		sk2, err := sign.GeneratePrivateKey(salg, seed)
		require.NoError(t, err)
		pk2 := sk2.PublicKey()

		// unrelated algo pair
		sk3, err := sign.GeneratePrivateKey(otherSigAlgo, seed)
		require.NoError(t, err)
		pk3 := sk3.PublicKey()

		// fourth pair with same algo but a different seed
		seed[0] ^= 1
		sk4, err := sign.GeneratePrivateKey(salg, seed)
		require.NoError(t, err)
		pk4 := sk4.PublicKey()

		// tests
		assert.True(t, sk1.Equals(sk2))
		assert.True(t, pk1.Equals(pk2))
		assert.False(t, sk1.Equals(sk3))
		assert.False(t, pk1.Equals(pk3))
		assert.False(t, sk1.Equals(sk4))
		assert.False(t, pk1.Equals(pk4))
	})
}

func TestKeysAlgorithm(t *testing.T, sk sign.PrivateKey, salg sign.SigningAlgorithm) {
	t.Run(fmt.Sprintf("key.Algorithm for %s", salg), func(t *testing.T) {
		alg := sk.Algorithm()
		assert.Equal(t, alg, salg)
		alg = sk.PublicKey().Algorithm()
		assert.Equal(t, alg, salg)
	})
}

func TestKeySize(t *testing.T, sk sign.PrivateKey, skLen int, pkLen int) {
	t.Run(fmt.Sprintf("key.Size for %s", sk.Algorithm()), func(t *testing.T) {
		size := sk.Size()
		assert.Equal(t, size, skLen)
		size = sk.PublicKey().Size()
		assert.Equal(t, size, pkLen)
	})
}

func BenchVerify(b *testing.B, algo sign.SigningAlgorithm, halg hash.Hasher) {
	b.Run(fmt.Sprintf("verify %s", algo), func(b *testing.B) {
		seed := make([]byte, 48)
		for j := 0; j < len(seed); j++ {
			seed[j] = byte(j)
		}
		sk, err := sign.GeneratePrivateKey(algo, seed)
		require.NoError(b, err)
		pk := sk.PublicKey()

		input := []byte("Bench input")
		s, err := sk.Sign(input, halg)
		require.NoError(b, err)
		var result bool

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			result, err = pk.Verify(s, input, halg)
			require.NoError(b, err)
		}
		// sanity check
		require.True(b, result)

		b.StopTimer()
	})
}

func BenchSign(b *testing.B, algo sign.SigningAlgorithm, halg hash.Hasher) {
	b.Run(fmt.Sprintf("Single sign %s", algo), func(b *testing.B) {
		seed := make([]byte, 48)
		for j := 0; j < len(seed); j++ {
			seed[j] = byte(j)
		}
		sk, err := sign.GeneratePrivateKey(algo, seed)
		require.NoError(b, err)

		input := []byte("Bench input")
		var signature []byte

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			signature, err = sk.Sign(input, halg)
			require.NoError(b, err)
		}
		// sanity check
		result, err := sk.PublicKey().Verify(signature, input, halg)
		require.NoError(b, err)
		require.True(b, result)

		b.StopTimer()
	})
}
