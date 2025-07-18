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

package internal

import (
	crand "crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onflow/crypto/common"
	"github.com/onflow/crypto/hash"
	"github.com/onflow/crypto/internal"
	"github.com/onflow/crypto/sign"
)

func TestKeyGenErrors(t *testing.T) {
	seed := make([]byte, 50)
	invalidSigAlgo := sign.SigningAlgorithm(20)
	sk, err := sign.GeneratePrivateKey(invalidSigAlgo, seed)
	assert.Nil(t, sk)
	assert.Error(t, err)
	assert.True(t, common.IsInvalidInputsError(err))
}

func TestHasherErrors(t *testing.T) {
	t.Run("nilHasher error sanity", func(t *testing.T) {
		err := common.ErrNilHasher
		invInpError := common.InvalidInputsErrorf("")
		otherError := fmt.Errorf("some error")
		assert.True(t, common.IsNilHasherError(err))
		assert.False(t, common.IsInvalidInputsError(err))
		assert.False(t, common.IsNilHasherError(invInpError))
		assert.False(t, common.IsNilHasherError(otherError))
		assert.False(t, common.IsNilHasherError(nil))
	})

	t.Run("nilHasher error sanity", func(t *testing.T) {
		err := common.InvalidHasherSizeErrorf("")
		invInpError := common.InvalidInputsErrorf("")
		otherError := fmt.Errorf("some error")
		assert.True(t, common.IsInvalidHasherSizeError(err))
		assert.False(t, common.IsInvalidInputsError(err))
		assert.False(t, common.IsInvalidHasherSizeError(invInpError))
		assert.False(t, common.IsInvalidHasherSizeError(otherError))
		assert.False(t, common.IsInvalidHasherSizeError(nil))
	})
}

// tests sign and verify are consistent for multiple generated keys and messages
func TestGenSignVerify(t *testing.T, salg sign.SigningAlgorithm, halg hash.Hasher) {
	t.Run(fmt.Sprintf("Generation/Signature/Verification for %s", salg), func(t *testing.T) {
		seed := make([]byte, sign.KeyGenSeedMinLen)
		input := make([]byte, 100)
		rand := internal.GetPRG(t)

		loops := 50
		for j := 0; j < loops; j++ {
			n, err := rand.Read(seed)
			require.Equal(t, n, sign.KeyGenSeedMinLen)
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

// tests the key generation constraints with regards to the input seed, mainly
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
		assert.True(t, common.IsInvalidInputsError(err))
		if maxLen > 0 {
			seed = make([]byte, maxLen+1)
			_, err = sign.GeneratePrivateKey(salg, seed)
			assert.Error(t, err)
			assert.True(t, common.IsInvalidInputsError(err))
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

func TestEncodeDecode(t *testing.T, salg sign.SigningAlgorithm) {
	t.Run(fmt.Sprintf("generic encode/decode for %s", salg), func(t *testing.T) {
		rand := internal.GetPRG(t)

		t.Run("happy path tests", func(t *testing.T) {
			loops := 50
			for j := 0; j < loops; j++ {
				// generate a private key
				seed := make([]byte, sign.KeyGenSeedMinLen)
				read, err := rand.Read(seed)
				require.Equal(t, read, sign.KeyGenSeedMinLen)
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
				assert.True(t, pk.Equals(pkCheck))
				pkCheckBytes := pkCheck.Encode()
				assert.Equal(t, pkBytes, pkCheckBytes)
				distinctPkBytes := distinctSk.PublicKey().Encode()
				assert.NotEqual(t, pkBytes, distinctPkBytes)

				// same for the compressed encoding
				// skip if BLS is used and compression isn't supported
				// TODO: fix properly
				//if salg == sign.BLSBLS12381 && !isG2Compressed() {
				if salg == sign.BLSBLS12381 && false {
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
			// TODO: update this to use the correct private key lengths
			skLens[sign.ECDSAP256] = 32
			skLens[sign.ECDSASecp256k1] = 32
			skLens[sign.BLSBLS12381] = 32

			bytes := make([]byte, skLens[salg]+1)
			sk, err := sign.DecodePrivateKey(salg, bytes)
			require.Error(t, err)
			assert.True(t, common.IsInvalidInputsError(err))
			assert.Nil(t, sk)

			// public key
			pkLens := make(map[sign.SigningAlgorithm]int)
			// TODO: update this to use the correct public key lengths
			pkLens[sign.ECDSAP256] = 64
			pkLens[sign.ECDSASecp256k1] = 64
			pkLens[sign.BLSBLS12381] = 96

			bytes = make([]byte, pkLens[salg]+1)
			pk, err := sign.DecodePublicKey(salg, bytes)
			require.Error(t, err)
			assert.True(t, common.IsInvalidInputsError(err))
			assert.Nil(t, pk)
		})
	})
}

func TestEquals(t *testing.T, salg sign.SigningAlgorithm, otherSigAlgo sign.SigningAlgorithm) {
	t.Run(fmt.Sprintf("equals for %s", salg), func(t *testing.T) {
		rand := internal.GetPRG(t)
		// generate a key pair
		seed := make([]byte, sign.KeyGenSeedMinLen)
		n, err := rand.Read(seed)
		require.Equal(t, n, sign.KeyGenSeedMinLen)
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
