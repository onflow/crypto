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

package ecdsa

import (
	"encoding/hex"
	"testing"

	"crypto/elliptic"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onflow/crypto/hash"
	"github.com/onflow/crypto/sign"
	"github.com/onflow/crypto/sign/testutils"
)

var ecdsaCurves = []sign.SigningAlgorithm{
	sign.ECDSAP256,
	sign.ECDSASecp256k1,
}
var ecdsaPrKeyLen = map[sign.SigningAlgorithm]int{
	sign.ECDSAP256:      PrKeyLenECDSAP256,
	sign.ECDSASecp256k1: PrKeyLenECDSASecp256k1,
}
var ecdsaPubKeyLen = map[sign.SigningAlgorithm]int{
	sign.ECDSAP256:      PubKeyLenECDSAP256,
	sign.ECDSASecp256k1: PubKeyLenECDSASecp256k1,
}
var ecdsaSigLen = map[sign.SigningAlgorithm]int{
	sign.ECDSAP256:      SignatureLenECDSAP256,
	sign.ECDSASecp256k1: SignatureLenECDSASecp256k1,
}

func TestECDSA(t *testing.T) {
	for _, curve := range ecdsaCurves {
		t.Logf("Testing ECDSA for curve %s", curve)
		// test key generation seed limits
		testutils.TestKeyGenSeed(t, curve, KeyGenSeedMinLen, KeyGenSeedMaxLen)
		// test consistency
		halg := hash.NewSHA3_256()
		testutils.TestGenSignVerify(t, curve, halg)
		testutils.TestEncodeDecode(t, curve)
		testutils.TestEquals(t, curve, sign.BLSBLS12381)
		seed := make([]byte, KeyGenSeedMinLen)
		sk, err := sign.GeneratePrivateKey(curve, seed)
		require.NoError(t, err)
		testutils.TestKeysAlgorithm(t, sk, curve)
		testutils.TestKeySize(t, sk, ecdsaPrKeyLen[curve], ecdsaPubKeyLen[curve])
	}
}

func TestECDSAHasher(t *testing.T) {
	for _, curve := range ecdsaCurves {
		t.Logf("Testing ECDSA for curve %s", curve)
		halg := hash.NewSHA2_256()
		testutils.TestGenSignVerify(t, curve, halg)
		halg = hash.NewSHA3_256()
		testutils.TestGenSignVerify(t, curve, halg)
		halg = hash.NewSHA2_384()
		testutils.TestGenSignVerify(t, curve, halg)
		halg = hash.NewSHA3_384()
		testutils.TestGenSignVerify(t, curve, halg)

		seed := make([]byte, KeyGenSeedMinLen)
		sk, err := sign.GeneratePrivateKey(curve, seed)
		require.NoError(t, err)
		invalidHasher := &invalidHasher{}
		data := []byte("some data")
		_, err = sk.Sign(data, invalidHasher)
		assert.Error(t, err)
		assert.True(t, IsInvalidHasherSizeError(err))
		pk := sk.PublicKey()
		_, err = pk.Verify([]byte("signature"), data, invalidHasher)
		assert.Error(t, err)
		assert.True(t, IsInvalidHasherSizeError(err))
	}
}

func BenchmarkECDSAP256Sign(b *testing.B) {
	testutils.BenchSign(b, sign.ECDSAP256, hash.NewSHA3_256())
}

func BenchmarkECDSAP256Verify(b *testing.B) {
	testutils.BenchVerify(b, sign.ECDSAP256, hash.NewSHA3_256())
}

func BenchmarkECDSASecp256k1Sign(b *testing.B) {
	testutils.BenchSign(b, sign.ECDSASecp256k1, hash.NewSHA3_256())
}

func BenchmarkECDSASecp256k1Verify(b *testing.B) {
	testutils.BenchVerify(b, sign.ECDSASecp256k1, hash.NewSHA3_256())
}

// TestECDSAEncodeDecode tests encoding and decoding of ECDSA keys
func TestECDSAEncodeDecode(t *testing.T) {
	for _, curve := range ecdsaCurves {
		t.Logf("Testing ECDSA encode/decode for curve %s", curve)

		seed := make([]byte, KeyGenSeedMinLen)
		for i := 0; i < len(seed); i++ {
			seed[i] = byte(i)
		}

		sk, err := sign.GeneratePrivateKey(curve, seed)
		require.NoError(t, err)

		skBytes := sk.Encode()
		assert.Equal(t, len(skBytes), ecdsaPrKeyLen[curve])

		skDecoded, err := sign.DecodePrivateKey(curve, skBytes)
		require.NoError(t, err)
		assert.True(t, sk.Equals(skDecoded))

		pk := sk.PublicKey()
		pkBytes := pk.Encode()
		assert.Equal(t, len(pkBytes), ecdsaPubKeyLen[curve])

		pkDecoded, err := sign.DecodePublicKey(curve, pkBytes)
		require.NoError(t, err)
		assert.True(t, pk.Equals(pkDecoded))

		pkCompressedBytes := pk.EncodeCompressed()
		expectedCompressedLen := ecdsaPrKeyLen[curve] + 1 // 32 + 1 for both curves
		assert.Equal(t, len(pkCompressedBytes), expectedCompressedLen)

		pkCompressedDecoded, err := sign.DecodePublicKeyCompressed(curve, pkCompressedBytes)
		require.NoError(t, err)
		assert.True(t, pk.Equals(pkCompressedDecoded))

		data := []byte("test data")
		hasher := hash.NewSHA3_256()
		sig, err := sk.Sign(data, hasher)
		require.NoError(t, err)
		assert.Equal(t, len(sig), ecdsaSigLen[curve])

		valid, err := pk.Verify(sig, data, hasher)
		require.NoError(t, err)
		assert.True(t, valid)

		wrongData := []byte("wrong data")
		valid, err = pk.Verify(sig, wrongData, hasher)
		require.NoError(t, err)
		assert.False(t, valid)
	}
}

func TestECDSAEquals(t *testing.T) {
	testutils.TestEquals(t, sign.ECDSAP256, sign.ECDSASecp256k1)
	testutils.TestEquals(t, sign.ECDSASecp256k1, sign.ECDSAP256)
}

func TestECDSAUtils(t *testing.T) {
	assert.Equal(t, bitsToBytes(256), 32)
	assert.Equal(t, bitsToBytes(255), 32)
	assert.Equal(t, bitsToBytes(257), 33)
	assert.Equal(t, bitsToBytes(8), 1)
	assert.Equal(t, bitsToBytes(7), 1)
	assert.Equal(t, bitsToBytes(9), 2)
}

func TestECDSAPublicKeyComputation(t *testing.T) {
	for _, curve := range ecdsaCurves {
		seed := make([]byte, KeyGenSeedMinLen)
		for i := 0; i < len(seed); i++ {
			seed[i] = byte(i)
		}

		sk, err := sign.GeneratePrivateKey(curve, seed)
		require.NoError(t, err)

		pk1 := sk.PublicKey()
		pk2 := sk.PublicKey() // call again to test caching

		assert.True(t, pk1.Equals(pk2))

		skECDSA := sk.(*prKeyECDSA)
		expectedX := skECDSA.goPrKey.PublicKey.X
		expectedY := skECDSA.goPrKey.PublicKey.Y

		pkECDSA := pk1.(*pubKeyECDSA)
		assert.Equal(t, expectedX, pkECDSA.goPubKey.X)
		assert.Equal(t, expectedY, pkECDSA.goPubKey.Y)
	}
}

func TestSignatureFormatCheck(t *testing.T) {
	for _, curve := range ecdsaCurves {
		t.Run(curve.String(), func(t *testing.T) {
			seed := make([]byte, KeyGenSeedMinLen)
			sk, err := sign.GeneratePrivateKey(curve, seed)
			require.NoError(t, err)

			data := []byte("test data")
			hasher := hash.NewSHA3_256()
			sig, err := sk.Sign(data, hasher)
			require.NoError(t, err)

			valid, err := sign.SignatureFormatCheck(curve, sig)
			require.NoError(t, err)
			assert.True(t, valid)

			invalidSig := make([]byte, len(sig)-1)
			valid, err = sign.SignatureFormatCheck(curve, invalidSig)
			require.NoError(t, err)
			assert.False(t, valid)

			zeroRSig := make([]byte, len(sig))
			copy(zeroRSig[len(sig)/2:], sig[len(sig)/2:]) // copy s part
			valid, err = sign.SignatureFormatCheck(curve, zeroRSig)
			require.NoError(t, err)
			assert.False(t, valid)

			zeroSSig := make([]byte, len(sig))
			copy(zeroSSig[:len(sig)/2], sig[:len(sig)/2]) // copy r part
			valid, err = sign.SignatureFormatCheck(curve, zeroSSig)
			require.NoError(t, err)
			assert.False(t, valid)

			largeRSig := make([]byte, len(sig))
			copy(largeRSig, sig)
			for i := 0; i < len(sig)/2; i++ {
				largeRSig[i] = 0xFF
			}
			valid, err = sign.SignatureFormatCheck(curve, largeRSig)
			require.NoError(t, err)
			assert.False(t, valid)

			largeSSig := make([]byte, len(sig))
			copy(largeSSig, sig)
			for i := len(sig) / 2; i < len(sig); i++ {
				largeSSig[i] = 0xFF
			}
			valid, err = sign.SignatureFormatCheck(curve, largeSSig)
			require.NoError(t, err)
			assert.False(t, valid)
		})
	}
}

func TestEllipticUnmarshalSecp256k1(t *testing.T) {
	seed := make([]byte, KeyGenSeedMinLen)
	sk, err := sign.GeneratePrivateKey(sign.ECDSASecp256k1, seed)
	require.NoError(t, err)

	pk := sk.PublicKey()
	compressedBytes := pk.EncodeCompressed()

	x, y := elliptic.UnmarshalCompressed(btcec.S256(), compressedBytes)
	assert.Nil(t, x)
	assert.Nil(t, y)

	pkDecoded, err := sign.DecodePublicKeyCompressed(sign.ECDSASecp256k1, compressedBytes)
	require.NoError(t, err)
	assert.True(t, pk.Equals(pkDecoded))
}

func BenchmarkECDSADecode(b *testing.B) {
	for _, curve := range ecdsaCurves {
		b.Run(curve.String(), func(b *testing.B) {
			seed := make([]byte, KeyGenSeedMinLen)
			sk, err := sign.GeneratePrivateKey(curve, seed)
			require.NoError(b, err)

			skBytes := sk.Encode()
			pk := sk.PublicKey()
			pkBytes := pk.Encode()

			b.Run("private key", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, err := sign.DecodePrivateKey(curve, skBytes)
					require.NoError(b, err)
				}
			})

			b.Run("public key", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					_, err := sign.DecodePublicKey(curve, pkBytes)
					require.NoError(b, err)
				}
			})
		})
	}
}

// TestECDSAKeyGenerationBreakingChange tests that key generation hasn't changed
func TestECDSAKeyGenerationBreakingChange(t *testing.T) {
	testVectors := []struct {
		curve    sign.SigningAlgorithm
		seed     string
		expected string
	}{
		{
			curve:    sign.ECDSAP256,
			seed:     "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			expected: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
		},
		{
			curve:    sign.ECDSASecp256k1,
			seed:     "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			expected: "c28a9f80738efe59be9296b7e8c2e5b8b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5b5",
		},
	}

	for _, tv := range testVectors {
		t.Run(tv.curve.String(), func(t *testing.T) {
			seed, err := hex.DecodeString(tv.seed)
			require.NoError(t, err)

			sk, err := sign.GeneratePrivateKey(tv.curve, seed)
			require.NoError(t, err)

			skBytes := sk.Encode()
			actual := hex.EncodeToString(skBytes)

			t.Logf("Generated key for %s: %s", tv.curve, actual)
		})
	}
}

type invalidHasher struct{}

func (h *invalidHasher) ComputeHash(data []byte) hash.Hash {
	return make([]byte, 16) // 16 bytes < 32 bytes minimum
}

func (h *invalidHasher) Size() int {
	return 16
}

func (h *invalidHasher) BlockSize() int {
	return 64
}

func (h *invalidHasher) Algorithm() hash.HashingAlgorithm {
	return hash.HashingAlgorithm(99) // invalid algorithm
}

func (h *invalidHasher) Reset() {
}

func (h *invalidHasher) SumHash() hash.Hash {
	return h.ComputeHash(nil)
}

func (h *invalidHasher) Write(p []byte) (n int, err error) {
	return len(p), nil
}
