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

package crypto

import (
	"encoding/hex"
	"testing"

	"crypto/elliptic"
	crand "crypto/rand"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onflow/crypto/hash"
	"github.com/onflow/crypto/sign"
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

// ECDSA tests
func TestECDSA(t *testing.T) {

	for _, curve := range ecdsaCurves {
		t.Logf("Testing ECDSA for curve %s", curve)
		// test key generation seed limits
		testKeyGenSeed(t, curve, KeyGenSeedMinLen, KeyGenSeedMaxLen)
		// test consistency
		halg := hash.NewSHA3_256()
		testGenSignVerify(t, curve, halg)
	}
}

type dummyHasher struct{ size int }

func newDummyHasher(size int) hash.Hasher               { return &dummyHasher{size} }
func (d *dummyHasher) Algorithm() hash.HashingAlgorithm { return hash.UnknownHashingAlgorithm }
func (d *dummyHasher) Size() int                        { return d.size }
func (d *dummyHasher) ComputeHash([]byte) hash.Hash     { return make([]byte, d.size) }
func (d *dummyHasher) Write([]byte) (int, error)        { return 0, nil }
func (d *dummyHasher) SumHash() hash.Hash               { return make([]byte, d.size) }
func (d *dummyHasher) Reset()                           {}

func TestECDSAHasher(t *testing.T) {
	for _, curve := range ecdsaCurves {
		// generate a key pair
		seed := make([]byte, KeyGenSeedMinLen)
		n, err := crand.Read(seed)
		require.Equal(t, n, KeyGenSeedMinLen)
		require.NoError(t, err)
		sk, err := sign.GeneratePrivateKey(curve, seed)
		require.NoError(t, err)
		sig := make([]byte, ecdsaSigLen[curve])

		// empty hasher
		t.Run("Empty hasher", func(t *testing.T) {
			_, err := sk.Sign(seed, nil)
			assert.Error(t, err)
			assert.True(t, IsNilHasherError(err))
			_, err = sk.PublicKey().Verify(sig, seed, nil)
			assert.Error(t, err)
			assert.True(t, IsNilHasherError(err))
		})

		// hasher with large output size
		t.Run("large size hasher is accepted", func(t *testing.T) {
			dummy := newDummyHasher(500)
			_, err := sk.Sign(seed, dummy)
			assert.NoError(t, err)
			_, err = sk.PublicKey().Verify(sig, seed, dummy)
			assert.NoError(t, err)
		})

		// hasher with small output size
		t.Run("small size hasher is rejected", func(t *testing.T) {
			dummy := newDummyHasher(31) // 31 is one byte less than the supported curves' order
			_, err := sk.Sign(seed, dummy)
			assert.Error(t, err)
			assert.True(t, IsInvalidHasherSizeError(err))
			_, err = sk.PublicKey().Verify(sig, seed, dummy)
			assert.Error(t, err)
			assert.True(t, IsInvalidHasherSizeError(err))
		})
	}
}

// Signing bench
func BenchmarkECDSAP256Sign(b *testing.B) {
	halg := hash.NewSHA3_256()
	benchSign(b, sign.ECDSAP256, halg)
}

// Verifying bench
func BenchmarkECDSAP256Verify(b *testing.B) {
	halg := hash.NewSHA3_256()
	benchVerify(b, sign.ECDSAP256, halg)
}

// Signing bench
func BenchmarkECDSASecp256k1Sign(b *testing.B) {
	halg := hash.NewSHA3_256()
	benchSign(b, sign.ECDSASecp256k1, halg)
}

// Verifying bench
func BenchmarkECDSASecp256k1Verify(b *testing.B) {
	halg := hash.NewSHA3_256()
	benchVerify(b, sign.ECDSASecp256k1, halg)
}

// TestECDSAEncodeDecode tests encoding and decoding of ECDSA keys
func TestECDSAEncodeDecode(t *testing.T) {
	for _, curve := range ecdsaCurves {
		testEncodeDecode(t, curve)

		//  zero private key
		t.Run("zero private key", func(t *testing.T) {
			skBytes := make([]byte, ecdsaPrKeyLen[curve])
			sk, err := sign.DecodePrivateKey(curve, skBytes)
			require.Error(t, err, "decoding identity private key should fail")
			assert.True(t, IsInvalidInputsError(err))
			assert.ErrorContains(t, err, "zero private keys are not a valid")
			assert.Nil(t, sk)
		})

		// group order private key
		t.Run("group order private key", func(t *testing.T) {
			groupOrder := make(map[sign.SigningAlgorithm]string)
			groupOrder[sign.ECDSAP256] = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
			groupOrder[sign.ECDSASecp256k1] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
			orderBytes, err := hex.DecodeString(groupOrder[curve])
			require.NoError(t, err)
			sk, err := sign.DecodePrivateKey(curve, orderBytes)
			require.Error(t, err)
			assert.True(t, IsInvalidInputsError(err))
			assert.ErrorContains(t, err, "input is larger than the curve order")
			assert.Nil(t, sk)
		})

		// this is the edge case of a zero-coordinates point.
		// This is not the infinity point case, it only represents the (0,0) point.
		// For both curves supported in the package, this point is not on curve.
		// Infinity point serialization isn't defined by the package for ECDSA and can't be deserialized.
		t.Run("all zeros public key", func(t *testing.T) {
			pkBytes := make([]byte, ecdsaPubKeyLen[curve])
			pk, err := sign.DecodePublicKey(curve, pkBytes)
			require.Error(t, err, "point is not on curve")
			assert.True(t, IsInvalidInputsError(err))
			assert.ErrorContains(t, err, "input is not a point on curve")
			assert.Nil(t, pk)
		})

		// Test a public key serialization with a point encoded with
		// x or y not reduced mod p.
		// This test checks that:
		//  - public key decoding handles input x-coordinates with x and y larger than p (doesn't result in an exception)
		//  - public key decoding only accepts reduced x and y
		t.Run("public key with non-reduced coordinates", func(t *testing.T) {
			invalidPK1s := map[sign.SigningAlgorithm]string{
				sign.ECDSASecp256k1: "0000000000000000000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
				sign.ECDSAP256:      "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF0000000000000000000000000000000000000000000000000000000000000000",
			}
			invalidPK2s := map[sign.SigningAlgorithm]string{
				sign.ECDSASecp256k1: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F0000000000000000000000000000000000000000000000000000000000000000",
				sign.ECDSAP256:      "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF0000000000000000000000000000000000000000000000000000000000000000",
			}
			// invalidpk1 with x >= p
			invalidPk1, err := hex.DecodeString(invalidPK1s[curve])
			require.NoError(t, err)
			_, err = sign.DecodePublicKey(curve, invalidPk1)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "at least one coordinate is larger than the field prime for")
			// invalidpk2 with y >= p
			invalidPk2, err := hex.DecodeString(invalidPK2s[curve])
			require.NoError(t, err)
			_, err = sign.DecodePublicKey(curve, invalidPk2)
			assert.Error(t, err)
			assert.ErrorContains(t, err, "at least one coordinate is larger than the field prime for")
		})
	}
}

// TestECDSAEquals tests equal for ECDSA keys
func TestECDSAEquals(t *testing.T) {
	for i, curve := range ecdsaCurves {
		testEquals(t, curve, ecdsaCurves[i]^1)
	}
}

// TestECDSAUtils tests some utility functions
func TestECDSAUtils(t *testing.T) {
	for _, curve := range ecdsaCurves {
		// generate a key pair
		seed := make([]byte, KeyGenSeedMinLen)
		n, err := crand.Read(seed)
		require.Equal(t, n, KeyGenSeedMinLen)
		require.NoError(t, err)
		sk, err := sign.GeneratePrivateKey(curve, seed)
		require.NoError(t, err)
		testKeysAlgorithm(t, sk, curve)
		testKeySize(t, sk, ecdsaPrKeyLen[curve], ecdsaPubKeyLen[curve])
	}
}

// TestECDSAPublicKeyComputation is a sanity check that the public
// key derivation from the private key is valid.
// This is a sanity check of the underlined base scalar multiplication.
// Derived public keys are compared against a hardcoded vector.
func TestECDSAPublicKeyComputation(t *testing.T) {
	testVec := []struct {
		curve sign.SigningAlgorithm
		sk    string
		pk    string
	}{
		{
			sign.ECDSASecp256k1,
			"6e37a39c31a05181bf77919ace790efd0bdbcaf42b5a52871fc112fceb918c95",
			"0x36f292f6c287b6e72ca8128465647c7f88730f84ab27a1e934dbd2da753930fa39a09ddcf3d28fb30cc683de3fc725e095ec865c3d41aef6065044cb12b1ff61",
		},
		{
			sign.ECDSAP256,
			"6e37a39c31a05181bf77919ace790efd0bdbcaf42b5a52871fc112fceb918c95",
			"0x78a80dfe190a6068be8ddf05644c32d2540402ffc682442f6a9eeb96125d86813789f92cf4afabf719aaba79ecec54b27e33a188f83158f6dd15ecb231b49808",
		},
	}

	for _, test := range testVec {
		// get the private key (the scalar)
		bytes, err := hex.DecodeString(test.sk)
		require.NoError(t, err)
		sk, err := sign.DecodePrivateKey(test.curve, bytes)
		require.NoError(t, err)
		// computed public key (base scalar point result)
		computedPk := sk.PublicKey().String()
		require.NoError(t, err)
		// check that the computed public key matches the expected one
		assert.Equal(t, test.pk, computedPk)
	}
}

func TestSignatureFormatCheck(t *testing.T) {

	for _, curve := range ecdsaCurves {
		t.Run("valid signature", func(t *testing.T) {
			len := ecdsaSigLen[curve]
			sig := sign.Signature(make([]byte, len))
			_, err := crand.Read(sig)
			require.NoError(t, err)
			sig[len/2] = 0    // force s to be less than the curve order
			sig[len-1] |= 1   // force s to be non zero
			sig[0] = 0        // force r to be less than the curve order
			sig[len/2-1] |= 1 // force r to be non zero
			valid, err := sign.SignatureFormatCheck(curve, sig)
			assert.Nil(t, err)
			assert.True(t, valid)
		})

		t.Run("invalid length", func(t *testing.T) {
			len := ecdsaSigLen[curve]
			shortSig := sign.Signature(make([]byte, len/2))
			valid, err := sign.SignatureFormatCheck(curve, shortSig)
			assert.Nil(t, err)
			assert.False(t, valid)

			longSig := sign.Signature(make([]byte, len*2))
			valid, err = sign.SignatureFormatCheck(curve, longSig)
			assert.Nil(t, err)
			assert.False(t, valid)
		})

		t.Run("zero values", func(t *testing.T) {
			// signature with a zero s
			len := ecdsaSigLen[curve]
			sig0s := sign.Signature(make([]byte, len))
			_, err := crand.Read(sig0s[:len/2])
			require.NoError(t, err)

			valid, err := sign.SignatureFormatCheck(curve, sig0s)
			assert.Nil(t, err)
			assert.False(t, valid)

			// signature with a zero r
			sig0r := sign.Signature(make([]byte, len))
			_, err = crand.Read(sig0r[len/2:])
			require.NoError(t, err)

			valid, err = sign.SignatureFormatCheck(curve, sig0r)
			assert.Nil(t, err)
			assert.False(t, valid)
		})

		t.Run("large values", func(t *testing.T) {
			len := ecdsaSigLen[curve]
			sigLargeS := sign.Signature(make([]byte, len))
			_, err := crand.Read(sigLargeS[:len/2])
			require.NoError(t, err)
			// make sure s is larger than the curve order
			for i := len / 2; i < len; i++ {
				sigLargeS[i] = 0xFF
			}

			valid, err := sign.SignatureFormatCheck(curve, sigLargeS)
			assert.Nil(t, err)
			assert.False(t, valid)

			sigLargeR := sign.Signature(make([]byte, len))
			_, err = crand.Read(sigLargeR[len/2:])
			require.NoError(t, err)
			// make sure s is larger than the curve order
			for i := 0; i < len/2; i++ {
				sigLargeR[i] = 0xFF
			}

			valid, err = sign.SignatureFormatCheck(curve, sigLargeR)
			assert.Nil(t, err)
			assert.False(t, valid)
		})
	}
}

func TestEllipticUnmarshalSecp256k1(t *testing.T) {
	testVectors := []string{
		"028b10bf56476bf7da39a3286e29df389177a2fa0fca2d73348ff78887515d8da1", // IsOnCurve for elliptic returns false
		"03d39427f07f680d202fe8504306eb29041aceaf4b628c2c69b0ec248155443166", // odd, IsOnCurve for elliptic returns false
		"0267d1942a6cbe4daec242ea7e01c6cdb82dadb6e7077092deb55c845bf851433e", // arith of sqrt in elliptic doesn't match secp256k1
		"0345d45eda6d087918b041453a96303b78c478dce89a4ae9b3c933a018888c5e06", // odd, arith of sqrt in elliptic doesn't match secp256k1
	}

	for _, testVector := range testVectors {
		// get the compressed bytes
		publicBytes, err := hex.DecodeString(testVector)
		require.NoError(t, err)

		// decompress, check that those are perfectly valid Secp256k1 public keys
		retrieved, err := sign.DecodePublicKeyCompressed(sign.ECDSASecp256k1, publicBytes)
		require.NoError(t, err)

		// check the compression is canonical by re-compressing to the same bytes
		require.Equal(t, retrieved.EncodeCompressed(), publicBytes)

		// check that elliptic fails at decompressing them
		x, y := elliptic.UnmarshalCompressed(btcec.S256(), publicBytes)
		require.Nil(t, x)
		require.Nil(t, y)
	}
}

func BenchmarkECDSADecode(b *testing.B) {
	// random message
	seed := make([]byte, 50)
	_, _ = crand.Read(seed)

	for _, curve := range []sign.SigningAlgorithm{sign.ECDSASecp256k1, sign.ECDSAP256} {
		sk, _ := sign.GeneratePrivateKey(curve, seed)
		comp := sk.PublicKey().EncodeCompressed()
		uncomp := sk.PublicKey().Encode()

		b.Run("compressed point on "+curve.String(), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := sign.DecodePublicKeyCompressed(curve, comp)
				require.NoError(b, err)
			}
			b.StopTimer()
		})

		b.Run("uncompressed point on "+curve.String(), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := sign.DecodePublicKey(curve, uncomp)
				require.NoError(b, err)
			}
			b.StopTimer()
		})
	}
}

// TestECDSAKeyGenerationBreakingChange detects if the deterministic key generation
// changes behaviors (same seed outputs a different key than before)
func TestECDSAKeyGenerationBreakingChange(t *testing.T) {
	testVec := []struct {
		curve      sign.SigningAlgorithm
		seed       string
		expectedSK string
	}{
		{
			sign.ECDSASecp256k1,
			"00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
			"0x4723d238a9702296f96bf64f1288c8b1eb93a4bff8b1482be4172c745bf30acb",
		},
		{
			sign.ECDSAP256,
			"00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
			"0x3cadd4123b493233252ffdeccaef07066b73e2c3a9a08905669c5a857027708b",
		},
	}

	for _, test := range testVec {
		t.Logf("testing keyGen change for curve %s", test.curve)
		// key generation
		seedBytes, err := hex.DecodeString(test.seed)
		require.NoError(t, err)
		sk, err := sign.GeneratePrivateKey(test.curve, seedBytes)
		require.NoError(t, err)
		// test change
		assert.Equal(t, test.expectedSK, sk.String())
	}
}
