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
	"fmt"
	"math/big"
	"testing"

	crand "crypto/rand"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/onflow/crypto/hash"
)

var ecdsaCurves = []SigningAlgorithm{
	ECDSAP256,
	ECDSASecp256k1,
}
var ecdsaPrKeyLen = map[SigningAlgorithm]int{
	ECDSAP256:      PrKeyLenECDSAP256,
	ECDSASecp256k1: PrKeyLenECDSASecp256k1,
}
var ecdsaPubKeyLen = map[SigningAlgorithm]int{
	ECDSAP256:      PubKeyLenECDSAP256,
	ECDSASecp256k1: PubKeyLenECDSASecp256k1,
}
var ecdsaSigLen = map[SigningAlgorithm]int{
	ECDSAP256:      SignatureLenECDSAP256,
	ECDSASecp256k1: SignatureLenECDSASecp256k1,
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

// dishonestHasher declares a size but computes hashes one byte shorter,
// simulating a hash.Hasher implementation that breaks the interface contract
type dishonestHasher struct{ dummyHasher }

func newDishonestHasher(size int) hash.Hasher           { return &dishonestHasher{dummyHasher{size}} }
func (d *dishonestHasher) ComputeHash([]byte) hash.Hash { return make([]byte, d.size-1) }

func TestECDSAHasher(t *testing.T) {
	for _, curve := range ecdsaCurves {
		// generate a key pair
		seed := make([]byte, KeyGenSeedMinLen)
		n, err := crand.Read(seed)
		require.Equal(t, n, KeyGenSeedMinLen)
		require.NoError(t, err)
		sk, err := GeneratePrivateKey(curve, seed)
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
			dummy := newDummyHasher(31) // 31 is one byte less than the curve order
			_, err := sk.Sign(seed, dummy)
			assert.Error(t, err)
			assert.True(t, IsInvalidHasherSizeError(err))
			_, err = sk.PublicKey().Verify(sig, seed, dummy)
			assert.Error(t, err)
			assert.True(t, IsInvalidHasherSizeError(err))
		})

		// hasher whose computed hash is shorter than its declared size
		t.Run("dishonest hasher is rejected without a panic", func(t *testing.T) {
			dummy := newDishonestHasher(32)
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
	benchSign(b, ECDSAP256, halg)
}

// Verifying bench
func BenchmarkECDSAP256Verify(b *testing.B) {
	halg := hash.NewSHA3_256()
	benchVerify(b, ECDSAP256, halg)
}

// Signing bench
func BenchmarkECDSASecp256k1Sign(b *testing.B) {
	halg := hash.NewSHA3_256()
	benchSign(b, ECDSASecp256k1, halg)
}

// Verifying bench
func BenchmarkECDSASecp256k1Verify(b *testing.B) {
	halg := hash.NewSHA3_256()
	benchVerify(b, ECDSASecp256k1, halg)
}

// TestECDSAEncodeDecode tests encoding and decoding of ECDSA keys
func TestECDSAEncodeDecode(t *testing.T) {
	for _, curve := range ecdsaCurves {
		testEncodeDecode(t, curve)

		//  zero private key
		t.Run("zero private key", func(t *testing.T) {
			skBytes := make([]byte, ecdsaPrKeyLen[curve])
			sk, err := DecodePrivateKey(curve, skBytes)
			require.Error(t, err, "decoding identity private key should fail")
			assert.True(t, IsInvalidInputsError(err))
			assert.ErrorContains(t, err, "zero private keys are not a valid")
			assert.Nil(t, sk)
		})

		// group order private key
		t.Run("group order private key", func(t *testing.T) {
			groupOrder := make(map[SigningAlgorithm]string)
			groupOrder[ECDSAP256] = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
			groupOrder[ECDSASecp256k1] = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
			orderBytes, err := hex.DecodeString(groupOrder[curve])
			require.NoError(t, err)
			sk, err := DecodePrivateKey(curve, orderBytes)
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
			pk, err := DecodePublicKey(curve, pkBytes)
			require.Error(t, err, "point is not on curve")
			assert.True(t, IsInvalidInputsError(err))
			assert.Nil(t, pk)
		})
	}
	// Test a public key serialization with a point encoded with
	// x or y not reduced mod p.
	// This test checks that:
	//  - public key decoding handles input x-coordinates with x and y larger than p (doesn't result in an exception)
	//  - public key decoding only accepts reduced x and y
	t.Run("public key with non-reduced coordinates", func(t *testing.T) {
		onflowCryptoErr := "at least one coordinate is larger than the field prime"
		goCryptoErr := "invalid P256 element encoding"

		invalidPKs := []struct {
			curve    SigningAlgorithm
			pk       string
			errorMsg string
			// assertions are based on the correct error message.
			// In particular, the error message in this test must be about the coordinates
			// being incorrect/non-reduced rather than the point not being on curve.
			// Future edits must not update the error messages without taking this into account.
		}{
			// x >= p  ,  point not on curve
			{
				ECDSASecp256k1, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F0000000000000000000000000000000000000000000000000000000000000000",
				onflowCryptoErr,
			}, {
				ECDSAP256, "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF0000000000000000000000000000000000000000000000000000000000000000",
				goCryptoErr,
			},
			// y >= p ,  point not on curve
			{
				ECDSASecp256k1, "0000000000000000000000000000000000000000000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
				onflowCryptoErr,
			}, {
				ECDSAP256, "0000000000000000000000000000000000000000000000000000000000000000FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
				goCryptoErr,
			},
			// x >= p ,  point on curve
			{
				ECDSASecp256k1, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc304218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee",
				onflowCryptoErr,
			},
		}

		for _, invalidPK := range invalidPKs {
			pkBytes, err := hex.DecodeString(invalidPK.pk)
			require.NoError(t, err)
			pk, err := DecodePublicKey(invalidPK.curve, pkBytes)
			require.Error(t, err)
			assert.True(t, IsInvalidInputsError(err))
			assert.ErrorContains(t, err, invalidPK.errorMsg)
			assert.Nil(t, pk)
		}
	})
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
		sk, err := GeneratePrivateKey(curve, seed)
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
		curve SigningAlgorithm
		sk    string
		pk    string
	}{
		{
			ECDSASecp256k1,
			"6e37a39c31a05181bf77919ace790efd0bdbcaf42b5a52871fc112fceb918c95",
			"0x36f292f6c287b6e72ca8128465647c7f88730f84ab27a1e934dbd2da753930fa39a09ddcf3d28fb30cc683de3fc725e095ec865c3d41aef6065044cb12b1ff61",
		},
		{
			ECDSAP256,
			"6e37a39c31a05181bf77919ace790efd0bdbcaf42b5a52871fc112fceb918c95",
			"0x78a80dfe190a6068be8ddf05644c32d2540402ffc682442f6a9eeb96125d86813789f92cf4afabf719aaba79ecec54b27e33a188f83158f6dd15ecb231b49808",
		},
	}

	for _, test := range testVec {
		// get the private key (the scalar)
		bytes, err := hex.DecodeString(test.sk)
		require.NoError(t, err)
		sk, err := DecodePrivateKey(test.curve, bytes)
		require.NoError(t, err)
		// computed public key (base scalar point result)
		computedPk := sk.PublicKey().String()
		require.NoError(t, err)
		// check that the computed public key matches the expected one
		assert.Equal(t, test.pk, computedPk)
	}
}

// TestECDSASignatureFormatCheck tests SignatureFormatCheck.
func TestECDSASignatureFormatCheck(t *testing.T) {
	for _, curve := range ecdsaCurves {
		t.Run("valid signature check", func(t *testing.T) {
			len := ecdsaSigLen[curve]
			sig := Signature(make([]byte, len))
			_, err := crand.Read(sig)
			require.NoError(t, err)
			sig[len/2] = 0    // force s to be less than the curve order
			sig[len-1] |= 1   // force s to be non zero
			sig[0] = 0        // force r to be less than the curve order
			sig[len/2-1] |= 1 // force r to be non zero
			valid, err := SignatureFormatCheck(curve, sig)
			assert.Nil(t, err)
			assert.True(t, valid)
		})

		t.Run("invalid length", func(t *testing.T) {
			len := ecdsaSigLen[curve]
			shortSig := Signature(make([]byte, len/2))
			valid, err := SignatureFormatCheck(curve, shortSig)
			assert.Nil(t, err)
			assert.False(t, valid)

			longSig := Signature(make([]byte, len*2))
			valid, err = SignatureFormatCheck(curve, longSig)
			assert.Nil(t, err)
			assert.False(t, valid)
		})
		t.Run("zero values", func(t *testing.T) {
			// S=0
			len := ecdsaSigLen[curve]
			sig0s := Signature(make([]byte, len))
			_, err := crand.Read(sig0s[:len/2])
			require.NoError(t, err)

			valid, err := SignatureFormatCheck(curve, sig0s)
			assert.Nil(t, err)
			assert.False(t, valid)

			// R=0
			sig0r := Signature(make([]byte, len))
			_, err = crand.Read(sig0r[len/2:])
			require.NoError(t, err)

			valid, err = SignatureFormatCheck(curve, sig0r)
			assert.Nil(t, err)
			assert.False(t, valid)

			// signature with R=S=0
			sig0 := Signature(make([]byte, len))
			valid, err = SignatureFormatCheck(curve, sig0)
			assert.Nil(t, err)
			assert.False(t, valid)
		})

		t.Run("non-reduced values", func(t *testing.T) {
			len := ecdsaSigLen[curve]
			sigLargeS := Signature(make([]byte, len))
			_, err := crand.Read(sigLargeS[:len/2])
			require.NoError(t, err)
			// s >= N
			for i := len / 2; i < len; i++ {
				sigLargeS[i] = 0xFF
			}

			valid, err := SignatureFormatCheck(curve, sigLargeS)
			assert.Nil(t, err)
			assert.False(t, valid)

			sigLargeR := Signature(make([]byte, len))
			_, err = crand.Read(sigLargeR[len/2:])
			require.NoError(t, err)
			// R >= N
			for i := 0; i < len/2; i++ {
				sigLargeR[i] = 0xFF
			}

			valid, err = SignatureFormatCheck(curve, sigLargeR)
			assert.Nil(t, err)
			assert.False(t, valid)
		})
	}
}

func BenchmarkECDSADecode(b *testing.B) {
	// random message
	seed := make([]byte, 50)
	_, _ = crand.Read(seed)

	for _, curve := range []SigningAlgorithm{ECDSASecp256k1, ECDSAP256} {
		sk, _ := GeneratePrivateKey(curve, seed)
		comp := sk.PublicKey().EncodeCompressed()
		uncomp := sk.PublicKey().Encode()

		b.Run("compressed point on "+curve.String(), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := DecodePublicKeyCompressed(curve, comp)
				require.NoError(b, err)
			}
			b.StopTimer()
		})

		b.Run("uncompressed point on "+curve.String(), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := DecodePublicKey(curve, uncomp)
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
		curve      SigningAlgorithm
		seed       string
		expectedSK string
	}{
		{
			ECDSASecp256k1,
			"00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
			"0x4723d238a9702296f96bf64f1288c8b1eb93a4bff8b1482be4172c745bf30acb",
		},
		{
			ECDSAP256,
			"00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
			"0x3cadd4123b493233252ffdeccaef07066b73e2c3a9a08905669c5a857027708b",
		},
	}

	for _, test := range testVec {
		t.Logf("testing keyGen change for curve %s", test.curve)
		// key generation
		seedBytes, err := hex.DecodeString(test.seed)
		require.NoError(t, err)
		sk, err := GeneratePrivateKey(test.curve, seedBytes)
		require.NoError(t, err)
		// test change
		assert.Equal(t, test.expectedSK, sk.String())
	}
}

// TestECDSAHighAndLowS checks that both signature malleability forms are accepted.
//
// For a valid signature (r,s), the pair (r,n-s) is also a valid signature of the same
// message under the same key. The package signature verification accepts both forms and should keep doing so.
// Rejecting the high-s form would be a breaking change for applications using this package.
func TestECDSAHighAndLowS(t *testing.T) {

	var ecdsaContexts = map[SigningAlgorithm]*ecdsaContext{
		ECDSAP256:      p256Instance,
		ECDSASecp256k1: secp256k1Instance,
	}

	t.Run("lowS and HighS pass", func(t *testing.T) {
		for _, curve := range ecdsaCurves {
			t.Run(curve.String(), func(t *testing.T) {
				// generate a key and sign a random message
				seed := make([]byte, KeyGenSeedMinLen)
				_, err := crand.Read(seed)
				require.NoError(t, err)
				sk, err := GeneratePrivateKey(curve, seed)
				require.NoError(t, err)

				msg := make([]byte, 10)
				_, err = crand.Read(msg)
				require.NoError(t, err)

				halg := hash.NewSHA3_256()
				sig, err := sk.Sign(msg, halg)
				require.NoError(t, err)

				// extract S and test the current case of S (either low or high)
				_, s := readTwoBigInts(sig, ecdsaSigLen[curve]/2)
				isLowS := ecdsaContexts[curve].isLowS(s)

				t.Run(fmt.Sprintf("low S equals %v", isLowS), func(t *testing.T) {
					// the format check must accept both forms
					wellFormed, err := SignatureFormatCheck(curve, sig)
					require.NoError(t, err)
					assert.True(t, wellFormed)

					// verification must accept the first form (can be low or high S)
					valid, err := sk.PublicKey().Verify(sig, msg, halg)
					require.NoError(t, err)
					assert.True(t, valid)
				})

				// flip S to N-S to check the other case
				t.Run(fmt.Sprintf("low S equals %v", !isLowS), func(t *testing.T) {
					newSig := ecdsaContexts[curve].signatureFlipS(sig)

					// sanity check
					_, newS := readTwoBigInts(newSig, ecdsaSigLen[curve]/2)
					newIsLowS := ecdsaContexts[curve].isLowS(newS)
					require.Equal(t, !newIsLowS, isLowS, "S didn't flip") // this test is correct because S cannot equal N-S since N is odd

					// the format check must accept both forms
					wellFormed, err := SignatureFormatCheck(curve, newSig)
					require.NoError(t, err)
					assert.True(t, wellFormed)

					// verification must accept the second form (can be low or high S)
					valid, err := sk.PublicKey().Verify(newSig, msg, halg)
					require.NoError(t, err)
					assert.True(t, valid)
				})
			})
		}
	})

	// signatureNormalizeS must reject values S >= N
	t.Run("check signatureNormalizeS", func(t *testing.T) {
		for _, curve := range ecdsaCurves {
			t.Run(curve.String(), func(t *testing.T) {
				nLen := ecdsaSigLen[curve] / 2
				badSig := make([]byte, ecdsaSigLen[curve])
				// set all S bytes to 0xFF which makes S larger than N.
				// R value does not matter in the function
				for i := nLen; i < len(badSig); i++ {
					badSig[i] = 0xFF
				}

				newSig, validS := ecdsaContexts[curve].signatureNormalizeS(badSig)
				assert.False(t, validS)
				assert.Nil(t, newSig)
			})
		}
	})
}

// Test function only to flip S in a signature. It is used for testing signature malleability
func (a *ecdsaContext) signatureFlipS(sig []byte) []byte {
	// read S
	nLen := bitsToBytes(a.curveN.BitLen())
	s := new(big.Int).SetBytes(sig[nLen:])
	// compute N-S
	sComplement := new(big.Int).Sub(a.curveN, s)
	// write it into a new signature
	newSig := make([]byte, len(sig))
	copy(newSig, sig[:nLen])             // copy R
	sComplement.FillBytes(newSig[nLen:]) // write S complement
	return newSig
}

// TestECDSASecp256k1DeterministicSigning checks deterministic ECDSA signatures
// on secp256k1 against RFC 6979 known-answer test vectors.
// The vectors are the community secp256k1/SHA-256 vectors
// replicated in trezor-crypto and python-ecdsa.
// The expected signatures are the low-S normalized (r || s) pairs.
//
// The test only makes sense while the underlying implementation (currently go-ethereum)
// uses RFC 6979 nonces and outputs low-S signatures.
// An underlying implementation that does not do both is not required to pass this test,
// and the test must then be deleted.
//
// The package itself does not require or guarantee deterministic or low-S signatures.
// The test therefore checks the correctness of the current implementation only
// and does not guarantee any such property in future updates of the package.
func TestECDSASecp256k1DeterministicSigning(t *testing.T) {
	vectors := []struct {
		sk  string
		msg string
		sig string
	}{
		{
			sk:  "0000000000000000000000000000000000000000000000000000000000000001",
			msg: "Satoshi Nakamoto",
			sig: "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d82442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5",
		},
		{
			// the private key is the curve order minus 1
			sk:  "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
			msg: "Satoshi Nakamoto",
			sig: "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d06b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5",
		},
		{
			sk:  "f8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181",
			msg: "Alan Turing",
			sig: "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea",
		},
	}

	for i, v := range vectors {
		skBytes, err := hex.DecodeString(v.sk)
		require.NoError(t, err)
		sk, err := DecodePrivateKey(ECDSASecp256k1, skBytes)
		require.NoError(t, err)

		sig, err := sk.Sign([]byte(v.msg), hash.NewSHA2_256())
		require.NoError(t, err)
		assert.Equal(t, v.sig, hex.EncodeToString(sig), "vector %d", i)

		// the signature must verify under the matching public key
		valid, err := sk.PublicKey().Verify(sig, []byte(v.msg), hash.NewSHA2_256())
		require.NoError(t, err)
		assert.True(t, valid, "vector %d", i)
	}
}
