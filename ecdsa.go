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

// Elliptic Curve Digital Signature Algorithm is implemented as
// defined in FIPS 186-4 (although the hash functions implemented in this package are SHA2 and SHA3).

// This implementation is not resistant against side-channel attacks or fault attacks.

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/onflow/crypto/hash"
)

// ecdsaContext embeds SigningAlgorithm
type ecdsaContext struct {
	// the signing algo
	algo SigningAlgorithm
	// curve prime field
	curveP *big.Int
	// curve order
	curveN *big.Int
}

const ecEncodingUncompressed = 0x4

func initECDSA() {
	// ECDSA with P256
	initECDSAP256()
	// ECDSA with secp256k1
	initECDSASecp256k1()
}

func bitsToBytes(bits int) int {
	return (bits + 7) >> 3
}

func (a *ecdsaContext) checkAlgoAndComputeHash(msg []byte, hasher hash.Hasher) (hash.Hash, error) {
	if hasher == nil {
		return nil, errNilHasher
	}

	// check hasher's size is at least the curve order in bytes
	nLen := bitsToBytes((a.curveN).BitLen())
	if hasher.Size() < nLen {
		return nil, invalidHasherSizeErrorf(
			"hasher's size should be at least %d, got %d", nLen, hasher.Size())
	}

	h := hasher.ComputeHash(msg)
	return h, nil
}

// signatureFormatCheck verifies the format of a serialized signature,
// regardless of messages or public keys.
// If FormatCheck returns false then the input is not a valid ECDSA
// signature and will fail a verification against any message and public key.
func (a *ecdsaContext) signatureFormatCheck(sig Signature) bool {
	N := a.curveN
	nLen := bitsToBytes(N.BitLen())

	if len(sig) != 2*nLen {
		return false
	}

	r, s := readTwoBigInts(sig, nLen)

	if r.Sign() == 0 || s.Sign() == 0 {
		return false
	}

	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	// We could also check whether r and r+N are quadratic residues modulo (p)
	// using Euler's criterion, but this may be too heavy for a light sanity check.
	return true
}

var one = new(big.Int).SetInt64(1)

// mapToPrivateKey simply maps the input seed to an ECDSA private key
// The private scalar `d` satisfies 0 < d < n.
//
// The function returns:
//   - (nil, invalidInputsError) if the curve is not supported
//   - (nil, error) if an unexpected error occurs
//   - (sk, nil) if key mapping was successful
func (a *ecdsaContext) mapToPrivateKey(seed []byte) (PrivateKey, error) {
	d := new(big.Int).SetBytes(seed)
	NminusOne := new(big.Int).Sub(a.curveN, one)
	d.Mod(d, NminusOne)
	d.Add(d, one) // n > d > 0 at this point
	return a.privateKey(d)
}

// privateKey returns an ECDSA private key using the
// input scalar.

// Input scalar d is assumed to be satisfy 0 < d < n before calling this function.
//
// The function returns:
//   - (nil, invalidInputsError) if the curve is not supported
//   - (nil, error) if an unexpected error occurs
//   - (sk, nil) if key mapping was successful
func (a *ecdsaContext) privateKey(d *big.Int) (PrivateKey, error) {
	dBytes := make([]byte, bitsToBytes(a.curveN.BitLen()))
	d.FillBytes(dBytes) // dBytes is the big-endian encoding of d padded to the curve order

	// build the private key depending on the curve
	switch a.algo {
	case ECDSAP256:
		return privateKeyECDSAP256(a, dBytes)
	case ECDSASecp256k1:
		return privateKeyECDSASecp256k1(a, dBytes), nil
	default:
		return nil, invalidInputsErrorf("the curve is not supported")
	}
}

// generatePrivateKey generates a private key for ECDSA
// deterministically using the input seed.
//
// It is recommended to use a secure crypto RNG to generate the seed.
// The seed must have enough entropy.
func (a *ecdsaContext) generatePrivateKey(seed []byte) (PrivateKey, error) {
	if len(seed) < KeyGenSeedMinLen || len(seed) > KeyGenSeedMaxLen {
		return nil, invalidInputsErrorf("seed byte length should be between %d and %d",
			KeyGenSeedMinLen, KeyGenSeedMaxLen)
	}

	// use HKDF to extract the seed entropy and expand it into key bytes

	// use SHA2-256 as the building block H in HKDF
	hashFunction := sha256.New
	salt := []byte("") // HKDF salt
	info := ""         // HKDF info
	// use extra 128 bits to reduce the modular reduction bias
	nLen := bitsToBytes((a.curveN).BitLen())
	okmLength := nLen + (securityBits / 8)

	// instantiate HKDF and extract okm
	okm, err := hkdf.Key(hashFunction, seed, salt, info, okmLength)
	if err != nil {
		return nil, fmt.Errorf("HKDF computation failed : %w", err)
	}
	defer overwrite(okm) // overwrite okm

	sk, err := a.mapToPrivateKey(okm)
	if err != nil {
		// no error is expected at this point
		return nil, fmt.Errorf("mapping the private key failed: %w", err)
	}
	return sk, nil
}

func (a *ecdsaContext) rawDecodePrivateKey(der []byte) (PrivateKey, error) {
	n := a.curveN
	nLen := bitsToBytes(n.BitLen())
	if len(der) != nLen {
		return nil, invalidInputsErrorf("input has incorrect %s key size, should be %d", a.algo, nLen)
	}
	var d big.Int
	d.SetBytes(der)

	if d.Cmp(n) >= 0 {
		return nil, invalidInputsErrorf("input is larger than the curve order of %s", a.algo)
	}

	if d.Sign() == 0 {
		return nil, invalidInputsErrorf("zero private keys are not a valid %s key", a.algo)
	}

	sk, err := a.privateKey(&d) // n > d > 0 at this point
	if err != nil {
		// error is not expected at this point
		return nil, fmt.Errorf("building the private key failed: %w", err)
	}

	return sk, nil
}

func (a *ecdsaContext) decodePrivateKey(der []byte) (PrivateKey, error) {
	return a.rawDecodePrivateKey(der)
}

// rawDecodePublicKey decodes a public key.
// A valid input is `bytes(x) || bytes(y)` where `bytes()` is the big-endian encoding padded to the field size.
// Note that infinity point serialization isn't defined in this package so the input (or output) can never represent an infinity point.
// Error Returns:
//   - invalidInputsError if the input is not a valid serialization of a public key on the given curve.
func (a *ecdsaContext) rawDecodePublicKey(input []byte) (PublicKey, error) {
	// all the curves supported for now have a cofactor equal to 1,
	// so that checking the point is on curve is enough to make sure it is on the correct subgroup
	switch a.algo {
	case ECDSAP256:
		return publicKeyECDSAP256(a, input)
	case ECDSASecp256k1:
		return publicKeyECDSASecp256k1(a, input)
	default:
		return nil, invalidInputsErrorf("curve is not supported")
	}

}

func (a *ecdsaContext) decodePublicKey(der []byte) (PublicKey, error) {
	return a.rawDecodePublicKey(der)
}

// decodePublicKeyCompressed returns a non-infinity public key given the bytes of a compressed
// public key according to X9.62 section 4.3.6.
// Note that infinity point serialization isn't defined in this package so the input (or output)
// can never represent an infinity point.
// Error Returns:
//   - invalidInputsError if the curve isn't supported or the input isn't a valid key serialization
//     on the given curve.
func (a *ecdsaContext) decodePublicKeyCompressed(pkBytes []byte) (PublicKey, error) {
	switch a.algo {
	case ECDSAP256:
		return p256DecodePublicKeyCompressed(pkBytes)
	case ECDSASecp256k1:
		return secp256k1DecodePublicKeyCompressed(pkBytes)
	default:
		return nil, invalidInputsErrorf("the input curve is not supported")
	}
}

// Algorithm returns the algo related to the private key
func (a *ecdsaContext) Algorithm() SigningAlgorithm {
	return a.algo
}

type prKeyCommonECDSA struct {
	// ECDSA context
	*ecdsaContext
}

// Size returns the length of the private key in bytes
func (sk *prKeyCommonECDSA) Size() int {
	return bitsToBytes((sk.curveN).BitLen())
}

// prKeyCommonECDSAString returns the string representation of an ECDSA private key.
// It is used by all ECDSA private keys regardless of the curve.
func prKeyCommonECDSAString(sk PrivateKey) string {
	return fmt.Sprintf("%#x", sk.Encode())
}

// pubKeyCommonECDSAString returns the string representation of an ECDSA public key.
// It is used by all ECDSA public keys regardless of the curve.
func pubKeyCommonECDSAString(pk PublicKey) string {
	return fmt.Sprintf("%#x", pk.Encode())
}

// Equals test the equality of two private keys
func prKeyCommonECDSAEquals(sk, other PrivateKey) bool {
	// check the algorithm
	if sk.Algorithm() != other.Algorithm() {
		return false
	}
	// check the scalar
	return bytes.Equal(sk.Encode(), other.Encode())
}

type pubKeyCommonECDSA struct {
	// ECDSA context
	*ecdsaContext
}

// Size returns the length of the public key in bytes
func (pk *pubKeyCommonECDSA) Size() int {
	return 2 * bitsToBytes(pk.curveP.BitLen())
}

// Equals test the equality of two private keys
func pubKeyCommonECDSAEquals(pk, other PublicKey) bool {
	// check the algorithm
	if pk.Algorithm() != other.Algorithm() {
		return false
	}
	// check the point
	return bytes.Equal(pk.Encode(), other.Encode())
}

// Helper function to pad two big integers to "size" bytes and concatenate them.
// This helper is needed in serializations in ECDSA implementation.
// It assumes the output buffer has at least 2*size byte-length
func padToSizeAndConcat(output []byte, a, b *big.Int, size int) {
	a.FillBytes(output[:size])
	b.FillBytes(output[size:])
}

// Helper function to read two big integers of "size" bytes each from a concatenate input buffer.
// This helper is needed when deserializing.
// It assumes the input buffer has at least 2*size byte-length.
func readTwoBigInts(input []byte, size int) (*big.Int, *big.Int) {
	a := new(big.Int).SetBytes(input[:size])
	b := new(big.Int).SetBytes(input[size : 2*size])
	return a, b
}
