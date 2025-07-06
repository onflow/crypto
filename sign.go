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
	"crypto/elliptic"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/onflow/crypto/sign"
)

// revive:disable:var-naming

// revive:enable

type SigningAlgorithm = sign.SigningAlgorithm
type Signature = sign.Signature
type PrivateKey = sign.PrivateKey
type PublicKey = sign.PublicKey

const (
	// Supported signing algorithms
	UnknownSigningAlgorithm = sign.UnknownSigningAlgorithm
	// BLSBLS12381 is BLS on BLS 12-381 curve
	BLSBLS12381 = sign.BLSBLS12381
	// ECDSAP256 is ECDSA on NIST P-256 curve
	ECDSAP256 = sign.ECDSAP256
	// ECDSASecp256k1 is ECDSA on secp256k1 curve
	ECDSASecp256k1 = sign.ECDSASecp256k1
)

type signer interface {
	// generatePrivateKey generates a private key
	generatePrivateKey([]byte) (PrivateKey, error)
	// decodePrivateKey loads a private key from a byte array
	decodePrivateKey([]byte) (PrivateKey, error)
	// decodePublicKey loads a public key from a byte array
	decodePublicKey([]byte) (PublicKey, error)
	// decodePublicKeyCompressed loads a public key from a byte array representing a point in compressed form
	decodePublicKeyCompressed([]byte) (PublicKey, error)
	// signatureFormatCheck verifies the format of a serialized signature
	signatureFormatCheck(Signature) bool
}

// newSigner returns a signer instance
func newSigner(algo SigningAlgorithm) (signer, error) {
	switch algo {
	case ECDSAP256:
		return p256Instance, nil
	case ECDSASecp256k1:
		return secp256k1Instance, nil
	case BLSBLS12381:
		return blsInstance, nil
	default:
		return nil, invalidInputsErrorf("the signature scheme %s is not supported", algo)
	}
}

// Initialize the context of all algos
func init() {
	// ECDSA
	p256Instance = &(ecdsaAlgo{
		curve: elliptic.P256(),
		algo:  ECDSAP256,
	})
	secp256k1Instance = &(ecdsaAlgo{
		curve: btcec.S256(),
		algo:  ECDSASecp256k1,
	})

	// BLS
	initBLS12381()
	blsInstance = &blsBLS12381Algo{
		algo: BLSBLS12381,
	}
}

// SignatureFormatCheck verifies the format of a serialized signature,
// regardless of messages or public keys.
//
// This function is only defined for ECDSA algos for now.
//
// If SignatureFormatCheck returns false then the input is not a valid
// signature and will fail a verification against any message and public key.
func SignatureFormatCheck(algo SigningAlgorithm, s Signature) (bool, error) {
	switch algo {
	case ECDSAP256:
		return p256Instance.signatureFormatCheck(s), nil
	case ECDSASecp256k1:
		return secp256k1Instance.signatureFormatCheck(s), nil
	default:
		return false, invalidInputsErrorf(
			"the signature scheme %s is not supported",
			algo)
	}
}

// GeneratePrivateKey generates a private key of the algorithm using the entropy of the given seed.
//
// The seed minimum length is 32 bytes and it should have enough entropy.
// It is recommended to use a secure crypto RNG to generate the seed.
//
// The function returns:
//   - (false, invalidInputsErrors) if the signing algorithm is not supported or
//     if the seed length is not valid (less than 32 bytes or larger than 256 bytes)
//   - (false, error) if an unexpected error occurs
//   - (sk, nil) if key generation was successful
func GeneratePrivateKey(algo SigningAlgorithm, seed []byte) (PrivateKey, error) {
	signer, err := newSigner(algo)
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}
	return signer.generatePrivateKey(seed)
}

// DecodePrivateKey decodes an array of bytes into a private key of the given algorithm
//
// The function returns:
//   - (nil, invalidInputsErrors) if the signing algorithm is not supported
//   - (nil, invalidInputsErrors) if the input does not serialize a valid private key:
//     -- ECDSA: a valid input is bytes(x) where bytes() is the big-endian encoding padded to the curve order size (32 bytes),
//     and `x` is a scalar strictly smaller than the curve order and strictly larger than zero.
//     -- BLS: a valid input is bytes(x) where bytes() is the big-endian encoding padded to the order size of BLS12-381 (32 bytes),
//     and `x` is a scalar strictly smaller than the curve order and strictly larger than zero.
//   - (nil, error) if an unexpected error occurs
//   - (sk, nil) otherwise
func DecodePrivateKey(algo SigningAlgorithm, input []byte) (PrivateKey, error) {
	signer, err := newSigner(algo)
	if err != nil {
		return nil, fmt.Errorf("decode private key failed: %w", err)
	}
	return signer.decodePrivateKey(input)
}

// DecodePublicKey decodes an array of bytes into a public key of the given algorithm
//
// The function returns:
//   - (nil, invalidInputsErrors) if the signing algorithm is not supported
//   - (nil, invalidInputsErrors) if the input does not serialize a valid public key:
//     -- ECDSA: a valid input is `bytes(x) || bytes(y)` where `bytes()` is the big-endian encoding padded to the field size (32 bytes),
//     x and y are a point coordinates reduced modulo the field's prime, with the point being on curve.
//     Note that infinity point serialization isn't defined in this package, so an infinity public key cannot be constructed.
//     -- BLS: a valid input is a compressed serialization of a G2 point following
//     https://www.ietf.org/archive/id/draft-irtf-cfrg-pairing-friendly-curves-08.html#name-zcash-serialization-format-
//     Note that infinity point is a valid serialized public key.
//   - (nil, error) if an unexpected error occurs
//   - (pk, nil) otherwise
func DecodePublicKey(algo SigningAlgorithm, input []byte) (PublicKey, error) {
	signer, err := newSigner(algo)
	if err != nil {
		return nil, fmt.Errorf("decode public key failed: %w", err)
	}
	return signer.decodePublicKey(input)
}

// DecodePublicKeyCompressed decodes an array of bytes given in a compressed representation into a public key of the given algorithm.
// Only ECDSA is supported (BLS uses the compressed serialization by default).
//
// The function returns:
//   - (nil, invalidInputsErrors) if the signing algorithm is not supported (is not ECDSA)
//   - (nil, invalidInputsErrors) if the input does not serialize a valid public key:
//     -- ECDSA: a valid input is `sign_byte || bytes(x)` according to X9.62 section 4.3.6.
//     x is the first point coordinate (reduced modulo the field's prime) of a point being on curve.
//     Note that infinity point serialization isn't defined in this package, so an infinity public key cannot be constructed.
//     Note that infinity point serialization isn't defined in this package.
//   - (nil, error) if an unexpected error occurs
//   - (pk, nil) otherwise
func DecodePublicKeyCompressed(algo SigningAlgorithm, data []byte) (PublicKey, error) {
	signer, err := newSigner(algo)
	if err != nil {
		return nil, fmt.Errorf("decode compressed public key failed: %w", err)
	}
	return signer.decodePublicKeyCompressed(data)
}
