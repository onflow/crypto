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

package sign

import (
	"fmt"

	"github.com/onflow/crypto/hash"
)

// SigningAlgorithm is an identifier for a signing algorithm
// (and parameters if applicable)
type SigningAlgorithm int

const (
	// Supported signing algorithms
	UnknownSigningAlgorithm SigningAlgorithm = iota
	// BLSBLS12381 is BLS on BLS 12-381 curve
	BLSBLS12381
	// ECDSAP256 is ECDSA on NIST P-256 curve
	ECDSAP256
	// ECDSASecp256k1 is ECDSA on secp256k1 curve
	ECDSASecp256k1
)

// String returns the string representation of this signing algorithm.
func (f SigningAlgorithm) String() string {
	return [...]string{"UNKNOWN", "BLS_BLS12381", "ECDSA_P256", "ECDSA_secp256k1"}[f]
}

// Signature is a generic type, regardless of the signature scheme
type Signature []byte

// Bytes returns a byte array of the signature data
func (s Signature) Bytes() []byte {
	return s[:]
}

// String returns a String representation of the signature data
func (s Signature) String() string {
	return fmt.Sprintf("%#x", s.Bytes())
}

// PrivateKey is an unspecified signature scheme private key
type PrivateKey interface {
	// Algorithm returns the signing algorithm related to the private key.
	Algorithm() SigningAlgorithm
	// Size return the key size in bytes.
	Size() int
	// String return a hex representation of the key
	String() string
	// Sign generates a signature using the provided hasher.
	Sign([]byte, hash.Hasher) (Signature, error)
	// PublicKey returns the public key.
	PublicKey() PublicKey
	// Encode returns a bytes representation of the private key
	Encode() []byte
	// Equals returns true if the given PrivateKeys are equal. Keys are considered unequal if their algorithms are
	// unequal or if their encoded representations are unequal. If the encoding of either key fails, they are considered
	// unequal as well.
	Equals(PrivateKey) bool
}

// PublicKey is an unspecified signature scheme public key.
type PublicKey interface {
	// Algorithm returns the signing algorithm related to the public key.
	Algorithm() SigningAlgorithm
	// Size() return the key size in bytes.
	Size() int
	// String return a hex representation of the key
	String() string
	// Verify verifies a signature of an input message using the provided hasher.
	Verify(Signature, []byte, hash.Hasher) (bool, error)
	// Encode returns a bytes representation of the public key.
	Encode() []byte
	// EncodeCompressed returns a compressed byte representation of the public key.
	// The compressed serialization concept is generic to elliptic curves,
	// but we refer to individual curve parameters for details of the compressed format
	EncodeCompressed() []byte
	// Equals returns true if the given PublicKeys are equal. Keys are considered unequal if their algorithms are
	// unequal or if their encoded representations are unequal. If the encoding of either key fails, they are considered
	// unequal as well.
	Equals(PublicKey) bool
}

// SignatureFormatCheck verifies the format of a serialized signature,
// regardless of messages or public keys.
//
// This function is only defined for ECDSA algos for now.
//
// If SignatureFormatCheck returns false then the input is not a valid
// signature and will fail a verification against any message and public key.
func SignatureFormatCheck(algo SigningAlgorithm, s Signature) (bool, error) {
	return false, fmt.Errorf("the signature scheme %s is not supported", algo)
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
	return nil, fmt.Errorf("the signature scheme %s is not supported", algo)
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
	return nil, fmt.Errorf("the signature scheme %s is not supported", algo)
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
	return nil, fmt.Errorf("the signature scheme %s is not supported", algo)
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
	return nil, fmt.Errorf("the signature scheme %s is not supported", algo)
}
