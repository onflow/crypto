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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"

	"github.com/onflow/crypto/hash"
)

// ECDSA implementation on NIST-P256 is based on https://pkg.go.dev/crypto and https://pkg.go.dev/crypto/elliptic
// This implementation is not resistant against side-channel attacks or fault attacks.

const (
	nLenP256 = 32
	pLenP256 = 32
)

const (
	// NIST P256
	SignatureLenECDSAP256 = 2 * nLenP256
	PrKeyLenECDSAP256     = nLenP256
	// PubKeyLenECDSAP256 is the size of uncompressed points on P256
	PubKeyLenECDSAP256 = 2 * pLenP256
)

// context of ECDSA on NIST P-256
var p256Instance *ecdsaContext

func initECDSAP256() {
	curve := elliptic.P256()
	n := curve.Params().N

	p256Instance = &(ecdsaContext{
		curveP:     curve.Params().P,
		curveN:     n,
		curveNdiv2: new(big.Int).Rsh(n, 1), // (N-1)/2, since N is odd
		algo:       ECDSAP256,
	})
}

// prKeyECDSAP256 is the private key of ECDSA on P256, it implements the interface PrivateKey
type prKeyECDSAP256 struct {
	// ECDSA generic private key
	*prKeyCommonECDSA
	// go ecdsa standard lib private key
	goPrKey *ecdsa.PrivateKey
	// pubKeyOnce guards the lazy construction of pubKey,
	// making concurrent calls to PublicKey safe
	pubKeyOnce sync.Once
	// public key
	pubKey *pubKeyECDSAP256
}

var _ PrivateKey = (*prKeyECDSAP256)(nil)

// pubKeyECDSAP256 is the public key of ECDSA on P256, it implements PublicKey
type pubKeyECDSAP256 struct {
	// ECDSA generic public key
	*pubKeyCommonECDSA
	// go ecdsa standard lib public key
	goPubKey *ecdsa.PublicKey
}

var _ PublicKey = (*pubKeyECDSAP256)(nil)

// Input scalar d is assumed to satisfy 0 < d < n before calling this function.
func privateKeyECDSAP256(a *ecdsaContext, dBytes []byte) (*prKeyECDSAP256, error) {
	internalSK, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), dBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw private key: %w", err)
	}
	sk := &prKeyECDSAP256{
		prKeyCommonECDSA: &prKeyCommonECDSA{a},
		goPrKey:          internalSK,
		pubKey:           nil, // public key is not constructed yet
	}
	return sk, nil
}

// Sign signs an array of bytes
//
// The resulting signature is the concatenation bytes(r)||bytes(s),
// where r and s are padded to the curve order size.
// The private key is read only while sha2 and sha3 hashers are
// modified temporarily.
//
// The function returns:
//   - (nil, errNilHasher) if a hasher is nil
//   - (nil, invalidHasherSizeError) when the hasher's output size is less than the curve order (currently 32 bytes).
//   - (nil, error) if an unexpected error occurs
//   - (signature, nil) otherwise
func (sk *prKeyECDSAP256) Sign(msg []byte, hasher hash.Hasher) (Signature, error) {
	hash, err := sk.checkHasherAndComputeHash(msg, hasher)
	if err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, sk.goPrKey, hash)
	if err != nil {
		return nil, fmt.Errorf("ECDSA sign failed: %w", err)
	}

	signature := make([]byte, 2*nLenP256)
	padToSizeAndConcat(signature, r, s, nLenP256)
	return signature, nil
}

// String returns the hex string representation of the private key
func (sk *prKeyECDSAP256) String() string {
	return prKeyCommonECDSAString(sk)
}

// returns a publicKeyECDSAP256 from (bytes(x) || bytes(y)) bytes
func publicKeyECDSAP256(XYBytes []byte) (*pubKeyECDSAP256, error) {
	if len(XYBytes) != 2*pLenP256 {
		return nil, invalidInputsErrorf("input has incorrect %s key size, got %d, expects %d",
			ECDSAP256, len(XYBytes), 2*pLenP256)
	}

	// deserialization uses SEC1 version 2 (https://www.secg.org/sec1-v2.pdf section 2.3.3)
	// and includes on curve check.
	// The bytes serialization for non-infinity points is `0x04 || X || Y` and infinity point should be rejected anyway
	parsingBytes := append([]byte{ecEncodingUncompressed}, XYBytes...)

	// ParseUncompressedPublicKey includes x<p and y<p checks, and on curve checks
	internalPK, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), parsingBytes)
	if err != nil {
		return nil, invalidInputsErrorf("input point has invalid coordinates or is not on curve: %w", err)
	}
	return &pubKeyECDSAP256{
		&pubKeyCommonECDSA{p256Instance},
		internalPK,
	}, nil
}

// String returns the hex string representation of the public key
func (pk *pubKeyECDSAP256) String() string {
	return pubKeyCommonECDSAString(pk)
}

// PublicKey returns the public key associated to the private key
func (sk *prKeyECDSAP256) PublicKey() PublicKey {
	// construct the public key once
	sk.pubKeyOnce.Do(func() {
		sk.pubKey = &pubKeyECDSAP256{
			pubKeyCommonECDSA: &pubKeyCommonECDSA{p256Instance},
			goPubKey:          &sk.goPrKey.PublicKey,
		}
	})
	return sk.pubKey
}

// Verify verifies a signature of an input data under the public key.
//
// If the input signature slice has an invalid length or fails to deserialize into valid
// scalars, the function returns false without an error.
//
// Public keys are read only, sha2 and sha3 hashers are
// modified temporarily.
//
// The function returns:
//   - (false, errNilHasher) if a hasher is nil
//   - (false, invalidHasherSizeError) when the hasher's output size is less than the curve order (currently 32 bytes).
//   - (false, error) if an unexpected error occurs
//   - (validity, nil) otherwise
func (pk *pubKeyECDSAP256) Verify(sig Signature, data []byte, alg hash.Hasher) (bool, error) {
	h, err := pk.checkHasherAndComputeHash(data, alg)
	if err != nil {
		return false, err
	}
	if len(sig) != SignatureLenECDSAP256 {
		return false, nil
	}

	r, s := readTwoBigInts(sig, nLenP256)
	return ecdsa.Verify(pk.goPubKey, h, r, s), nil
}

// given a private key (d), returns a raw encoding bytes(d) in big endian
// padded to the private key length
func (sk *prKeyECDSAP256) rawEncode() []byte {
	skBytes, err := sk.goPrKey.Bytes()
	if err != nil {
		// not expected to happen since the private key is generated by this package and should be valid
		panic(fmt.Sprintf("failed to encode private key: %v", err))
	}
	return skBytes
}

// Encode returns a byte representation of a private key.
// a simple raw byte encoding in big endian is used for all curves
func (sk *prKeyECDSAP256) Encode() []byte {
	return sk.rawEncode()
}

// Equals tests the equality of two private keys
func (sk *prKeyECDSAP256) Equals(other PrivateKey) bool {
	return prKeyCommonECDSAEquals(sk, other)
}

// Equals tests the equality of two public keys
func (pk *pubKeyECDSAP256) Equals(other PublicKey) bool {
	return pubKeyCommonECDSAEquals(pk, other)
}

// `rawEncode` returns a raw uncompressed encoding `bytes(x) || bytes(y)` given a public key (x,y).
// x and y are padded to the field size.
func (pk *pubKeyECDSAP256) rawEncode() []byte {
	bytes, err := pk.goPubKey.Bytes()
	if err != nil {
		// not expected to happen since the public keys generated by this package only
		// use elliptic.P256
		panic(fmt.Sprintf("unexpected failure to encode public key: %v", err))
	}
	return bytes[1:] // remove the uncompressed point prefix
}

// Encode returns a byte representation of a public key.
// a simple uncompressed raw encoding X||Y is used for all curves
// X and Y are the big endian byte encoding of the x and y coordinates of the public key
func (pk *pubKeyECDSAP256) Encode() []byte {
	return pk.rawEncode()
}

// EncodeCompressed returns a compressed encoding according to X9.62 section 4.3.6.
// This compressed representation uses an extra byte to disambiguate parity.
// The expected input is a public key (x,y).
//
// Receiver point is guaranteed to be on curve and to be non-infinity because
// the package does not allow constructing infinity points or points not on curve.
func (pk *pubKeyECDSAP256) EncodeCompressed() []byte {
	bytes := pk.rawEncode()
	// read X and Y from the encoding
	x, y := readTwoBigInts(bytes, pLenP256)
	// use elliptic.MarshalCompressed to get the compressed encoding
	return elliptic.MarshalCompressed(elliptic.P256(), x, y)
}

// p256DecodePublicKeyCompressed returns a non-infinity P-256 public key given the bytes of a compressed
// public key according to X9.62 section 4.3.6.
// Note that infinity point serialization isn't defined in this package so the input (or output)
// can never represent an infinity point.
// Error Returns:
//   - invalidInputsError if the input isn't a valid key serialization
//     on the given curve.
func p256DecodePublicKeyCompressed(pkBytes []byte) (*pubKeyECDSAP256, error) {

	expectedLen := pLenP256 + 1
	if len(pkBytes) != expectedLen {
		return nil, invalidInputsErrorf("incorrect input length, expected %d, got %d", expectedLen, len(pkBytes))
	}
	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), pkBytes)
	if x == nil || y == nil {
		return nil, invalidInputsErrorf("input %x isn't a compressed serialization of a point on P256", pkBytes)
	}
	// serialize the coordinates and delegate to the uncompressed decoding,
	// so that both decoding paths construct the key the same way
	xyBytes := make([]byte, 2*pLenP256)
	padToSizeAndConcat(xyBytes, x, y, pLenP256)
	return publicKeyECDSAP256(xyBytes)
}
