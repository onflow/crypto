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
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"

	"github.com/onflow/crypto/hash"
)

// ECDSA implementation on SECG secp256k1 is based on https://pkg.go.dev/github.com/ethereum/go-ethereum/crypto/secp256k1

// This implementation is not resistant against side-channel attacks or fault attacks.

// curve parameters for SECG secp256k1 https://www.secg.org/sec2-v2.pdf
const (
	secp256k1PHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
	secp256k1NHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"

	nLenSecp256k1 = 32
	pLenSecp256k1 = 32

	secp256k1Ndiv2Hex = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"
)

const (
	// SECG secp256k1
	SignatureLenECDSASecp256k1 = 2 * nLenSecp256k1
	PrKeyLenECDSASecp256k1     = nLenSecp256k1
	// PubKeyLenECDSASecp256k1 is the size of uncompressed points on secp256k1
	PubKeyLenECDSASecp256k1 = 2 * pLenSecp256k1
)

// context of ECDSA on SECG secp256k1 curve https://www.secg.org/sec2-v2.pdf
var secp256k1Instance *ecdsaContext

func initECDSASecp256k1() {
	curveP, ok := new(big.Int).SetString(secp256k1PHex, 16)
	if !ok {
		panic("failed to initialize ECDSA with secp256k1 curve")
	}
	curveN, ok := new(big.Int).SetString(secp256k1NHex, 16)
	if !ok {
		panic("failed to initialize ECDSA with secp256k1 curve")
	}
	curveNdiv2, ok := new(big.Int).SetString(secp256k1Ndiv2Hex, 16)
	if !ok {
		panic("failed to initialize ECDSA with secp256k1 curve")
	}
	secp256k1Instance = &(ecdsaContext{
		curveP:     curveP,
		curveN:     curveN,
		curveNdiv2: curveNdiv2,
		algo:       ECDSASecp256k1,
	})
}

// prKeyECDSASecp256k1 is the private key of ECDSA on SECG secp256k1, it implements PrivateKey
type prKeyECDSASecp256k1 struct {
	// ECDSA generic private key
	*prKeyCommonECDSA
	// bytes(D) of private scalar D in big endian, padded to the curve order size (32 bytes)
	dBytes []byte
	// public key
	pubKey *pubKeyECDSASecp256k1
}

var _ PrivateKey = (*prKeyECDSASecp256k1)(nil)

// pubKeyECDSASecp256k1 is the public key of ECDSA on SECG secp256k1, it implements PublicKey
type pubKeyECDSASecp256k1 struct {
	// ECDSA generic public key
	*pubKeyCommonECDSA
	// 0x4 || bytes(x) || bytes(y)  (65 bytes) where x and y are the coordinates of the public key point, padded to the field size (32 bytes).
	// This is the form required by go-ethereum/crypto/secp256k1.
	pkBytes []byte
}

var _ PublicKey = (*pubKeyECDSASecp256k1)(nil)

// Input scalar d is assumed to satisfy 0 < d < n before calling this function.
func privateKeyECDSASecp256k1(a *ecdsaContext, dBytes []byte) *prKeyECDSASecp256k1 {
	sk := &prKeyECDSASecp256k1{
		prKeyCommonECDSA: &prKeyCommonECDSA{a},
		dBytes:           dBytes,
		pubKey:           nil, // public key is not constructed yet
	}
	return sk
}

// Sign signs an array of bytes
//
// The resulting signature is the concatenation bytes(r)||bytes(s),
// where r and s are padded to the curve order size.
// The private key is read only while sha2 and sha3 hashers are
// modified temporarily.
//
// The function returns:
//   - (false, errNilHasher) if a hasher is nil
//   - (false, invalidHasherSizeError) when the hasher's output size is less than the curve order (currently 32 bytes).
//   - (nil, error) if an unexpected error occurs
//   - (signature, nil) otherwise
func (sk *prKeyECDSASecp256k1) Sign(msg []byte, hasher hash.Hasher) (Signature, error) {
	hash, err := sk.checkAlgoAndComputeHash(msg, hasher)
	if err != nil {
		return nil, err
	}
	// truncate the hash to the curve order size, as specified in FIPS 186-4 section 6.4 (nLenSecp256k1 here is a multiple of 8 bits).
	// Moreover, the secp256k1 package requires the message hash to equal nLenSecp256k1
	hash = hash[:nLenSecp256k1]
	signature, err := secp256k1.Sign(hash, sk.dBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash: %w", err)
	}
	// remove the EC recover byte (last byte)
	return signature[:SignatureLenECDSASecp256k1], nil
}

// String returns the hex string representation of the private key
func (sk *prKeyECDSASecp256k1) String() string {
	return prKeyCommonECDSAString(sk)
}

func publicKeyECDSASecp256k1(a *ecdsaContext, XYBytes []byte) (*pubKeyECDSASecp256k1, error) {
	pLen := bitsToBytes(a.curveP.BitLen())

	if len(XYBytes) != 2*pLen {
		return nil, invalidInputsErrorf("input has incorrect %s key size, got %d, expects %d",
			a.algo, len(XYBytes), 2*pLen)
	}

	x, y := readTwoBigInts(XYBytes, pLen)

	// check the coordinates are valid field elements (required for go-ethereum versions prior to or equal to v1.16.8)
	if x.Cmp(a.curveP) >= 0 || y.Cmp(a.curveP) >= 0 {
		return nil, invalidInputsErrorf("at least one coordinate is larger than the field prime for %s", a.algo)
	}

	// `IsOnCurve` includes checks for x<p and y<p (in go-ethereum versions from v1.16.9 onwards)
	if !secp256k1.S256().IsOnCurve(x, y) {
		return nil, invalidInputsErrorf("input point has invalid coordinates or is not on curve")
	}
	return &pubKeyECDSASecp256k1{
		&pubKeyCommonECDSA{secp256k1Instance},
		secp256k1PkBytes(x, y),
	}, nil
}

// String returns the hex string representation of the public key
func (pk *pubKeyECDSASecp256k1) String() string {
	return pubKeyCommonECDSAString(pk)
}

// 0x4 || bytes(x) || bytes(y)  (65 bytes) where x and y are the coordinates of the public key point, padded to the field size (32 bytes).
// This is the form required by the underlying go-ethereum/crypto/secp256k1.
//
// The function assumes x and y are valid field elements and the point (x,y) is on curve
func secp256k1PkBytes(x, y *big.Int) []byte {
	pkBytes := make([]byte, 1+2*pLenSecp256k1)
	pkBytes[0] = ecEncodingUncompressed
	// pad x and y to the field size and concatenate them
	padToSizeAndConcat(pkBytes[1:], x, y, pLenSecp256k1)
	return pkBytes
}

// PublicKey returns the public key associated to the private key
func (sk *prKeyECDSASecp256k1) PublicKey() PublicKey {
	// construct the public key once
	if sk.pubKey == nil {
		x, y := secp256k1.S256().ScalarBaseMult(sk.dBytes)

		sk.pubKey = &pubKeyECDSASecp256k1{
			pubKeyCommonECDSA: &pubKeyCommonECDSA{secp256k1Instance},
			pkBytes:           secp256k1PkBytes(x, y),
		}
	}
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
func (pk *pubKeyECDSASecp256k1) Verify(sig Signature, msg []byte, hasher hash.Hasher) (bool, error) {
	hash, err := pk.checkAlgoAndComputeHash(msg, hasher)
	if err != nil {
		return false, err
	}
	if len(sig) != 2*nLenSecp256k1 {
		return false, nil
	}
	// normalize the signature to low S.
	// This is required because the secp256k1 package does not accept high S signatures while the package allows them.
	// Rejecting high S signatures would be a breaking change with prior versions.
	newSig, validS := secp256k1Instance.signatureNormalizeS(sig)
	if !validS {
		return false, nil // S value is invalid, return early
	}

	// truncate the hash to the curve order size, as specified in FIPS 186-4 section 6.4 (nLenSecp256k1 here is a multiple of 8 bits).
	// Moreover, the secp256k1 package requires the message hash to equal nLenSecp256k1
	hash = hash[:nLenSecp256k1]
	return secp256k1.VerifySignature(pk.pkBytes, hash, newSig), nil
}

// given a private key (d), returns a raw encoding bytes(d) in big endian
// padded to the private key length
func (sk *prKeyECDSASecp256k1) rawEncode() []byte {
	return append([]byte(nil), sk.dBytes...)
}

// Encode returns a byte representation of a private key.
// a simple raw byte encoding in big endian is used for all curves
func (sk *prKeyECDSASecp256k1) Encode() []byte {
	return sk.rawEncode()
}

// Equals tests the equality of two private keys
func (sk *prKeyECDSASecp256k1) Equals(other PrivateKey) bool {
	return prKeyCommonECDSAEquals(sk, other)
}

// Equals tests the equality of two public keys
func (pk *pubKeyECDSASecp256k1) Equals(other PublicKey) bool {
	return pubKeyCommonECDSAEquals(pk, other)
}

// `rawEncode` returns a raw uncompressed encoding `bytes(x) || bytes(y)` given a public key (x,y).
// x and y are padded to the field size.
func (pk *pubKeyECDSASecp256k1) rawEncode() []byte {
	// skip the uncompressed encoding byte
	return append([]byte(nil), pk.pkBytes[1:]...)
}

// Encode returns a byte representation of a public key.
// a simple uncompressed raw encoding X||Y is used for all curves
// X and Y are the big endian byte encoding of the x and y coordinates of the public key
func (pk *pubKeyECDSASecp256k1) Encode() []byte {
	return pk.rawEncode()
}

// EncodeCompressed returns a compressed encoding according to X9.62 section 4.3.6.
// This compressed representation uses an extra byte to disambiguate parity.
// The expected input is a public key (x,y).
//
// Receiver point is guaranteed to be on curve and to be non-infinity because
// the package does not allow constructing infinity points or points not on curve.
func (pk *pubKeyECDSASecp256k1) EncodeCompressed() []byte {
	x, y := readTwoBigInts(pk.pkBytes[1:], pLenSecp256k1)
	return secp256k1.CompressPubkey(x, y)
}

// secp256k1DecodePublicKeyCompressed returns a non-infinity public key given the bytes of a compressed
// public key according to X9.62 section 4.3.6.
// Note that infinity point serialization isn't defined in this package so the input (or output)
// can never represent an infinity point.
// Error Returns:
//   - invalidInputsError if the input isn't a valid key serialization
//     on the given curve.
func secp256k1DecodePublicKeyCompressed(pkBytes []byte) (*pubKeyECDSASecp256k1, error) {
	expectedLen := pLenSecp256k1 + 1
	if len(pkBytes) != expectedLen {
		return nil, invalidInputsErrorf("incorrect input length, expected %d, got %d", expectedLen, len(pkBytes))
	}
	x, y := secp256k1.DecompressPubkey(pkBytes)
	if x == nil || y == nil {
		return nil, invalidInputsErrorf("input %x isn't a compressed serialization of a point on secp256k1", pkBytes)
	}

	return &pubKeyECDSASecp256k1{
		&pubKeyCommonECDSA{secp256k1Instance},
		secp256k1PkBytes(x, y),
	}, nil
}
