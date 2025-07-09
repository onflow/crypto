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
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/onflow/crypto/common"
	"github.com/onflow/crypto/hash"
	"github.com/onflow/crypto/sign"
)

const (
	minHashSizeECDSA = 32
	KeyGenSeedMinLen = 32
	KeyGenSeedMaxLen = 128 // maximum constraint
	securityBits = 128
)

func invalidInputsErrorf(msg string, args ...interface{}) error {
	return fmt.Errorf("crypto: invalid inputs: "+msg, args...)
}

func invalidHasherSizeErrorf(msg string, args ...interface{}) error {
	return fmt.Errorf("crypto: invalid hasher size: "+msg, args...)
}

func isValidHasher(h hash.Hasher) bool {
	return h.Size() >= minHashSizeECDSA
}


// IsInvalidHasherSizeError checks if an error is an invalid hasher size error
func IsInvalidHasherSizeError(err error) bool {
	if err == nil {
		return false
	}
	return fmt.Sprintf("%s", err)[:len("crypto: invalid hasher size")] == "crypto: invalid hasher size"
}

func IsNilHasherError(err error) bool {
	if err == nil {
		return false
	}
	return fmt.Sprintf("%s", err) == "hasher cannot be nil"
}

// IsInvalidInputsError checks if an error is an invalid inputs error
func IsInvalidInputsError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return errStr[:len("crypto: invalid inputs")] == "crypto: invalid inputs"
}

const (
	// NIST P256
	SignatureLenECDSAP256 = 64
	PrKeyLenECDSAP256     = 32
	// PubKeyLenECDSAP256 is the size of uncompressed points on P256
	PubKeyLenECDSAP256 = 64

	SignatureLenECDSASecp256k1 = 64
	PrKeyLenECDSASecp256k1     = 32
	// PubKeyLenECDSASecp256k1 is the size of uncompressed points on secp256k1
	PubKeyLenECDSASecp256k1 = 64
)

// ecdsaAlgo embeds SignAlgo
type ecdsaAlgo struct {
	// elliptic curve
	curve elliptic.Curve
	// the signing algo and parameters
	algo sign.SigningAlgorithm
}

type EcdsaAlgo = ecdsaAlgo

func init() {
	// register ECDSA contexts for each supported curve in the `sign` package
	if err := sign.RegisterSigner(sign.ECDSAP256, &ecdsaAlgo{
		curve: elliptic.P256(),
		algo:  sign.ECDSAP256,
	}); err != nil {
		panic(err)
	}
	if err := sign.RegisterSigner(sign.ECDSASecp256k1, &ecdsaAlgo{
		curve: btcec.S256(),
		algo:  sign.ECDSASecp256k1,
	}); err != nil {
		panic(err)
	}
}

func bitsToBytes(bits int) int {
	return (bits + 7) >> 3
}

// signHash returns the signature of the input hash using the private key receiver.
// The signature is the concatenation bytes(r) || bytes(s),
// where `r` and `s` are padded to the curve order size.
// Current implementation of `sign` is randomized, mixing the entropy from the
// the system's crypto/rand, the private key and the hash.
//
// The caller must make sure that the hash is at least the curve order size.
func (sk *prKeyECDSA) signHash(h hash.Hash) (sign.Signature, error) {
	r, s, err := ecdsa.Sign(rand.Reader, sk.goPrKey, h)
	if err != nil {
		return nil, fmt.Errorf("ECDSA sign failed: %w", err)
	}
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	nLen := bitsToBytes((sk.alg.curve.Params().N).BitLen())
	signature := make([]byte, 2*nLen)
	// pad the signature with zeroes
	copy(signature[nLen-len(rBytes):], rBytes)
	copy(signature[2*nLen-len(sBytes):], sBytes)
	return signature, nil
}

// Sign signs an array of bytes
//
// The resulting signature is the concatenation bytes(r)||bytes(s),
// where r and s are padded to the curve order size.
//
//
// The function returns:
//   - (signature, nil) if no error occurred
//   - (nil, invalidInputsError) if the hasher is not supported by the signature algorithm
//   - (nil, error) if an unexpected error occurs
func (sk *prKeyECDSA) Sign(data []byte, alg hash.Hasher) (sign.Signature, error) {
	if !isValidHasher(alg) {
		return nil, invalidHasherSizeErrorf("hasher's output size should be at least %d bytes for %s", minHashSizeECDSA, sk.alg.algo)
	}
	h := alg.ComputeHash(data)
	return sk.signHash(h)
}

// The signature is the concatenation bytes(r) || bytes(s),
// where `r` and `s` are padded to the curve order size.
func (pk *pubKeyECDSA) verifyHash(sig sign.Signature, h hash.Hash) (bool, error) {
	nLen := bitsToBytes((pk.alg.curve.Params().N).BitLen())
	if len(sig) != 2*nLen {
		return false, nil
	}
	var r, s big.Int
	r.SetBytes(sig[:nLen])
	s.SetBytes(sig[nLen:])
	return ecdsa.Verify(pk.goPubKey, h, &r, &s), nil
}

// Verify verifies a signature of an input message using the public key receiver.
//
//
// The function returns:
//   - (true, nil) if the signature is valid
//   - (false, invalidInputsError) if the hasher is not supported by the signature algorithm
//   - (false, error) if an unexpected error occurs
func (pk *pubKeyECDSA) Verify(sig sign.Signature, data []byte, alg hash.Hasher) (bool, error) {
	if !isValidHasher(alg) {
		return false, invalidHasherSizeErrorf("hasher's output size should be at least %d bytes for %s", minHashSizeECDSA, pk.alg.algo)
	}
	h := alg.ComputeHash(data)
	return pk.verifyHash(sig, h)
}

// SignatureFormatCheck verifies the format of a serialized signature,
// regardless of messages or public keys.
//
// This function is only defined for ECDSA algos for now.
//
// If SignatureFormatCheck returns false then the input is not a valid
// signature and will fail a verification against any message and public key.
func (a *ecdsaAlgo) SignatureFormatCheck(s sign.Signature) (bool, error) {
	nLen := bitsToBytes((a.curve.Params().N).BitLen())
	if len(s) != 2*nLen {
		return false, nil
	}
	var r, sVal big.Int
	r.SetBytes(s[:nLen])
	sVal.SetBytes(s[nLen:])

	n := a.curve.Params().N
	if r.Sign() == 0 || sVal.Sign() == 0 {
		return false, nil
	}
	if r.Cmp(n) >= 0 || sVal.Cmp(n) >= 0 {
		return false, nil
	}
	return true, nil
}

func goecdsaMapKey(curve elliptic.Curve, input []byte) (*ecdsa.PrivateKey, error) {
	var d big.Int
	d.SetBytes(input)
	return goecdsaPrivateKey(curve, &d)
}

func goecdsaPrivateKey(curve elliptic.Curve, d *big.Int) (*ecdsa.PrivateKey, error) {
	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = curve
	priv.D = d
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(d.Bytes())
	return priv, nil
}

// GeneratePrivateKey generates a private key for ECDSA.
//
// It is recommended to use a secure crypto RNG to generate the seed.
// The seed must have enough entropy.
func (a *ecdsaAlgo) GeneratePrivateKey(seed []byte) (sign.PrivateKey, error) {
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
	nLen := bitsToBytes((a.curve.Params().N).BitLen())
	okmLength := nLen + (securityBits / 8)

	// instantiate HKDF and extract okm
	okm, err := hkdf.Key(hashFunction, seed, salt, info, okmLength)
	if err != nil {
		return nil, fmt.Errorf("HKDF computation failed : %w", err)
	}
	defer common.Overwrite(okm) // overwrite okm

	sk, err := goecdsaMapKey(a.curve, okm)
	if err != nil {
		// no error is expected at this point
		return nil, fmt.Errorf("mapping the private key failed: %w", err)
	}
	return &prKeyECDSA{
		alg:     a,
		goPrKey: sk,
		pubKey:  nil, // public key is not constructed
	}, nil
}

func (a *ecdsaAlgo) rawDecodePrivateKey(der []byte) (sign.PrivateKey, error) {
	n := a.curve.Params().N
	nLen := bitsToBytes(n.BitLen())
	if len(der) != nLen {
		return nil, invalidInputsErrorf("input has incorrect %s key size", a.algo)
	}
	var d big.Int
	d.SetBytes(der)

	if d.Cmp(n) >= 0 {
		return nil, invalidInputsErrorf("input is larger than the curve order of %s", a.algo)
	}

	if d.Sign() == 0 {
		return nil, invalidInputsErrorf("zero private keys are not a valid %s key", a.algo)
	}

	priv, err := goecdsaPrivateKey(a.curve, &d) // n > d > 0 at this point
	if err != nil {
		// error is not expected at this point
		return nil, fmt.Errorf("building the private key failed: %w", err)
	}

	result := &prKeyECDSA{
		alg:     a,
		goPrKey: priv,
		pubKey:  nil, // public key is not constructed
	}
	return result, nil
}

func (a *ecdsaAlgo) DecodePrivateKey(der []byte) (sign.PrivateKey, error) {
	return a.rawDecodePrivateKey(der)
}

// rawDecodePublicKey decodes a public key.
// A valid input is `bytes(x) || bytes(y)` where `bytes()` is the big-endian encoding padded to the field size.
// Note that infinity point serialization isn't defined in this package so the input (or output) can never represent an infinity point.
// Error Returns:
//   - invalidInputsError if the input is not a valid serialization of a public key on the given curve.
func (a *ecdsaAlgo) rawDecodePublicKey(der []byte) (sign.PublicKey, error) {
	curve := a.curve
	p := (curve.Params().P)
	pLen := bitsToBytes(p.BitLen())
	if len(der) != 2*pLen {
		return nil, invalidInputsErrorf("input has incorrect %s key size, got %d, expects %d",
			a.algo, len(der), 2*pLen)
	}
	var x, y big.Int
	x.SetBytes(der[:pLen])
	y.SetBytes(der[pLen:])

	// check the coordinates are valid field elements
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, invalidInputsErrorf("at least one coordinate is larger than the field prime for %s", a.algo)
	}

	// all the curves supported for now have a cofactor equal to 1,
	// so that checking the point is on curve is enough.
	if curve == elliptic.P256() {
		// use crypto/ecdh implementation to perform on curve check
		// because crypto/elliptic deprecated `IsOnCurve`.
		// ECDH's `NewPublicKey` checks the public key is on curve to avoid falling in small-order groups.

		// crypto/ecdh deserialization uses SEC1 version 2 (https://www.secg.org/sec1-v2.pdf section 2.3.3)
		// except for infinity point.
		// The bytes serialization for non-zero points is `0x04 || X || Y`
		ecdhPubBytes := append([]byte{0x4}, der...)

		_, err := ecdh.P256().NewPublicKey(ecdhPubBytes)
		if err != nil {
			return nil, invalidInputsErrorf("input is not a point on curve P-256: %w", err)
		}
	} else if curve == btcec.S256() {
		// `IsOnCurve` is not deprecated in btcec's type `KoblitzCurve`
		if !btcec.S256().IsOnCurve(&x, &y) {
			return nil, invalidInputsErrorf("input is not a point on curve secp256k1")
		}
	} else {
		return nil, invalidInputsErrorf("curve is not supported")
	}

	pk := ecdsa.PublicKey{
		Curve: a.curve,
		X:     &x,
		Y:     &y,
	}

	return &pubKeyECDSA{a, &pk}, nil
}

func (a *ecdsaAlgo) DecodePublicKey(der []byte) (sign.PublicKey, error) {
	return a.rawDecodePublicKey(der)
}

// DecodePublicKeyCompressed returns a non-infinity public key given the bytes of a compressed
// public key according to X9.62 section 4.3.6.
// The compressed representation uses an extra byte to disambiguate sign.
// Note that infinity point serialization isn't defined in this package so the input (or output)
// can never represent an infinity point.
// Error Returns:
//   - invalidInputsError if the curve isn't supported or the input isn't a valid key serialization
//     on the given curve.
func (a *ecdsaAlgo) DecodePublicKeyCompressed(pkBytes []byte) (sign.PublicKey, error) {
	expectedLen := bitsToBytes(a.curve.Params().BitSize) + 1
	if len(pkBytes) != expectedLen {
		return nil, invalidInputsErrorf("input length incompatible, expected %d, got %d", expectedLen, len(pkBytes))
	}
	var goPubKey *ecdsa.PublicKey

	if a.curve == elliptic.P256() {
		x, y := elliptic.UnmarshalCompressed(a.curve, pkBytes)
		if x == nil {
			return nil, invalidInputsErrorf("input %x isn't a compressed serialization of a %v key", pkBytes, a.algo.String())
		}
		goPubKey = new(ecdsa.PublicKey)
		goPubKey.Curve = a.curve
		goPubKey.X = x
		goPubKey.Y = y

	} else if a.curve == btcec.S256() {
		// use `btcec` because elliptic's `UnmarshalCompressed` doesn't work for SEC Koblitz curves
		pk, err := btcec.ParsePubKey(pkBytes)
		if err != nil {
			return nil, invalidInputsErrorf("input %x isn't a compressed serialization of a %v key", pkBytes, a.algo.String())
		}
		// convert to a crypto/ecdsa key
		goPubKey = pk.ToECDSA()
	} else {
		return nil, invalidInputsErrorf("the input curve is not supported")
	}
	return &pubKeyECDSA{a, goPubKey}, nil
}

// prKeyECDSA is the private key of ECDSA, it implements the interface PrivateKey
type prKeyECDSA struct {
	// the signature algo
	alg *ecdsaAlgo
	// ecdsa private key
	goPrKey *ecdsa.PrivateKey
	// public key
	pubKey *pubKeyECDSA
}

var _ sign.PrivateKey = (*prKeyECDSA)(nil)

// Algorithm returns the algo related to the private key
func (sk *prKeyECDSA) Algorithm() sign.SigningAlgorithm {
	return sk.alg.algo
}

// Size returns the length of the private key in bytes
func (sk *prKeyECDSA) Size() int {
	switch sk.alg.algo {
	case sign.ECDSAP256:
		return PrKeyLenECDSAP256
	case sign.ECDSASecp256k1:
		return PrKeyLenECDSASecp256k1
	default:
		return bitsToBytes((sk.alg.curve.Params().N).BitLen())
	}
}

// PublicKey returns the public key associated to the private key
func (sk *prKeyECDSA) PublicKey() sign.PublicKey {
	// construct the public key once
	if sk.pubKey == nil {
		sk.pubKey = &pubKeyECDSA{
			alg:      sk.alg,
			goPubKey: &sk.goPrKey.PublicKey,
		}
	}
	return sk.pubKey
}

// given a private key (d), returns a raw encoding bytes(d) in big endian
// padded to the private key length
func (sk *prKeyECDSA) rawEncode() []byte {
	skBytes := sk.goPrKey.D.Bytes()
	nLen := sk.Size() // use the Size() method instead of calculating
	skEncoded := make([]byte, nLen)
	// pad sk with zeroes - ensure we don't go out of bounds
	if len(skBytes) <= nLen {
		copy(skEncoded[nLen-len(skBytes):], skBytes)
	} else {
		copy(skEncoded, skBytes[len(skBytes)-nLen:])
	}
	return skEncoded
}

// Encode returns a byte representation of a private key.
// a simple raw byte encoding in big endian is used for all curves
func (sk *prKeyECDSA) Encode() []byte {
	return sk.rawEncode()
}

// Equals test the equality of two private keys
func (sk *prKeyECDSA) Equals(other sign.PrivateKey) bool {
	// check the key type
	otherECDSA, ok := other.(*prKeyECDSA)
	if !ok {
		return false
	}
	// check the algorithm instead of curve pointer
	if sk.alg.algo != otherECDSA.alg.algo {
		return false
	}
	if sk.goPrKey == nil || sk.goPrKey.D == nil {
		return false
	}
	if otherECDSA.goPrKey == nil || otherECDSA.goPrKey.D == nil {
		return false
	}
	return sk.goPrKey.D.Cmp(otherECDSA.goPrKey.D) == 0
}

// String returns the hex string representation of the key.
func (sk *prKeyECDSA) String() string {
	return fmt.Sprintf("%#x", sk.Encode())
}

// pubKeyECDSA is the public key of ECDSA, it implements PublicKey
type pubKeyECDSA struct {
	// the signature algo
	alg *ecdsaAlgo
	// public key data
	goPubKey *ecdsa.PublicKey
}

var _ sign.PublicKey = (*pubKeyECDSA)(nil)

// Algorithm returns the the algo related to the private key
func (pk *pubKeyECDSA) Algorithm() sign.SigningAlgorithm {
	return pk.alg.algo
}

// Size returns the length of the public key in bytes
func (pk *pubKeyECDSA) Size() int {
	switch pk.alg.algo {
	case sign.ECDSAP256:
		return PubKeyLenECDSAP256
	case sign.ECDSASecp256k1:
		return PubKeyLenECDSASecp256k1
	default:
		return 2 * bitsToBytes((pk.goPubKey.Params().P).BitLen())
	}
}

// EncodeCompressed returns a compressed encoding according to X9.62 section 4.3.6.
// This compressed representation uses an extra byte to disambiguate parity.
// The expected input is a public key (x,y).
//
// Receiver point is guaranteed to be on curve and to be non-infinity because
// the package does not allow constructing infinity points or points not on curve.
func (pk *pubKeyECDSA) EncodeCompressed() []byte {
	return elliptic.MarshalCompressed(pk.goPubKey.Curve, pk.goPubKey.X, pk.goPubKey.Y)
}

// `rawEncode` returns a raw uncompressed encoding `bytes(x) || bytes(y)` given a public key (x,y).
// x and y are padded to the field size.
func (pk *pubKeyECDSA) rawEncode() []byte {
	xBytes := pk.goPubKey.X.Bytes()
	yBytes := pk.goPubKey.Y.Bytes()
	Plen := pk.Size() / 2 // use Size() method and divide by 2 for coordinate length
	pkEncoded := make([]byte, 2*Plen)
	// pad the public key coordinates with zeroes - ensure we don't go out of bounds
	if len(xBytes) <= Plen {
		copy(pkEncoded[Plen-len(xBytes):], xBytes)
	} else {
		copy(pkEncoded, xBytes[len(xBytes)-Plen:])
	}
	if len(yBytes) <= Plen {
		copy(pkEncoded[2*Plen-len(yBytes):], yBytes)
	} else {
		copy(pkEncoded[Plen:], yBytes[len(yBytes)-Plen:])
	}
	return pkEncoded
}

// Encode returns a byte representation of a public key.
// a simple uncompressed raw encoding X||Y is used for all curves
// X and Y are the big endian byte encoding of the x and y coordinates of the public key
func (pk *pubKeyECDSA) Encode() []byte {
	return pk.rawEncode()
}

// Equals test the equality of two public keys
func (pk *pubKeyECDSA) Equals(other sign.PublicKey) bool {
	// check the key type
	otherECDSA, ok := other.(*pubKeyECDSA)
	if !ok {
		return false
	}
	// check the algorithm instead of curve pointer
	if pk.alg.algo != otherECDSA.alg.algo {
		return false
	}
	return (pk.goPubKey.X.Cmp(otherECDSA.goPubKey.X) == 0) &&
		(pk.goPubKey.Y.Cmp(otherECDSA.goPubKey.Y) == 0)
}

// String returns the hex string representation of the key.
func (pk *pubKeyECDSA) String() string {
	return fmt.Sprintf("%#x", pk.Encode())
}
