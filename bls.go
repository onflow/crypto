// +build relic

package crypto

import (
	"errors"
	"fmt"
	"sync"

	"github.com/dapperlabs/flow-go/crypto/hash"
)

// blsBLS12381Algo, embeds SignAlgo
type blsBLS12381Algo struct {
	// points to Relic context of BLS12-381 with all the parameters
	context ctx
	// embeds commonSigner
	*commonSigner
}

//  Once variables to use a unique instance
var blsInstance *blsBLS12381Algo
var once sync.Once

func newBlsBLS12381() *blsBLS12381Algo {
	once.Do(func() {
		blsInstance = &(blsBLS12381Algo{
			commonSigner: &commonSigner{BLS_BLS12381},
		})
		blsInstance.init()
	})
	return blsInstance
}

// Sign signs an array of bytes
// This function does not modify the private key, even temporarily
// If the hasher used is KMAC128, it is not modified by the function, even temporarily
func (sk *PrKeyBLS_BLS12381) Sign(data []byte, kmac hash.Hasher) (Signature, error) {
	if kmac == nil {
		return nil, errors.New("Sign requires a Hasher")
	}
	// hash the input to 128 bytes
	h := kmac.ComputeHash(data)
	return newBlsBLS12381().blsSign(&sk.scalar, h), nil
}

const BLS_KMACFunction = "H2C"

// NewBLS_KMAC returns a new KMAC128 instance with the right parameters
// chosen for BLS signatures and verifications
// tag is the domain separation tag
func NewBLS_KMAC(tag string) hash.Hasher {
	// the error is ignored as the parameter lengths are in the correct range of kmac
	kmac, _ := hash.NewKMAC_128([]byte(tag), []byte("BLS_KMACFunction"), OpSwUInputLenBLS_BLS12381)
	return kmac
}

// Verify verifies a signature of a byte array using the public key
// The function assumes the public key is in the valid G2 subgroup as it is
// either generated by the library or read through the DecodePublicKey function.
// This function does not modify the public key, even temporarily
// If the hasher used is KMAC128, it is not modified by the function, even temporarily
func (pk *PubKeyBLS_BLS12381) Verify(s Signature, data []byte, kmac hash.Hasher) (bool, error) {
	if kmac == nil {
		return false, errors.New("VerifyBytes requires a Hasher")
	}
	// hash the input to 128 bytes
	h := kmac.ComputeHash(data)

	return newBlsBLS12381().blsVerify(&pk.point, s, h), nil
}

// generatePrivateKey generates a private key for BLS on BLS12381 curve
// The minimum size of the input seed is 48 bytes (for a sceurity of 128 bits)
func (a *blsBLS12381Algo) generatePrivateKey(seed []byte) (PrivateKey, error) {
	if len(seed) < KeyGenSeedMinLenBLS_BLS12381 {
		return nil, fmt.Errorf("seed should be at least %d bytes",
			KeyGenSeedMinLenBLS_BLS12381)
	}

	sk := &PrKeyBLS_BLS12381{
		// public key is not computed
		pk: nil,
	}

	// maps the seed to a private key
	mapKeyZr(&(sk.scalar), seed)
	return sk, nil
}

func (a *blsBLS12381Algo) decodePrivateKey(privateKeyBytes []byte) (PrivateKey, error) {
	if len(privateKeyBytes) != prKeyLengthBLS_BLS12381 {
		return nil, fmt.Errorf("the input length has to be equal to %d", prKeyLengthBLS_BLS12381)
	}
	sk := &PrKeyBLS_BLS12381{
		pk: nil,
	}
	readScalar(&sk.scalar, privateKeyBytes)
	if sk.scalar.checkMembershipZr() {
		return sk, nil
	}
	return nil, errors.New("the private key is not a valid BLS12-381 curve key")
}

func (a *blsBLS12381Algo) decodePublicKey(publicKeyBytes []byte) (PublicKey, error) {
	if len(publicKeyBytes) != pubKeyLengthBLS_BLS12381 {
		return nil, fmt.Errorf("the input length has to be equal to %d", pubKeyLengthBLS_BLS12381)
	}
	var pk PubKeyBLS_BLS12381
	if readPointG2(&pk.point, publicKeyBytes) != nil {
		return nil, errors.New("the input slice does not encode a public key")
	}
	if pk.point.checkMembershipG2() {
		return &pk, nil
	}
	return nil, errors.New("the public key is not a valid BLS12-381 curve key")

}

// PrKeyBLS_BLS12381 is the private key of BLS using BLS12_381, it implements PrivateKey
type PrKeyBLS_BLS12381 struct {
	// public key
	pk *PubKeyBLS_BLS12381
	// private key data
	scalar scalar
}

func (sk *PrKeyBLS_BLS12381) Algorithm() SigningAlgorithm {
	return BLS_BLS12381
}

func (sk *PrKeyBLS_BLS12381) KeySize() int {
	return PrKeyLenBLS_BLS12381
}

// computePublicKey generates the public key corresponding to
// the input private key. The function makes sure the piblic key
// is valid in G2
func (sk *PrKeyBLS_BLS12381) computePublicKey() {
	var newPk PubKeyBLS_BLS12381
	// compute public key pk = g2^sk
	_G2scalarGenMult(&(newPk.point), &(sk.scalar))
	sk.pk = &newPk
}

func (sk *PrKeyBLS_BLS12381) PublicKey() PublicKey {
	if sk.pk != nil {
		return sk.pk
	}
	sk.computePublicKey()
	return sk.pk
}

func (a *PrKeyBLS_BLS12381) Encode() ([]byte, error) {
	dest := make([]byte, prKeyLengthBLS_BLS12381)
	writeScalar(dest, &a.scalar)
	return dest, nil
}

func (sk *PrKeyBLS_BLS12381) Equals(other PrivateKey) bool {
	otherBLS, ok := other.(*PrKeyBLS_BLS12381)
	if !ok {
		return false
	}
	return sk.scalar.equals(&otherBLS.scalar)
}

// PubKeyBLS_BLS12381 is the public key of BLS using BLS12_381,
// it implements PublicKey
type PubKeyBLS_BLS12381 struct {
	// public key data
	point pointG2
}

func (pk *PubKeyBLS_BLS12381) Algorithm() SigningAlgorithm {
	return BLS_BLS12381
}

func (pk *PubKeyBLS_BLS12381) KeySize() int {
	return PubKeyLenBLS_BLS12381
}

func (a *PubKeyBLS_BLS12381) Encode() ([]byte, error) {
	dest := make([]byte, pubKeyLengthBLS_BLS12381)
	writePointG2(dest, &a.point)
	return dest, nil
}

func (pk *PubKeyBLS_BLS12381) Equals(other PublicKey) bool {
	otherBLS, ok := other.(*PubKeyBLS_BLS12381)
	if !ok {
		return false
	}
	return pk.point.equals(&otherBLS.point)
}
