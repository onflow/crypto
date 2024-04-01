//go:build !cgo
// +build !cgo

package crypto

import (
	"fmt"

	"github.com/onflow/crypto/hash"
)

const (
	SignatureLenBLSBLS12381 = 0
	PubKeyLenBLSBLS12381    = 0
	PrKeyLenBLSBLS12381     = 0
)

func initBLS12381() {}

func withFeature(feature string) string {
	return fmt.Sprintf("%s is only supported with cgo, rebuild with CGO_ENABLED=1\n", feature)
}

type blsBLS12381Algo struct {
	algo SigningAlgorithm
}

// BLS context on the BLS 12-381 curve
var blsInstance *blsBLS12381Algo

func (a *blsBLS12381Algo) generatePrivateKey(ikm []byte) (PrivateKey, error) {
	panic(withFeature("BLS signature"))
}

func (a *blsBLS12381Algo) decodePrivateKey(privateKeyBytes []byte) (PrivateKey, error) {
	panic(withFeature("BLS signature"))
}

func (a *blsBLS12381Algo) decodePublicKey(publicKeyBytes []byte) (PublicKey, error) {
	panic(withFeature("BLS signature"))
}

func (a *blsBLS12381Algo) decodePublicKeyCompressed(publicKeyBytes []byte) (PublicKey, error) {
	panic(withFeature("BLS signature"))
}

func NewExpandMsgXOFKMAC128(domainTag string) hash.Hasher {
	panic(withFeature("BLS hasher"))
}

func IsBLSSignatureIdentity(s Signature) bool {
	panic(withFeature("BLS signature"))
}

func BLSInvalidSignature() Signature {
	panic(withFeature("BLS signature"))
}

func isG2Compressed() bool {
	panic(withFeature("BLS12-381 curve"))
}

func NewBLSThresholdSignatureParticipant(
	groupPublicKey PublicKey,
	sharePublicKeys []PublicKey,
	threshold int,
	myIndex int,
	myPrivateKey PrivateKey,
	message []byte,
	dsTag string,
) (ThresholdSignatureParticipant, error) {
	panic(withFeature("BLS threshold signature"))
}

func NewBLSThresholdSignatureInspector(
	groupPublicKey PublicKey,
	sharePublicKeys []PublicKey,
	threshold int,
	message []byte,
	dsTag string,
) (ThresholdSignatureInspector, error) {
	panic(withFeature("BLS threshold signature"))
}

func BLSReconstructThresholdSignature(size int, threshold int,
	shares []Signature, signers []int) (Signature, error) {
	panic(withFeature("BLS threshold signature"))
}

func EnoughShares(threshold int, sharesNumber int) (bool, error) {
	panic(withFeature("BLS threshold signature"))
}

func BLSThresholdKeyGen(size int, threshold int, seed []byte) ([]PrivateKey,
	[]PublicKey, PublicKey, error) {
	panic(withFeature("BLS threshold signature"))
}

func NewFeldmanVSS(size int, threshold int, myIndex int,
	processor DKGProcessor, dealerIndex int) (DKGState, error) {
	panic(withFeature("BLS-DKG"))
}

func NewFeldmanVSSQual(size int, threshold int, myIndex int,
	processor DKGProcessor, dealerIndex int) (DKGState, error) {
	panic(withFeature("BLS-DKG"))
}

func NewJointFeldman(size int, threshold int, myIndex int,
	processor DKGProcessor) (DKGState, error) {
	panic(withFeature("BLS-DKG"))
}

func SPOCKProve(sk PrivateKey, data []byte, kmac hash.Hasher) (Signature, error) {
	panic(withFeature("BLS-SPoCK"))
}

func SPOCKVerifyAgainstData(pk PublicKey, proof Signature, data []byte, kmac hash.Hasher) (bool, error) {
	panic(withFeature("BLS-SPoCK"))
}

func SPOCKVerify(pk1 PublicKey, proof1 Signature, pk2 PublicKey, proof2 Signature) (bool, error) {
	panic(withFeature("BLS-SPoCK"))
}
