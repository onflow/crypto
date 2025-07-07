//go:build !cgo && no_cgo
// +build !cgo,no_cgo

package crypto

// This file enables the build of the library when cgo is disabled, i.e when the environment
// variable `CGO_ENABLED` is set to `0`.
// The build without cgo succeeds but disables all algorithms working with
// the BLS12-381 curve (BLS signature, BLS threshold signature, BLS-based DKG and BLS-SPoCK).
// Any call to any of these algorithms would panic.

import (
	"fmt"

	"github.com/onflow/crypto/hash"
	"github.com/onflow/crypto/sign"
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
	algo sign.SigningAlgorithm
}


func (a *blsBLS12381Algo) GeneratePrivateKey(ikm []byte) (sign.PrivateKey, error) {
	panic(withFeature("BLS signature"))
}

func (a *blsBLS12381Algo) DecodePrivateKey(privateKeyBytes []byte) (sign.PrivateKey, error) {
	panic(withFeature("BLS signature"))
}

func (a *blsBLS12381Algo) DecodePublicKey(publicKeyBytes []byte) (sign.PublicKey, error) {
	panic(withFeature("BLS signature"))
}

func (a *blsBLS12381Algo) DecodePublicKeyCompressed(publicKeyBytes []byte) (sign.PublicKey, error) {
	panic(withFeature("BLS signature"))
}

func (a *blsBLS12381Algo) SignatureFormatCheck(sig sign.Signature) (bool, error) {
	panic(withFeature("BLS signature"))
}

func NewExpandMsgXOFKMAC128(domainTag string) hash.Hasher {
	panic(withFeature("BLS hasher"))
}

func IsBLSSignatureIdentity(s sign.Signature) bool {
	panic(withFeature("BLS signature"))
}

func BLSInvalidSignature() sign.Signature {
	panic(withFeature("BLS signature"))
}

func isG2Compressed() bool {
	panic(withFeature("BLS12-381 curve"))
}

func NewBLSThresholdSignatureParticipant(
	groupPublicKey sign.PublicKey,
	sharePublicKeys []sign.PublicKey,
	threshold int,
	myIndex int,
	myPrivateKey sign.PrivateKey,
	message []byte,
	dsTag string,
) (ThresholdSignatureParticipant, error) {
	panic(withFeature("BLS threshold signature"))
}

func NewBLSThresholdSignatureInspector(
	groupPublicKey sign.PublicKey,
	sharePublicKeys []sign.PublicKey,
	threshold int,
	message []byte,
	dsTag string,
) (ThresholdSignatureInspector, error) {
	panic(withFeature("BLS threshold signature"))
}

func BLSReconstructThresholdSignature(size int, threshold int,
	shares []sign.Signature, signers []int) (sign.Signature, error) {
	_ = duplicatedSignerErrorf("")
	_ = notEnoughSharesErrorf("")
	panic(withFeature("BLS threshold signature"))
}

func EnoughShares(threshold int, sharesNumber int) (bool, error) {
	panic(withFeature("BLS threshold signature"))
}

func BLSThresholdKeyGen(size int, threshold int, seed []byte) ([]sign.PrivateKey,
	[]sign.PublicKey, sign.PublicKey, error) {
	panic(withFeature("BLS threshold signature"))
}

func NewFeldmanVSS(size int, threshold int, myIndex int,
	processor DKGProcessor, dealerIndex int) (DKGState, error) {
	_, _ = newDKGCommon(size, threshold, myIndex,
		processor, dealerIndex)
	panic(withFeature("BLS-DKG"))
}

func NewFeldmanVSSQual(size int, threshold int, myIndex int,
	processor DKGProcessor, dealerIndex int) (DKGState, error) {
	_ = dkgFailureErrorf("")
	_ = dkgInvalidStateTransitionErrorf("")
	panic(withFeature("BLS-DKG"))
}

func NewJointFeldman(size int, threshold int, myIndex int,
	processor DKGProcessor) (DKGState, error) {
	_ = feldmanVSSShare | feldmanVSSVerifVec | feldmanVSSComplaint | feldmanVSSComplaintAnswer
	panic(withFeature("BLS-DKG"))
}

func SPOCKProve(sk sign.PrivateKey, data []byte, kmac hash.Hasher) (sign.Signature, error) {
	panic(withFeature("BLS-SPoCK"))
}

func SPOCKVerifyAgainstData(pk sign.PublicKey, proof sign.Signature, data []byte, kmac hash.Hasher) (bool, error) {
	panic(withFeature("BLS-SPoCK"))
}

func SPOCKVerify(pk1 sign.PublicKey, proof1 sign.Signature, pk2 sign.PublicKey, proof2 sign.Signature) (bool, error) {
	panic(withFeature("BLS-SPoCK"))
}

func BLSGeneratePOP(sk sign.PrivateKey) (sign.Signature, error) {
	panic(withFeature("BLS multi-sig"))
}

func BLSVerifyPOP(pk sign.PublicKey, s sign.Signature) (bool, error) {
	panic(withFeature("BLS multi-sig"))
}

func AggregateBLSSignatures(sigs []sign.Signature) (sign.Signature, error) {
	panic(withFeature("BLS multi-sig"))
}

func AggregateBLSPrivateKeys(keys []sign.PrivateKey) (sign.PrivateKey, error) {
	panic(withFeature("BLS multi-sig"))
}

func AggregateBLSPublicKeys(keys []sign.PublicKey) (sign.PublicKey, error) {
	panic(withFeature("BLS multi-sig"))
}

func IdentityBLSPublicKey() sign.PublicKey {
	panic(withFeature("BLS multi-sig"))
}

func RemoveBLSPublicKeys(aggKey sign.PublicKey, keysToRemove []sign.PublicKey) (sign.PublicKey, error) {
	panic(withFeature("BLS multi-sig"))
}

func VerifyBLSSignatureOneMessage(
	pks []sign.PublicKey, s sign.Signature, message []byte, kmac hash.Hasher,
) (bool, error) {
	panic(withFeature("BLS multi-sig"))
}

func VerifyBLSSignatureManyMessages(
	pks []sign.PublicKey, s sign.Signature, messages [][]byte, kmac []hash.Hasher,
) (bool, error) {
	panic(withFeature("BLS multi-sig"))
}

func BatchVerifyBLSSignaturesOneMessage(
	pks []sign.PublicKey, sigs []sign.Signature, message []byte, kmac hash.Hasher,
) ([]bool, error) {
	panic(withFeature("BLS multi-sig"))
}

func IsBLSAggregateEmptyListError(err error) bool {
	panic(withFeature("BLS multi-sig"))
}

func IsNotBLSKeyError(err error) bool {
	panic(withFeature("BLS multi-sig"))
}

func IsInvalidSignatureError(err error) bool {
	panic(withFeature("BLS multi-sig"))
}
