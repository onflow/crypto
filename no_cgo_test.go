//go:build !cgo && no_cgo
// +build !cgo,no_cgo

package crypto_test

import (
	"testing"

	"github.com/onflow/crypto"
	"github.com/onflow/crypto/sign"
	"github.com/stretchr/testify/assert"
)

// Test all public functions requiring cgo.
// These functions must panic if built without cgo.
func TestNoRelicPanic(t *testing.T) {
	assert.Panics(t, func() { _, _ = crypto.GeneratePrivateKey(sign.BLSBLS12381, nil) })
	assert.Panics(t, func() { _, _ = crypto.DecodePrivateKey(sign.BLSBLS12381, nil) })
	assert.Panics(t, func() { _, _ = crypto.DecodePublicKey(sign.BLSBLS12381, nil) })
	assert.Panics(t, func() { _, _ = crypto.DecodePublicKeyCompressed(sign.BLSBLS12381, nil) })
	assert.Panics(t, func() { _ = crypto.NewExpandMsgXOFKMAC128("") })
	assert.Panics(t, func() { _ = crypto.BLSInvalidSignature() })
	assert.Panics(t, func() { _, _ = crypto.BLSGeneratePOP(nil) })
	assert.Panics(t, func() { _, _ = crypto.BLSVerifyPOP(nil, nil) })
	assert.Panics(t, func() { _, _ = crypto.AggregateBLSSignatures(nil) })
	assert.Panics(t, func() { _, _ = crypto.AggregateBLSPrivateKeys(nil) })
	assert.Panics(t, func() { _, _ = crypto.AggregateBLSPublicKeys(nil) })
	assert.Panics(t, func() { _ = crypto.IdentityBLSPublicKey() })
	assert.Panics(t, func() { _ = crypto.IsBLSAggregateEmptyListError(nil) })
	assert.Panics(t, func() { _ = crypto.IsInvalidSignatureError(nil) })
	assert.Panics(t, func() { _ = crypto.IsNotBLSKeyError(nil) })
	assert.Panics(t, func() { _ = crypto.IsBLSSignatureIdentity(nil) })
	assert.Panics(t, func() { _, _ = crypto.RemoveBLSPublicKeys(nil, nil) })
	assert.Panics(t, func() { _, _ = crypto.VerifyBLSSignatureOneMessage(nil, nil, nil, nil) })
	assert.Panics(t, func() { _, _ = crypto.VerifyBLSSignatureManyMessages(nil, nil, nil, nil) })
	assert.Panics(t, func() { _, _ = crypto.BatchVerifyBLSSignaturesOneMessage(nil, nil, nil, nil) })
	assert.Panics(t, func() { _, _ = crypto.SPOCKProve(nil, nil, nil) })
	assert.Panics(t, func() { _, _ = crypto.SPOCKVerify(nil, nil, nil, nil) })
	assert.Panics(t, func() { _, _ = crypto.SPOCKVerifyAgainstData(nil, nil, nil, nil) })
	assert.Panics(t, func() { _, _ = crypto.NewBLSThresholdSignatureParticipant(nil, nil, 0, 0, nil, nil, "") })
	assert.Panics(t, func() { _, _ = crypto.NewBLSThresholdSignatureInspector(nil, nil, 0, nil, "") })
	assert.Panics(t, func() { _, _ = crypto.BLSReconstructThresholdSignature(0, 0, nil, nil) })
	assert.Panics(t, func() { _, _ = crypto.EnoughShares(0, 0) })
	assert.Panics(t, func() { _, _, _, _ = crypto.BLSThresholdKeyGen(0, 0, nil) })
	assert.Panics(t, func() { _, _ = crypto.NewFeldmanVSS(0, 0, 0, nil, 0) })
	assert.Panics(t, func() { _, _ = crypto.NewFeldmanVSSQual(0, 0, 0, nil, 0) })
	assert.Panics(t, func() { _, _ = crypto.NewJointFeldman(0, 0, 0, nil) })
}
