//go:build !cgo && no_cgo
// +build !cgo,no_cgo

package crypto_test

import (
	"testing"

	"github.com/onflow/crypto"
	"github.com/onflow/crypto/sign"
	"github.com/onflow/crypto/sign/bls"
	"github.com/stretchr/testify/assert"
)

// Test all public functions requiring cgo.
// These functions must panic if built without cgo.
func TestNoRelicPanic(t *testing.T) {
	assert.Panics(t, func() { _, _ = sign.GeneratePrivateKey(sign.BLSBLS12381, nil) })
	assert.Panics(t, func() { _, _ = sign.DecodePrivateKey(sign.BLSBLS12381, nil) })
	assert.Panics(t, func() { _, _ = sign.DecodePublicKey(sign.BLSBLS12381, nil) })
	assert.Panics(t, func() { _, _ = sign.DecodePublicKeyCompressed(sign.BLSBLS12381, nil) })
	assert.Panics(t, func() { _ = bls.NewExpandMsgXOFKMAC128("") })
	assert.Panics(t, func() { _ = bls.BLSInvalidSignature() })
	assert.Panics(t, func() { _, _ = bls.BLSGeneratePOP(nil) })
	assert.Panics(t, func() { _, _ = bls.BLSVerifyPOP(nil, nil) })
	assert.Panics(t, func() { _, _ = bls.AggregateBLSSignatures(nil) })
	assert.Panics(t, func() { _, _ = bls.AggregateBLSPrivateKeys(nil) })
	assert.Panics(t, func() { _, _ = bls.AggregateBLSPublicKeys(nil) })
	assert.Panics(t, func() { _ = bls.IdentityBLSPublicKey() })
	assert.Panics(t, func() { _ = bls.IsBLSAggregateEmptyListError(nil) })
	assert.Panics(t, func() { _ = bls.IsInvalidSignatureError(nil) })
	assert.Panics(t, func() { _ = bls.IsNotBLSKeyError(nil) })
	assert.Panics(t, func() { _ = bls.IsBLSSignatureIdentity(nil) })
	assert.Panics(t, func() { _, _ = bls.RemoveBLSPublicKeys(nil, nil) })
	assert.Panics(t, func() { _, _ = bls.VerifyBLSSignatureOneMessage(nil, nil, nil, nil) })
	assert.Panics(t, func() { _, _ = bls.VerifyBLSSignatureManyMessages(nil, nil, nil, nil) })
	assert.Panics(t, func() { _, _ = bls.BatchVerifyBLSSignaturesOneMessage(nil, nil, nil, nil) })
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
