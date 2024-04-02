//go:build !cgo && no_cgo
// +build !cgo,no_cgo

package crypto_test

import (
	"testing"

	"github.com/onflow/crypto"
	"github.com/stretchr/testify/assert"
)

// Test all public functions requiring cgo.
// These functions must panic if built without cgo.
func TestNoRelicPanic(t *testing.T) {
	assert.Panics(t, func() { crypto.GeneratePrivateKey(crypto.BLSBLS12381, nil) })
	assert.Panics(t, func() { crypto.DecodePrivateKey(crypto.BLSBLS12381, nil) })
	assert.Panics(t, func() { crypto.DecodePublicKey(crypto.BLSBLS12381, nil) })
	assert.Panics(t, func() { crypto.DecodePublicKeyCompressed(crypto.BLSBLS12381, nil) })
	assert.Panics(t, func() { crypto.NewExpandMsgXOFKMAC128("") })
	assert.Panics(t, func() { crypto.BLSInvalidSignature() })
	assert.Panics(t, func() { crypto.BLSGeneratePOP(nil) })
	assert.Panics(t, func() { crypto.BLSVerifyPOP(nil, nil) })
	assert.Panics(t, func() { crypto.AggregateBLSSignatures(nil) })
	assert.Panics(t, func() { crypto.AggregateBLSPrivateKeys(nil) })
	assert.Panics(t, func() { crypto.AggregateBLSPublicKeys(nil) })
	assert.Panics(t, func() { crypto.IdentityBLSPublicKey() })
	assert.Panics(t, func() { crypto.IsBLSAggregateEmptyListError(nil) })
	assert.Panics(t, func() { crypto.IsInvalidSignatureError(nil) })
	assert.Panics(t, func() { crypto.IsNotBLSKeyError(nil) })
	assert.Panics(t, func() { crypto.IsBLSSignatureIdentity(nil) })
	assert.Panics(t, func() { crypto.RemoveBLSPublicKeys(nil, nil) })
	assert.Panics(t, func() { crypto.VerifyBLSSignatureOneMessage(nil, nil, nil, nil) })
	assert.Panics(t, func() { crypto.VerifyBLSSignatureManyMessages(nil, nil, nil, nil) })
	assert.Panics(t, func() { crypto.BatchVerifyBLSSignaturesOneMessage(nil, nil, nil, nil) })
	assert.Panics(t, func() { crypto.SPOCKProve(nil, nil, nil) })
	assert.Panics(t, func() { crypto.SPOCKVerify(nil, nil, nil, nil) })
	assert.Panics(t, func() { crypto.SPOCKVerifyAgainstData(nil, nil, nil, nil) })
	assert.Panics(t, func() { crypto.NewBLSThresholdSignatureParticipant(nil, nil, 0, 0, nil, nil, "") })
	assert.Panics(t, func() { crypto.NewBLSThresholdSignatureInspector(nil, nil, 0, nil, "") })
	assert.Panics(t, func() { crypto.BLSReconstructThresholdSignature(0, 0, nil, nil) })
	assert.Panics(t, func() { crypto.EnoughShares(0, 0) })
	assert.Panics(t, func() { crypto.BLSThresholdKeyGen(0, 0, nil) })
	assert.Panics(t, func() { crypto.NewFeldmanVSS(0, 0, 0, nil, 0) })
	assert.Panics(t, func() { crypto.NewFeldmanVSSQual(0, 0, 0, nil, 0) })
	assert.Panics(t, func() { crypto.NewJointFeldman(0, 0, 0, nil) })
}
