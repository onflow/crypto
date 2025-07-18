//go:build cgo && !no_cgo
// +build cgo,!no_cgo

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

// #include "bls_thresholdsign_include.h"
import "C"

import (
	"fmt"
	"sync"

	"github.com/onflow/crypto/hash"
)

// BLS-based threshold signature is an implementation of
// a threshold signature scheme using BLS signatures
// on the BLS 12-381 curve.
// The BLS settings are the same as in the signature
// scheme defined in the package.
//
// The package provides two ways to use BLS-based threshold signature:
// - a stateful api where an object holds all information
//  of the protocol, implementing [ThresholdSignatureInspector]
//  and [ThresholdSignatureParticipant]. This is the recommended safe way
//  to guarantee correctness and reduce potential integration vulnerabilities.
// - stateless api with signature reconstruction. Verifying and storing
//  the message as well as the signature shares have to be managed by
//  the upper layer outside of the package.

// blsThresholdSignatureParticipant implements ThresholdSignatureParticipant
// based on the BLS signature scheme
type blsThresholdSignatureParticipant struct {
	// embed the follower
	*blsThresholdSignatureInspector
	// the index of the current participant
	myIndex int
	// the current participant private key (a threshold KG output)
	myPrivateKey PrivateKey
}

var _ ThresholdSignatureParticipant = (*blsThresholdSignatureParticipant)(nil)

// blsThresholdSignatureInspector implements ThresholdSignatureInspector
// based on the BLS signature scheme
type blsThresholdSignatureInspector struct {
	// size `n` of the group
	size int
	// the threshold `t` of the scheme where `t+1` shares are
	// required to reconstruct a signature
	threshold int
	// the group public key (a threshold KG output)
	groupPublicKey PublicKey
	// the group public key shares (a threshold KG output)
	publicKeyShares []PublicKey
	// the hasher to be used for all signatures
	hasher hash.Hasher
	// the message to be signed. Signature shares and the threshold signature
	// are verified against this message
	message []byte
	// the valid signature shares collected from other participants
	shares map[index]Signature
	// the threshold group signature.
	// It is equal to nil if the collected shares are less than `t+1`.
	thresholdSignature Signature
	// lock for atomic operations
	lock sync.RWMutex
}

var _ ThresholdSignatureInspector = (*blsThresholdSignatureInspector)(nil)

// NewBLSThresholdSignatureParticipant creates a new instance of a protocol participant using BLS.
// A participant is able to follow the protocol as well as contribute to the threshold signing.
// It implements the [ThresholdSignatureParticipant] interface.
//
// A new instance is needed for each set of public keys and message.
// If the key set or message change, a new structure needs to be instantiated.
// The `n` participants are identified using their public indices in the range `[0, n-1]`,
// as well as their public key shares.
// The input `sharePublicKeys` is an array of `n` keys ordered following the public indices:
// a participant assigned to index `i` uses the public key `sharePublicKeys[i]`.
// The current participant is defined by `myIndex` and holds the input private key
// corresponding to `sharePublicKeys[myIndex]`.
//
// The function returns:
// - (nil, invalidInputsError) if:
//   - `n` is not in [`ThresholdSignMinSize`, `ThresholdSignMaxSize`]
//   - threshold value is not in interval `[1, n-1]`
//   - input private key and public key at my index do not match
//   - (nil, errNotBLSKey) if the private or at least one public key is not of type BLS BLS12-381.
//   - (pointer, nil) otherwise
func NewBLSThresholdSignatureParticipant(
	groupPublicKey PublicKey,
	sharePublicKeys []PublicKey,
	threshold int,
	myIndex int,
	myPrivateKey PrivateKey,
	message []byte,
	dsTag string,
) (*blsThresholdSignatureParticipant, error) {

	size := len(sharePublicKeys)
	if myIndex >= size || myIndex < 0 {
		return nil, invalidInputsErrorf(
			"the current index must be between 0 and %d, got %d",
			size-1, myIndex)
	}

	// check private key is BLS key
	if _, ok := myPrivateKey.(*prKeyBLSBLS12381); !ok {
		return nil, fmt.Errorf("private key of participant %d is not valid: %w", myIndex, errNotBLSKey)
	}

	// create the follower
	follower, err := NewBLSThresholdSignatureInspector(groupPublicKey, sharePublicKeys, threshold, message, dsTag)
	if err != nil {
		return nil, fmt.Errorf("create a threshold signature follower failed: %w", err)
	}

	// check the private key, index and corresponding public key are consistent
	currentPublicKey := sharePublicKeys[myIndex]
	if !myPrivateKey.PublicKey().Equals(currentPublicKey) {
		return nil, invalidInputsErrorf("private key is not matching public key at index %d", myIndex)
	}

	return &blsThresholdSignatureParticipant{
		blsThresholdSignatureInspector: follower,
		myIndex:                        myIndex,      // current participant index
		myPrivateKey:                   myPrivateKey, // myPrivateKey is the current participant's own private key share
	}, nil
}

// NewBLSThresholdSignatureInspector creates a new instance of the protocol follower using BLS.
// The returned instance implements [ThresholdSignatureInspector].
//
// A new instance is needed for each set of public keys and message.
// If the key set or message change, a new structure needs to be instantiated.
// The `n` participants are identified using their public indices in the range `[0, n-1]`,
// as well as their public key shares.
// The input `sharePublicKeys` is an array of `n` keys ordered following the public indices:
// a participant assigned to index `i` uses the public key `sharePublicKeys[i]`.
//
// The function returns:
// - (nil, invalidInputsError) if:
//   - `n` is not in [`ThresholdSignMinSize`, `ThresholdSignMaxSize`]
//   - threshold value is not in interval `[1, n-1]`
//   - (nil, errNotBLSKey) at least one public key is not of type pubKeyBLSBLS12381
//   - (pointer, nil) otherwise
func NewBLSThresholdSignatureInspector(
	groupPublicKey PublicKey,
	sharePublicKeys []PublicKey,
	threshold int,
	message []byte,
	dsTag string,
) (*blsThresholdSignatureInspector, error) {

	size := len(sharePublicKeys)
	if size < ThresholdSignMinSize || size > ThresholdSignMaxSize {
		return nil, invalidInputsErrorf(
			"size should be between %d and %d, got %d",
			ThresholdSignMinSize, ThresholdSignMaxSize, size)
	}
	if threshold >= size || threshold < MinimumThreshold {
		return nil, invalidInputsErrorf(
			"the threshold must be between %d and %d, got %d",
			MinimumThreshold, size-1, threshold)
	}

	// check keys are BLS keys
	for i, pk := range sharePublicKeys {
		if _, ok := pk.(*pubKeyBLSBLS12381); !ok {
			return nil, fmt.Errorf("key at index %d is invalid: %w", i, errNotBLSKey)
		}
	}
	if _, ok := groupPublicKey.(*pubKeyBLSBLS12381); !ok {
		return nil, fmt.Errorf("group key is invalid: %w", errNotBLSKey)
	}

	return &blsThresholdSignatureInspector{
		size:               size,
		threshold:          threshold,
		message:            message,
		hasher:             NewExpandMsgXOFKMAC128(dsTag),
		shares:             make(map[index]Signature),
		thresholdSignature: nil,
		groupPublicKey:     groupPublicKey,  // groupPublicKey is the group public key corresponding to the group secret key
		publicKeyShares:    sharePublicKeys, // sharePublicKeys are the public key shares corresponding to the private key shares
	}, nil
}

// SignShare generates a signature share using the current private key share.
//
// The function does not add the share to the internal pool of shares and does
// not update the internal state.
// This function is thread safe and non-blocking
//
// The function returns
//   - (nil, error) if an unexpected error occurs
//   - (signature, nil) otherwise
func (s *blsThresholdSignatureParticipant) SignShare() (Signature, error) {
	share, err := s.myPrivateKey.Sign(s.message, s.hasher)
	if err != nil {
		return nil, fmt.Errorf("share signing failed: %w", err)
	}
	return share, nil
}

// validIndex returns invalidInputsError error if given index is valid and nil otherwise.
// This function is thread safe.
func (s *blsThresholdSignatureInspector) validIndex(orig int) error {
	if orig >= s.size || orig < 0 {
		return invalidInputsErrorf(
			"origin input is invalid, should be positive less than %d, got %d",
			s.size, orig)
	}
	return nil
}

// VerifyShare verifies the input signature against the stored message and stored
// key at the input index.
//
// This function does not update the internal state and is thread-safe.
// Returns:
//   - (true, nil) if the signature is valid
//   - (false, nil) if `orig` is valid but the signature share does not verify against
//     the public key share and message.
//   - (false, invalidInputsError) if `orig` is an invalid index value
//   - (false, error) for all other unexpected errors
func (s *blsThresholdSignatureInspector) VerifyShare(orig int, share Signature) (bool, error) {
	// validate index
	if err := s.validIndex(orig); err != nil {
		return false, err
	}
	return s.publicKeyShares[orig].Verify(share, s.message, s.hasher)
}

// VerifyThresholdSignature verifies the input signature against the stored
// message and stored group public key.
//
// This function does not update the internal state and is thread-safe.
//
// Returns:
//   - (true, nil): if the signature is valid
//   - (false, nil): if the signature is invalid
//   - (false, error): for all other unexpected errors
func (s *blsThresholdSignatureInspector) VerifyThresholdSignature(thresholdSignature Signature) (bool, error) {
	return s.groupPublicKey.Verify(thresholdSignature, s.message, s.hasher)
}

// EnoughShares indicates whether enough shares have been accumulated to reconstruct
// a group signature.
//
// This function is thread-safe.
//
// Returns:
//   - true: if and only if at least (threshold+1) shares were added
func (s *blsThresholdSignatureInspector) EnoughShares() bool {
	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.enoughShares()
}

// non thread safe version of EnoughShares
func (s *blsThresholdSignatureInspector) enoughShares() bool {
	// len(s.signers) is always <= s.threshold + 1
	return len(s.shares) == (s.threshold + 1)
}

// HasShare checks whether the internal map contains the share of the given index.
// This function is thread-safe and locks the internal state.
//
// Returns:
//   - (false, invalidInputsError): if the index is invalid
//   - (false, nil): if index is valid and share is not in the map
//   - (true, nil): if index is valid and share is in the map
func (s *blsThresholdSignatureInspector) HasShare(orig int) (bool, error) {
	// validate index
	if err := s.validIndex(orig); err != nil {
		return false, err
	}

	s.lock.RLock()
	defer s.lock.RUnlock()

	return s.hasShare(index(orig)), nil
}

// non thread safe version of HasShare, and assumes input is valid
func (s *blsThresholdSignatureInspector) hasShare(orig index) bool {
	_, ok := s.shares[orig]
	return ok
}

// TrustedAdd adds a signature share to the internal pool of shares
// without verifying the signature against the message and the participant's
// public key. Adding an invalid signature share is not considered an error and does
// not compromise the protocol security. However, the reconstruction of the threshold signature
// fails if at least one invalid signature share was added. `VerifyShare` can be used to verify
// the signature share before adding it to the internal pool through `TrustedAdd`.
// This function is thread-safe and locks the internal state.
//
// The share is only added if the signer index is valid and has not been
// added yet. Moreover, the share is added only if not enough shares were collected.
//
// Returns:
//   - (true, nil): if enough signature shares were already collected and no error occurred
//   - (false, nil): if not enough shares were collected and no error occurred
//   - (false, invalidInputsError): if index is invalid
//   - (false, duplicatedSignerError): if a signature for the index was previously added
func (s *blsThresholdSignatureInspector) TrustedAdd(orig int, share Signature) (bool, error) {
	// validate index
	if err := s.validIndex(orig); err != nil {
		return false, err
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	if s.hasShare(index(orig)) {
		return false, duplicatedSignerErrorf("share for %d was already added", orig)
	}

	if s.enoughShares() {
		return true, nil
	}
	s.shares[index(orig)] = share
	return s.enoughShares(), nil
}

// VerifyAndAdd verifies a signature share (same as `VerifyShare`),
// and attempts to add the share to the local pool of shares.
// This function is thread-safe and locks the internal state.
//
// The share is only added if the signature is valid, the signer index is valid,
// and has not been added yet. Moreover, the share is not added if enough shares were already collected.
//
// Returns:
//   - First boolean: true if the share is valid and no error is returned, false otherwise.
//   - Second boolean: true if enough shares were collected and no error is returned, false otherwise.
//   - Error:
//   - invalidInputsError: if input index is invalid. A signature that doesn't verify against the signer's
//     public key is not considered an invalid input.
//   - duplicatedSignerError: if signer was already added.
//   - other errors: if an unexpected exception occurred.
func (s *blsThresholdSignatureInspector) VerifyAndAdd(orig int, share Signature) (
	shareIsValid bool, enoughSharesCollected bool, err error) {
	// validate index
	if err := s.validIndex(orig); err != nil {
		return false, false, err
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	// check share is new
	if s.hasShare(index(orig)) {
		return false, false, duplicatedSignerErrorf("share for %d was already added", orig)
	}

	// verify the share
	verif, err := s.publicKeyShares[index(orig)].Verify(share, s.message, s.hasher)
	if err != nil {
		return false, false, fmt.Errorf("verification of share failed: %w", err)
	}

	enough := s.enoughShares()
	if verif && !enough {
		s.shares[index(orig)] = share
	}
	return verif, s.enoughShares(), nil
}

// ThresholdSignature returns the threshold signature if the threshold was reached.
// For safety, the function attempts the reconstruction and only returns a signature that is valid against the group public key.
// This is done by first reconstructing the signature and then validating it against the group public key.
// The reconstructed may fail the validation if at least one signature share added via `TrustedAdd` is invalid.
// The valid threshold signature is reconstructed only once and is cached for subsequent calls.
//
// The function is thread-safe.
//
// Returns:
//   - (signature, nil): if no error occurred
//   - (nil, notEnoughSharesError): if not enough shares were collected
//   - (nil, errInvalidSignature): if at least one collected share does not serialize to a valid BLS signature.
//   - (nil, invalidInputsError): if the constructed signature failed to verify against the group public key and stored
//     message. This post-verification is required for safety, as `TrustedAdd` allows adding invalid signatures.
//   - (nil, error): for any other unexpected error.
func (s *blsThresholdSignatureInspector) ThresholdSignature() (Signature, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// check cached thresholdSignature
	if s.thresholdSignature != nil {
		return s.thresholdSignature, nil
	}

	// reconstruct the threshold signature
	thresholdSignature, err := s.reconstructThresholdSignature()
	if err != nil {
		return nil, err
	}
	s.thresholdSignature = thresholdSignature
	return thresholdSignature, nil
}

// reconstructThresholdSignature reconstructs the threshold signature from at least (t+1) shares.
// The function attempts the reconstruction and only returns a signature that is valid against the group public key.
// This is done by first reconstructing the signature and then validating it against the group public key.
//
// Returns:
//   - (signature, nil): if no error occurred
//   - (nil, notEnoughSharesError): if not enough shares were collected
//   - (nil, errInvalidSignature): if at least one collected share does not serialize to a valid BLS signature.
//   - (nil, invalidInputsError): if the constructed signature failed to verify against the group public key and stored message.
//   - (nil, error): for any other unexpected error.
func (s *blsThresholdSignatureInspector) reconstructThresholdSignature() (Signature, error) {

	if !s.enoughShares() {
		return nil, notEnoughSharesErrorf("number of signature shares %d is not enough, %d are required",
			len(s.shares), s.threshold+1)
	}
	thresholdSignature := make([]byte, SignatureLenBLSBLS12381)

	// prepare the C layer inputs
	shares := make([]byte, 0, len(s.shares)*SignatureLenBLSBLS12381)
	signers := make([]index, 0, len(s.shares))
	for index, share := range s.shares {
		shares = append(shares, share...)
		signers = append(signers, index+1)
	}

	// Lagrange Interpolate at point 0
	result := C.E1_lagrange_interpolate_at_zero_write(
		(*C.uchar)(&thresholdSignature[0]),
		(*C.uchar)(&shares[0]),
		(*C.uint8_t)(&signers[0]), (C.int)(s.threshold))

	if result != valid {
		return nil, errInvalidSignature
	}

	// Verify the computed signature
	verif, err := s.VerifyThresholdSignature(thresholdSignature)
	if err != nil {
		return nil, fmt.Errorf("internal error while verifying the threshold signature: %w", err)
	}
	if !verif {
		return nil, invalidInputsErrorf(
			"constructed threshold signature does not verify against the group public key, check shares and public key")
	}

	return thresholdSignature, nil
}

// BLSReconstructThresholdSignature is a stateless BLS API that takes a list of
// BLS signatures and their signers' indices and returns the threshold signature.
//
// size is the number of participants. It must be in the range [ThresholdSignMinSize, ThresholdSignMaxSize].
// threshold is the threshold value. It must be in the range [MinimumThreshold, size-1].
// The function does not use or require input public keys. Therefore, it does not check the validity of the
// shares against individual public keys, nor does it check the validity of the resulting signature
// against the group public key.
// Passing an invalid signature share is not considered an error and does
// not compromise the protocol security, but if any invalid share is included, the reconstructed group
// signature will be invalid.
// The reconstruction is guaranteed to return a valid signature if only valid shares are passed to the
// function.
//
// If the number of shares reaches the required threshold, only the first threshold+1 shares
// are used to reconstruct the signature.
//
// Returns:
//   - (nil, invalidInputsError): if
//     -- number of shares does not match the number of signers
//     -- the inputs are not in the correct range
//   - (nil, notEnoughSharesError): if the threshold is not reached
//   - (nil, duplicatedSignerError): if input signers are not distinct
//   - (nil, errInvalidSignature): if at least one of the first (threshold+1) signatures does not serialize to a valid E1 point
//   - (threshold_sig, nil): otherwise
func BLSReconstructThresholdSignature(size int, threshold int,
	shares []Signature, signers []int) (Signature, error) {

	if size < ThresholdSignMinSize || size > ThresholdSignMaxSize {
		return nil, invalidInputsErrorf(
			"size should be between %d and %d",
			ThresholdSignMinSize,
			ThresholdSignMaxSize)
	}
	if threshold >= size || threshold < MinimumThreshold {
		return nil, invalidInputsErrorf(
			"the threshold must be between %d and %d, got %d",
			MinimumThreshold, size-1,
			threshold)
	}

	if len(shares) != len(signers) {
		return nil, invalidInputsErrorf(
			"the number of signature shares is not matching the number of signers")
	}

	if len(shares) < threshold+1 {
		return nil, notEnoughSharesErrorf(
			"the number of signatures %d is less than the minimum %d", len(shares), threshold+1)
	}

	// map to check signers are distinct
	m := make(map[index]bool)

	// flatten the shares (required by the C layer)
	flatShares := make([]byte, 0, SignatureLenBLSBLS12381*(threshold+1))
	indexSigners := make([]index, 0, threshold+1)
	for i, share := range shares {
		flatShares = append(flatShares, share...)
		// check the index is valid
		if signers[i] >= size || signers[i] < 0 {
			return nil, invalidInputsErrorf(
				"signer index #%d is invalid", i)
		}
		// check the index is new
		if _, isSeen := m[index(signers[i])]; isSeen {
			return nil, duplicatedSignerErrorf(
				"%d is a duplicate signer", index(signers[i]))
		}
		m[index(signers[i])] = true
		indexSigners = append(indexSigners, index(signers[i])+1)
	}

	thresholdSignature := make([]byte, SignatureLenBLSBLS12381)
	// Lagrange Interpolate at point 0
	if C.E1_lagrange_interpolate_at_zero_write(
		(*C.uchar)(&thresholdSignature[0]),
		(*C.uchar)(&flatShares[0]),
		(*C.uint8_t)(&indexSigners[0]), (C.int)(threshold),
	) != valid {
		return nil, errInvalidSignature
	}
	return thresholdSignature, nil
}

// EnoughShares is a stateless function that takes the value of the threshold
// and a number of shares, and returns true if the number of shares is enough
// to reconstruct a threshold signature.
//
// Returns:
//   - (false, invalidInputsErrorf): if input threshold is less than 1
//   - (false, nil): if threshold is valid but shares are not enough
//   - (true, nil): if the threshold is valid and shares are enough
func EnoughShares(threshold int, sharesNumber int) (bool, error) {
	if threshold < MinimumThreshold {
		return false, invalidInputsErrorf(
			"the threshold can't be smaller than %d, got %d",
			MinimumThreshold, threshold)
	}
	return sharesNumber > threshold, nil
}

// BLSThresholdKeyGen is a key generation function for a BLS-based
// threshold signature scheme with a trusted dealer.
//
// The generation takes the group size `n` as input and assigns
// participants to the public indices `[0, n-1]`.
//
// The group secret key is not returned. The function returns the corresponding
// group public key, the private key shares, and their corresponding public key
// shares. The key shares are ordered arrays following the public index: a participant
// assigned to index `i` uses the private key share at index `i`, corresponding
// to the public key share at index `i`.
//
// Returns:
//   - (nil, nil, nil, invalidInputsErrorf): if
//   - `seed` is too short
//   - `size` is not in [`ThresholdSignMinSize`, `ThresholdSignMaxSize`]
//   - `threshold` value is not in interval `[1, size-1]`
//   - ([]privKeyShares, []pubKeyShares, groupPubKey, nil): otherwise
func BLSThresholdKeyGen(size int, threshold int, seed []byte) ([]PrivateKey,
	[]PublicKey, PublicKey, error) {

	if size < ThresholdSignMinSize || size > ThresholdSignMaxSize {
		return nil, nil, nil, invalidInputsErrorf(
			"size should be between %d and %d, got %d",
			ThresholdSignMinSize,
			ThresholdSignMaxSize,
			size)
	}
	if threshold >= size || threshold < MinimumThreshold {
		return nil, nil, nil, invalidInputsErrorf(
			"the threshold must be between %d and %d, got %d",
			MinimumThreshold,
			size-1,
			threshold)
	}

	// the scalars x and G2 points y
	x := make([]scalar, size)
	y := make([]pointE2, size)
	var X0 pointE2

	// Generate a polynomial P in F_r[X] of degree t
	a, err := generateFrPolynomial(seed, threshold)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate random polynomial: %w", err)
	}

	// compute the shares
	for i := index(1); int(i) <= size; i++ {
		C.Fr_polynomial_image(
			(*C.Fr)(&x[i-1]),
			(*C.E2)(&y[i-1]),
			(*C.Fr)(&a[0]), (C.int)(len(a)-1),
			(C.uint8_t)(i),
		)
	}
	// group public key
	generatorScalarMultG2(&X0, &a[0])
	// export the keys
	skShares := make([]PrivateKey, size)
	pkShares := make([]PublicKey, size)
	var pkGroup PublicKey
	for i := 0; i < size; i++ {
		skShares[i] = newPrKeyBLSBLS12381(&x[i])
		pkShares[i] = newPubKeyBLSBLS12381(&y[i])
	}
	pkGroup = newPubKeyBLSBLS12381(&X0)

	// public key shares and group public key
	// are sampled uniformly at random. The probability of
	// generating an identity key is therefore negligible.
	return skShares, pkShares, pkGroup, nil
}
