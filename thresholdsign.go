/*
 * Flow Crypto
 *
 * Copyright Dapper Labs, Inc.
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
	"errors"
	"fmt"
)

// A threshold signature scheme allows a group of participants
// to generate a signature using a pre-distributed private key.
// No participant holds the private key but each participant holds
// a private key share. Any `t+1` subset of
// the participants can jointly generate a valid signature using
// their private key shares.
// Subsets of up to `t` participants cannot reveal any information about
// about any signature of a new message.
// The signature generated by each participant using their private key
// share is called a signature share.
//
// Threshold signature schemes are based on Shamir Secret Sharing (SSS).
// Each group participant is assigned to a unique index that is mapped to
// the unique polynomial image. In this package, the index is used as the
// public identifier of participants.
//
// Private key shares and their corresponding public key shares are generated
// and pre-distributed over participants by a trusted dealer or using a
// trustless distributed generation. The public index of each participant
// is assigned to each participant prior to the key generation step. The index
// along with the output public key share constitute the public identity of the
// participant. The same public info must be used by the threshold signature
// functions to guarantee correctness of the scheme. In this package, indices
// are assumed to be in the range `[0..n-1]` where `n` is the participant group
// size.
//
// In this package, it is assumed that any public party is able to verify
// signature shares and groups signatures, and reconstruct a group signature
// from signature shares using the public info only, in a
// non-interactive manner. Only threshold-signature schemes providing this
// feature are provided by this package. This feature is represented by
// the `ThresholdSignatureInspector` interface. An active participant in the protocol holding
// a private key share is represented by `ThresholdSignatureParticipant`.
//
//
// Although the package allows using arbitrary values of `t`,
// the threshold signature scheme is secure in the presence of up to `t`
// malicious participants when (`t < n/2`).
//
// The choice of input threshold `t` adjusts the tradeoff between unforgeability and robustness
// of the overall scheme.
// In order to equally optimize unforgeability and robustness,
// `t` should be set to `floor((n-1)/2)`.

const (
	// ThresholdSignMinSize is the minimum size of a group participating in a threshold signature protocol
	ThresholdSignMinSize = MinimumThreshold + 1
	// ThresholdSignMaxSize is the maximum size of a group participating in a threshold signature protocol
	ThresholdSignMaxSize = DKGMaxSize
)

// ThresholdSignatureInspector is an inspector of the threshold signature protocol.
//
// An inspector is not holding a private key share and does not contribute to the protocol
// but is able to verify and reconstruct signatures in a non-interactive manner
// based on the public data of the protocol.
type ThresholdSignatureInspector interface {
	// VerifyShare verifies the input signature against the stored message and stored
	// key at the input index. This function does not update the internal state.
	// The function is thread-safe.
	// Returns:
	//  - (true, nil) if the signature is valid
	//  - (false, nil) if `index` is a valid index but the signature share is invalid
	//  - (false, InvalidInputsError) if `index` is an invalid index value
	//  - (false, error) for all other unexpected errors
	VerifyShare(index int, share Signature) (bool, error)

	// VerifyThresholdSignature verifies the input signature against the stored
	// message and stored group public key. It does not update the internal state.
	// The function is thread-safe.
	// Returns:
	//  - (true, nil) if the signature is valid
	//  - (false, nil) if the signature is invalid
	//  - (false, error) for all other unexpected errors
	VerifyThresholdSignature(thresholdSignature Signature) (bool, error)

	// EnoughShares indicates whether enough shares have been accumulated in order to reconstruct
	// a group signature. This function is thread safe and locks the internal state.
	// Returns:
	//  - true if and only if at least (threshold+1) shares were added
	EnoughShares() bool

	// TrustedAdd adds a signature share to the internal pool of shares
	// without verifying the signature against the message and the participant's
	// public key. This function is thread safe and locks the internal state.
	//
	// The share is only added if the signer index is valid and has not been
	// added yet. Moreover, the share is added only if not enough shares were collected.
	// The function returns:
	//  - (true, nil) if enough signature shares were already collected and no error occurred
	//  - (false, nil) if not enough shares were collected and no error occurred
	//  - (false, InvalidInputsError) if index is invalid
	//  - (false, duplicatedSignerError) if a signature for the index was previously added
	TrustedAdd(index int, share Signature) (bool, error)

	// VerifyAndAdd verifies a signature share (same as `VerifyShare`),
	// and may or may not add the share to the local pool of shares.
	// This function is thread safe and locks the internal state.
	//
	// The share is only added if the signature is valid, the signer index is valid and has not been
	// added yet. Moreover, the share is added only if not enough shares were collected.
	// Boolean returns:
	//  - First boolean output is true if the share is valid and no error is returned, and false otherwise.
	//  - Second boolean output is true if enough shares were collected and no error is returned, and false otherwise.
	// Error returns:
	//  - invalidInputsError if input index is invalid. A signature that doesn't verify against the signer's
	//    public key is not considered an invalid input.
	//  - duplicatedSignerError if signer was already added.
	//  - other errors if an unexpected exception occurred.
	VerifyAndAdd(index int, share Signature) (bool, bool, error)

	// HasShare checks whether the internal map contains the share of the given index.
	// This function is thread safe.
	// The function errors with InvalidInputsError if the index is invalid.
	HasShare(index int) (bool, error)

	// ThresholdSignature returns the threshold signature if the threshold was reached.
	// The threshold signature is reconstructed only once and is cached for subsequent calls.
	//
	// Returns:
	// - (signature, nil) if no error occurred
	// - (nil, notEnoughSharesError) if not enough shares were collected
	// - (nil, invalidSignatureError) if at least one collected share does not serialize to a valid BLS signature.
	// - (nil, invalidInputsError) if the constructed signature failed to verify against the group public key and stored message. This post-verification
	//    is required  for safety, as `TrustedAdd` allows adding invalid signatures.
	// - (nil, error) for any other unexpected error.
	ThresholdSignature() (Signature, error)
}

// ThresholdSignatureParticipant is a participant in a threshold signature protocol.
// A participant holds a private key share and can contribute to group signatures,
// in addition to inspecting and reconstructing signatures.
type ThresholdSignatureParticipant interface {
	ThresholdSignatureInspector
	// SignShare generates a signature share using the current private key share.
	//
	// The function does not add the share to the internal pool of shares and do
	// not update the internal state.
	// This function is thread safe
	// No error is expected unless an unexpected exception occurs
	SignShare() (Signature, error)
}

// duplicatedSignerError is an error returned when TrustedAdd or VerifyAndAdd encounter
// a signature share that has been already added to the internal state.
type duplicatedSignerError struct {
	error
}

// duplicatedSignerErrorf constructs a new duplicatedSignerError
func duplicatedSignerErrorf(msg string, args ...interface{}) error {
	return &duplicatedSignerError{error: fmt.Errorf(msg, args...)}
}

// IsDuplicatedSignerError checks if the input error is a duplicatedSignerError
func IsDuplicatedSignerError(err error) bool {
	var target *duplicatedSignerError
	return errors.As(err, &target)
}

// notEnoughSharesError is an error returned when ThresholdSignature is called
// and not enough shares have been collected.
type notEnoughSharesError struct {
	error
}

// notEnoughSharesErrorf constructs a new notEnoughSharesError
func notEnoughSharesErrorf(msg string, args ...interface{}) error {
	return &notEnoughSharesError{error: fmt.Errorf(msg, args...)}
}

// IsNotEnoughSharesError checks if the input error is a notEnoughSharesError
func IsNotEnoughSharesError(err error) bool {
	var target *notEnoughSharesError
	return errors.As(err, &target)
}
