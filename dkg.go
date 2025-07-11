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
	"errors"
	"fmt"
)

// DKG stands for distributed key generation. In this package, DKG
// refers to discrete-log based protocols.
// The protocols currently implemented generate keys for a BLS-based threshold signature scheme.
// BLS is used with the BLS12-381 curve.
//
// The protocols generate a BLS key pair and share the secret key
// among `n` participants in a way that any `t+1` key shares allow reconstructing
// the private key (and also reconstructing a BLS signature under the key).
// Up to `t` shares don't reveal any information about the initial key (or a signature generated
// under the key).
//
// We refer to the initial key pair by group private key and group public key.
// `t` is the threshold parameter.
//
// The `n` participants are referred to using their unique public index, serving as
// their public identifier.
// The distinct indices are assigned to participants
// and agreed upon prior to running the protocol.
//
// Re-using the same BLS public parameters of the package (see bls.go):
// - private keys are scalars in `F_r`
// - public keys are points in G2

const (
	// DKG and Threshold Signatures

	// MinimumThreshold is the minimum value of the threshold parameter in all threshold-based protocols.
	MinimumThreshold = 1
	// DKGMinSize is the minimum size of a group participating in threshold-based protocols.
	DKGMinSize int = MinimumThreshold + 1
	// DKGMaxSize is the maximum size of a group participating in threshold-based protocols.
	DKGMaxSize int = 254
)

type DKGState interface {
	// Size returns the size of the DKG group n
	Size() int
	// Threshold returns the threshold value `t`
	Threshold() int
	// Start starts running a DKG in the current participant
	Start(seed []byte) error
	// HandleBroadcastMsg processes a new broadcasted message received by the current participant.
	// `orig` is the public index of the message sender.
	HandleBroadcastMsg(orig int, msg []byte) error
	// HandlePrivateMsg processes a new private message received by the current participant.
	// `orig` is the public index of the message sender.
	HandlePrivateMsg(orig int, msg []byte) error
	// End ends a DKG protocol in the current participant.
	// It returns the finalized public data and participant private key share.
	// - the group public key corresponding to the group secret key
	// - all the public key shares corresponding to the participants private
	// key shares
	// - the finalized private key which is the current participant's own private key share
	End() (PrivateKey, PublicKey, []PublicKey, error)
	// NextTimeout set the next timeout of the protocol if any timeout applies.
	// Some protocols could require more than one timeout
	NextTimeout() error
	// Running returns the running state of the DKG protocol
	Running() bool
	// ForceDisqualify forces a participant to get disqualified
	// for a reason outside of the DKG protocol.
	// The caller should make sure all honest participants call this function,
	// otherwise, the protocol can be broken.
	ForceDisqualify(participant int) error
}

// dkgFailureError is an error returned when a participant
// detects a failure in the protocol and is not able to compute output keys.
// Such a failure can be local and only depends on the participant's view of what
// happened in the protocol. The error can only be returned using the End() function.
type dkgFailureError struct {
	error
}

// dkgFailureErrorf constructs a new dkgFailureError
func dkgFailureErrorf(msg string, args ...interface{}) error {
	return &dkgFailureError{
		error: fmt.Errorf(msg, args...),
	}
}

// IsDKGFailureError checks if the input error is of a dkgFailureError type.
// dkgFailureError is an error returned when a participant
// detects a failure in the protocol and is not able to compute output keys.
func IsDKGFailureError(err error) bool {
	var target *dkgFailureError
	return errors.As(err, &target)
}

type dkgInvalidStateTransitionError struct {
	error
}

func (e dkgInvalidStateTransitionError) Unwrap() error {
	return e.error
}

// dkgInvalidStateTransitionErrorf constructs a new dkgInvalidStateTransitionError
func dkgInvalidStateTransitionErrorf(msg string, args ...interface{}) error {
	return &dkgInvalidStateTransitionError{
		error: fmt.Errorf(msg, args...),
	}
}

// IsDkgInvalidStateTransitionError checks if the input error is of a dkgInvalidStateTransition type.
// invalidStateTransition is returned when a caller
// triggers an invalid state transition in the local DKG instance.
// Such a failure can only happen if the API is misued by not respecting
// the state machine conditions.
func IsDKGInvalidStateTransitionError(err error) bool {
	var target *dkgInvalidStateTransitionError
	return errors.As(err, &target)
}

// `index` is the node index type used as public participant IDs.
//
// This is currently set to `byte` since [DKGMaxSize] fits into a byte.
// The current underlying implementation takes into account the current type
// and is not generalized for larger types.
type index byte

// newDKGCommon initializes the common structure of DKG protocols
func newDKGCommon(size int, threshold int, myIndex int,
	processor DKGProcessor, dealerIndex int) (*dkgCommon, error) {
	if size < DKGMinSize || size > DKGMaxSize {
		return nil, invalidInputsErrorf(
			"size should be between %d and %d",
			DKGMinSize,
			DKGMaxSize)
	}

	if myIndex >= size || dealerIndex >= size || myIndex < 0 || dealerIndex < 0 {
		return nil, invalidInputsErrorf(
			"indices of current and dealer nodes must be between 0 and %d, got %d",
			size-1,
			myIndex)
	}

	if threshold >= size || threshold < MinimumThreshold {
		return nil, invalidInputsErrorf(
			"The threshold must be between %d and %d, got %d",
			MinimumThreshold,
			size-1,
			threshold)
	}

	return &dkgCommon{
		size:      size,
		threshold: threshold,
		myIndex:   index(myIndex),
		processor: processor,
	}, nil
}

// dkgCommon holds the common data of all DKG protocols
type dkgCommon struct {
	size      int
	threshold int
	myIndex   index
	// running is true when the DKG protocol is running, is false otherwise
	running bool
	// processes the action of the DKG interface outputs
	processor DKGProcessor
}

// Running returns the running state of the DKG protocol.
// The state is equal to true when the DKG protocol is running, and is equal to false otherwise.
func (s *dkgCommon) Running() bool {
	return s.running
}

// Size returns the size of the DKG group n
func (s *dkgCommon) Size() int {
	return s.size
}

// Threshold returns the threshold value t
func (s *dkgCommon) Threshold() int {
	return s.threshold
}

// NextTimeout sets the next protocol timeout if there is any.
// This function should be overwritten by any protocol that uses timeouts.
func (s *dkgCommon) NextTimeout() error {
	return nil
}

// dkgMsgTag is the type used to encode message tags
type dkgMsgTag byte

const (
	feldmanVSSShare dkgMsgTag = iota
	feldmanVSSVerifVec
	feldmanVSSComplaint
	feldmanVSSComplaintAnswer
)

// DKGProcessor is an interface that implements the DKG actions by a DKG participant
// during the protocol run.
//
// In particular, it implements the communication channels with
// the other participants, taking into account their pre-agreed
// public indices.
//
// An instance of a DKGProcessor is needed for each participant in order to
// participate in a DKG protocol
type DKGProcessor interface {
	// PrivateSend sends a message to a destination over
	// a private channel. The channel must preserve the
	// confidentiality of the message and should authenticate
	// the sender.
	// It is recommended to use a unique private channel per
	// protocol instance. This can be achieved by prepending all
	// messages by a unique instance ID.
	// The message destination is specified using the destination index `dest`.
	PrivateSend(dest int, data []byte)
	// Broadcast broadcasts a message to all participants.
	// The function must implement a reliable broadcast
	// (Cachin and Poritz, Secure INtrusion-Tolerant Replication on the Internet, 2002)
	// to guarantee the correctness of the overall protocol.
	// The broadcasted message is public and not confidential.
	// The broadcasting channel should authenticate the sender.
	// It is recommended to use a unique broadcasting channel per
	// protocol instance. This can be achieved by prepending all
	// messages by a unique instance ID.
	Broadcast(data []byte)
	// Disqualify flags that the current instance detected that
	// another participant has misbehaved and that they got
	// disqualified from the protocol. Such misbehavior is
	// detected by all honest participants.
	// `log` is a string describing the disqualification reason.
	// The disqualified participant is referred to using its public index `index`.
	Disqualify(index int, log string)
	// FlagMisbehavior warns that the current instance detected that
	// another participant has misbehaved.
	// Such misbehavior is not necessarily detected by other participants and therefore
	// the participant is not disqualified from the protocol.
	// Other mechanisms outside DKG could be implemented to
	// synchronize slashing the misbehaving participant,
	// using the function `ForceDisqualify`.
	// Failing to synchronize the action properly by all honest participants
	// may break the protocol.
	// `log` is a string describing the misbehavior.
	// The disqualified participant is referred to using its public index `index`.
	FlagMisbehavior(index int, log string)
}
