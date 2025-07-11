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

// #include "dkg_include.h"
import "C"

import (
	"fmt"

	"github.com/onflow/crypto/hash"
	"github.com/onflow/crypto/random"
)

// Implements Feldman Verifiable Secret Sharing (VSS) using
// the BLS set up on the BLS12-381 curve.
//
// The secret is a BLS private key generated by a single dealer.
// The dealer generates key shares for a BLS-based
// `t`-threshold signature scheme and distributes the shares over `n`
// participants including itself (see dkg.go for details on the value `t`).
// The participants validate their shares
// locally using a public verification vector broadcasted by the dealer.
//
// The `n` participants are referred to using their unique public index, serving as
// their public identifier.
// The distinct indices are assigned to participants
// and agreed upon prior to running the protocol.
// The public index is used to define the Shamir
// Secret Sharing (SSS) polynomial input. Although it's enough to use distinct indices,
// the current implementation assumes the indices are the set `[0..n-1]`.
//
// Re-using the same BLS public parameters of the package (see bls.go):
// - private keys are scalars in `F_r`
// - public keys are points in G2

// feldman VSS protocol, implements DKGState
type feldmanVSSstate struct {
	// common DKG state
	*dkgCommon
	// dealer index
	dealerIndex index
	// SSS's polynomial of degree `t`: P(x) = a_0 + a_1*x + .. + a_t*x^t in F_r[X].
	// The vector size is `t+1`, `a_0` is the group private key
	a []scalar
	// Public vector corresponding to `P` (A_i = g_2^a_i, for all i), the vector size is `t+1`.
	// `A_0` is the group public key.
	vA         []pointE2
	vAReceived bool
	// Private share of the current participant
	x         scalar
	xReceived bool
	// Public keys of the group participants, the vector size is `n`
	y []pointE2
	// true if the private share is valid
	validKey bool
}

// NewFeldmanVSS creates a new instance of Feldman VSS protocol.
//
// An instance is run by a single participant and is usable for only one protocol run.
// In order to run the protocol again, a new instance needs to be created. The current
// participant uses the pre-agreed public index `myIndex`.
//
//   - `size` is the group size
//   - `threshold` is the threshold value `t`
//   - `myIndex` is the index of the current participant, in `[0, size-1]`
//   - `dealerIndex` is the index of the dealer, in `[0, size-1]`
//   - `processor` is an implementation of [DKGProcessor] (see dkg.go)
//
// The function returns:
// - (nil, InvalidInputsError) if:
//   - `size` if not in `[DKGMinSize, DKGMaxSize]`
//   - `threshold` is not in `[MinimumThreshold, size-1]`
//   - `myIndex` is not in `[0, size-1]`
//   - `dealerIndex` is not in `[0, size-1]`
//
// - (dkgInstance, nil) otherwise
func NewFeldmanVSS(
	size int,
	threshold int,
	myIndex int,
	processor DKGProcessor,
	dealerIndex int,
) (DKGState, error) {

	common, err := newDKGCommon(size, threshold, myIndex, processor, dealerIndex)
	if err != nil {
		return nil, err
	}

	fvss := &feldmanVSSstate{
		dkgCommon:   common,
		dealerIndex: index(dealerIndex),
	}
	fvss.init()
	return fvss, nil
}

func (s *feldmanVSSstate) init() {
	// set the bls context

	s.running = false
	s.y = nil
	s.xReceived = false
	s.vAReceived = false
}

// Start triggers the protocol start for the current participant.
// If the current participant is the dealer, then the seed is used
// to generate the secret polynomial (including the group private key).
// If the current participant is not the dealer, the seed is ignored.
//
// The function returns:
// - invalidInputError if seed is too short
// - dkgInvalidStateTransitionError if the DKG instance is already running.
// - error if an unexpected exception occurs
// - nil otherwise
func (s *feldmanVSSstate) Start(seed []byte) error {
	if s.running {
		return dkgInvalidStateTransitionErrorf("dkg is already running")
	}

	s.running = true
	// Generate shares if necessary
	if s.dealerIndex == s.myIndex {
		return s.generateShares(seed)
	}
	return nil
}

// End finalizes the protocol in the current node.
// It returns the finalized public data and participants private key share.
// - the group public key corresponding to the group secret key
// - all the public key shares corresponding to the participants private
// key shares.
// - the finalized private key which is the current participant's own private key share
//
// The returned error is :
//   - dkgInvalidStateTransitionError if the DKG instance was not running.
//   - dkgFailureError if the private key and vector are inconsistent.
//   - dkgFailureError if the public key share or group public key is identity.
//   - nil otherwise.
func (s *feldmanVSSstate) End() (PrivateKey, PublicKey, []PublicKey, error) {
	if !s.running {
		return nil, nil, nil, dkgInvalidStateTransitionErrorf("dkg is not running")
	}
	s.running = false
	if !s.validKey {
		return nil, nil, nil, dkgFailureErrorf("received private key is invalid")
	}
	// private key of the current participant
	x := newPrKeyBLSBLS12381(&s.x)

	// Group public key
	Y := newPubKeyBLSBLS12381(&s.vA[0])

	// The participants public keys
	y := make([]PublicKey, s.size)
	for i, p := range s.y {
		y[i] = newPubKeyBLSBLS12381(&p)
	}

	// check if current public key share or group public key is identity.
	// In that case all signatures generated by the key are invalid (as stated by the BLS IETF draft)
	// to avoid equivocation issues.
	if (&s.x).isZero() {
		return nil, nil, nil, dkgFailureErrorf("received private key is identity and is therefore invalid")
	}
	if Y.isIdentity {
		return nil, nil, nil, dkgFailureErrorf("group private key is identity and is therefore invalid")
	}
	return x, Y, y, nil
}

var (
	shareSize = frBytesLen
	// the actual verifVectorSize depends on the state and is:
	// g2BytesLen*(t+1)
	verifVectorSize = g2BytesLen
)

// HandleBroadcastMsg processes a new broadcasted message received by the current participant.
// `orig` is the message origin index.
//
// The function returns:
//   - dkgInvalidStateTransitionError if the instance is not running
//   - invalidInputsError if `orig` is not valid (in [0, size-1])
//   - nil otherwise
func (s *feldmanVSSstate) HandleBroadcastMsg(orig int, msg []byte) error {
	if !s.running {
		return dkgInvalidStateTransitionErrorf("dkg is not running")
	}
	if orig >= s.Size() || orig < 0 {
		return invalidInputsErrorf(
			"wrong origin input, should be less than %d, got %d",
			s.Size(),
			orig)
	}

	// In case a message is received by the origin participant,
	// the message is just ignored
	if s.myIndex == index(orig) {
		return nil
	}

	if len(msg) == 0 {
		s.processor.Disqualify(orig, "the received broadcast is empty")
		return nil
	}

	// msg = |tag| Data |
	if dkgMsgTag(msg[0]) == feldmanVSSVerifVec {
		s.receiveVerifVector(index(orig), msg[1:])
	} else {
		s.processor.Disqualify(orig,
			fmt.Sprintf("the broadcast header is invalid, got %d",
				dkgMsgTag(msg[0])))
	}
	return nil
}

// HandlePrivateMsg processes a new private message received by the current participant.
// `orig` is the message origin index.
//
// The function returns:
//   - dkgInvalidStateTransitionError if the instance is not running
//   - invalidInputsError if `orig` is not valid (in [0, size-1])
//   - nil otherwise
func (s *feldmanVSSstate) HandlePrivateMsg(orig int, msg []byte) error {
	if !s.running {
		return dkgInvalidStateTransitionErrorf("dkg is not running")
	}

	if orig >= s.Size() || orig < 0 {
		return invalidInputsErrorf(
			"wrong origin, should be positive less than %d, got %d",
			s.Size(),
			orig)
	}

	// In case a private message is received by the origin participant,
	// the message is just ignored
	if s.myIndex == index(orig) {
		return nil
	}

	// forward received message to receiveShare because private messages
	// can only be private shares
	// msg = |tag| Data |
	s.receiveShare(index(orig), msg)

	return nil
}

// ForceDisqualify forces a participant to get disqualified
// for a reason outside of the DKG protocol
// The caller should make sure all honest participants call this function,
// otherwise, the protocol can be broken.
//
// The function returns:
//   - dkgInvalidStateTransitionError if the instance is not running
//   - invalidInputsError if `orig` is not valid (in [0, size-1])
//   - nil otherwise
func (s *feldmanVSSstate) ForceDisqualify(participant int) error {
	if !s.running {
		return dkgInvalidStateTransitionErrorf("dkg is not running")
	}
	if participant >= s.Size() || participant < 0 {
		return invalidInputsErrorf(
			"wrong origin input, should be less than %d, got %d",
			s.Size(),
			participant)
	}
	if index(participant) == s.dealerIndex {
		s.validKey = false
	}
	return nil
}

// generate a pseudo-random polynomial P(x) = a_0 + a_1*x + .. + a_t x^t in F_r[X]
// where `t` is the input `degree` (higher degree monomial is non-zero).
// `a_0` is also non-zero (for single dealer BLS-DKGs, this insures
// protocol public key output is not identity).
// `seed` is used as the entropy source and must be at least `KeyGenSeedMinLen`
// random bytes with at least 128 bits entropy.
func generateFrPolynomial(seed []byte, degree int) ([]scalar, error) {
	if len(seed) < KeyGenSeedMinLen {
		return nil, invalidInputsErrorf(
			"seed should be at least %d bytes, got %d", KeyGenSeedMinLen, len(seed))
	}

	// build a PRG out of the seed
	// In this case, SHA3 is used to smoothen the seed and Chacha20 is used as a PRG
	var prgSeed [random.Chacha20SeedLen]byte
	hash.ComputeSHA3_256(&prgSeed, seed)
	prg, err := random.NewChacha20PRG(prgSeed[:], []byte("gen_poly"))
	if err != nil {
		return nil, fmt.Errorf("instanciating the PRG failed: %w", err)
	}

	// P's coefficients
	a := make([]scalar, degree+1)

	// generate a_0 in F_r*
	randFrStar(&a[0], prg)
	if degree > 0 {
		// genarate a_i on F_r, for 0<i<degree
		for i := 1; i < degree; i++ {
			_ = randFr(&a[i], prg)
		}
		// generate a_degree in F_r* to enforce P's degree
		randFrStar(&a[degree], prg)
	}
	return a, nil
}

// generateShares is used by the dealer to generate a secret SSS polynomial from the input seed
// and derive all private shares and public data.
//
// Note that Shamir's secret is defined as the polynomial's image of `0`. The public
// indices of participants defined in the range `[0..n-1]` are therefore mapped to the range
// `[1..n]` to insure they are non-zero. The private share of participant `i` is `P(i+1)`.
func (s *feldmanVSSstate) generateShares(seed []byte) error {

	s.y = make([]pointE2, s.size)

	// Generate a random polynomial P in F_r[X] of degree `t` (coefficients are a_i)
	// `s.a` are the coefficients of P
	//  - a_degree is non-zero as deg(P) = degree
	//  - `a_0` is non-zero to make sure BLS-DKG public key is non-identity
	var err error
	s.a, err = generateFrPolynomial(seed, s.threshold)
	if err != nil {
		return fmt.Errorf("failed to generate random polynomial: %w", err)
	}

	// compute the verification vector A_i = g2^a_i
	s.vA = make([]pointE2, s.threshold+1)
	for i := 0; i <= s.threshold; i++ {
		generatorScalarMultG2(&s.vA[i], &s.a[i])
	}

	// compute the shares (images of P)
	// The public indices of participants defined in the range `[0..n-1]` are mapped to the range
	// `[1..n]` to insure they are non-zero (`0` is reserved to Shamir's secret).
	for i := index(1); int(i) <= s.size; i++ {
		// the dealer's own share
		if i-1 == s.myIndex {
			xdata := make([]byte, shareSize)
			frPolynomialImage(xdata, s.a, i, &s.y[i-1])
			err := readScalarFrStar(&s.x, xdata)
			if err != nil {
				return fmt.Errorf("unexpected error when generating the dealer's own share: %w", err)
			}
			continue
		}
		// the-other-participant shares
		// The private share of participant `i` is `P(i+1)`
		data := make([]byte, shareSize+1)
		data[0] = byte(feldmanVSSShare)
		frPolynomialImage(data[1:], s.a, i, &s.y[i-1])
		s.processor.PrivateSend(int(i-1), data)
	}
	// broadcast the vector
	vectorSize := verifVectorSize * (s.threshold + 1)
	data := make([]byte, vectorSize+1)
	data[0] = byte(feldmanVSSVerifVec)
	writeVerifVector(data[1:], s.vA)
	s.processor.Broadcast(data)

	s.vAReceived = true
	s.xReceived = true
	s.validKey = true
	return nil
}

// receives a private share from the
func (s *feldmanVSSstate) receiveShare(origin index, data []byte) {
	// only accept private shares from the .
	if origin != s.dealerIndex {
		return
	}

	if s.xReceived {
		s.processor.FlagMisbehavior(int(origin), "private share was already received")
		return
	}

	// at this point, tag the private message as received
	s.xReceived = true

	// private message general check
	// msg = |tag| Data |
	if len(data) == 0 || dkgMsgTag(data[0]) != feldmanVSSShare {
		s.validKey = false
		s.processor.FlagMisbehavior(int(origin),
			fmt.Sprintf("private share should be non-empty and first byte should be %d, received %#x",
				feldmanVSSShare, data))
		return
	}

	// consider the remaining data from message
	data = data[1:]

	if (len(data)) != shareSize {
		s.validKey = false
		s.processor.FlagMisbehavior(int(origin),
			fmt.Sprintf("invalid share size, expects %d, got %d",
				shareSize, len(data)))
		return
	}

	// read the participant private share
	err := readScalarFrStar(&s.x, data)
	if err != nil {
		s.validKey = false
		s.processor.FlagMisbehavior(int(origin),
			fmt.Sprintf("invalid share value %x: %s", data, err))
		return
	}

	if s.vAReceived {
		s.validKey = s.verifyShare()
	}
}

// receives the public vector from the dealer
func (s *feldmanVSSstate) receiveVerifVector(origin index, data []byte) {
	// only accept the verification vector from the dealer.
	if origin != s.dealerIndex {
		return
	}

	if s.vAReceived {
		s.processor.FlagMisbehavior(int(origin),
			"verification vector was already received")
		return
	}

	if verifVectorSize*(s.threshold+1) != len(data) {
		s.vAReceived = true
		s.validKey = false
		s.processor.Disqualify(int(origin),
			fmt.Sprintf("invalid verification vector size, expects %d, got %d",
				verifVectorSize*(s.threshold+1), len(data)))
		return
	}
	// read the verification vector
	s.vA = make([]pointE2, s.threshold+1)
	err := readVerifVector(s.vA, data)
	if err != nil {
		s.vAReceived = true
		s.validKey = false
		s.processor.Disqualify(int(origin),
			fmt.Sprintf("reading the verification vector failed: %s", err))
	}

	s.y = make([]pointE2, s.size)
	s.computePublicKeys()

	s.vAReceived = true
	if s.xReceived {
		s.validKey = s.verifyShare()
	}
}

// frPolynomialImage computes P(x) = a_0 + a_1*x + .. + a_t*x^t in F_r[X]
// r being the order of G1
// P(x) is written in dest, while g2^P(x) is written in y
// x being a small integer
func frPolynomialImage(dest []byte, a []scalar, x index, y *pointE2) {
	C.Fr_polynomial_image_write((*C.uchar)(&dest[0]),
		(*C.E2)(y),
		(*C.Fr)(&a[0]), (C.int)(len(a)-1),
		(C.uint8_t)(x),
	)
}

// writeVerifVector exports a vector A into an array of bytes
// assuming the array length matches the vector length
func writeVerifVector(dest []byte, A []pointE2) {
	C.E2_vector_write_bytes((*C.uchar)(&dest[0]),
		(*C.E2)(&A[0]),
		(C.int)(len(A)),
	)
}

// readVerifVector imports A vector (G2 points) from an array of bytes,
// assuming the slice length matches the vector length.
func readVerifVector(A []pointE2, src []byte) error {
	read := C.G2_vector_read_bytes(
		(*C.E2)(&A[0]),
		(*C.uchar)(&src[0]),
		(C.int)(len(A)))
	if read == valid {
		return nil
	}
	// invalid A vector
	return invalidInputsErrorf("the verification vector does not serialize valid G2 points: error code %d", read)
}

func (s *feldmanVSSstate) verifyShare() bool {
	// check y[current] == x.G2
	return bool(C.G2_check_log(
		(*C.Fr)(&s.x),
		(*C.E2)(&s.y[s.myIndex])))
}

// computePublicKeys extracts the participants public keys from the verification vector `vA`.
// y[i] = Q(i+1) for all participants i in {0,..,n-1}, where:
//
//   - Q(x) = A_0 + A_1*x + ... +  A_t*x^t  in G2
//   - `t+1` is the length of coefficients A_i
//   - `n` is the length of the array `s.y`
//   - the computed public keys are stored in `s.y` such that participant `i`'s key is stored in `s.y[i]`
func (s *feldmanVSSstate) computePublicKeys() {
	E2PolynomialImages(s.y, s.vA)
}

// E2PolynomialImages computes `n` images of a polynomial in E2, where:
//   - the `n` inputs are the small scalars {1,..,n}
//   - the polynomial is of degree `t` with the `t+1` coefficients A_i (array A), such that Q(x) = A_0 + A_1*x + ... +  A_t*x^t  in E2
//
// `out` stores the `n` outputs such that `out[i] = Q(i+1)`
func E2PolynomialImages(out []pointE2, A []pointE2) {
	C.E2_polynomial_images(
		(*C.E2)(&out[0]), (C.int)(len(out)),
		(*C.E2)(&A[0]), (C.int)(len(A)-1),
	)
}
