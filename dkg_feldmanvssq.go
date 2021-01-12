// +build relic

package crypto

// #cgo CFLAGS: -g -Wall -std=c99
// #include "dkg_include.h"
import "C"

import (
	"errors"
	"fmt"
)

// Implements Feldman Verifiable Secret Sharing using
// the BLS set up on the BLS12-381 curve. A complaint mechanism
// is added to qualify/disqualify the leader/dealer if they misbehave.

// The secret is a BLS private key generated by the leader.
// (and hence this is a centralized generation).
// The leader generates key shares for a BLS-based
// threshold signature scheme and distributes the shares over the (n)
// partcipants including itself. The particpants validate their shares
// using a public verifiaction vector shared by the leader and are able
// to broadcast compalints against a misbehaving leader.

// The leader has the chance to avoid being disqualified by broadcasting
// a complaint answer. The protocol ends with all honest particiants
// reaching a consensus about the leader qualification/disqualifiaction.

// Private keys are scalar in Zr, where r is the group order of G1/G2
// Public keys are in G2.

// feldman VSS protocol, with complaint mechanism, implements DKGState
type feldmanVSSQualState struct {
	// feldmanVSSstate state
	*feldmanVSSstate
	// complaints received against the leader:
	// the key is the origin of the complaint
	// a complaint will be created if a complaint message or an answer was
	// broadcasted, a complaint will be checked only when both the
	// complaint message and the answer were broadcasted
	complaints map[index]*complaint
	// is the leader disqualified
	disqualified bool
	// Timeout to receive shares and verification vector
	// - if a share is not received before this timeout a complaint will be formed
	// - if the verification is not received before this timeout,
	// leader is disqualified
	sharesTimeout bool
	// Timeout to receive complaints
	// all complaints received after this timeout are ignored
	complaintsTimeout bool
}

// these data are required to justify a slashing
type complaint struct {
	received       bool
	answerReceived bool
	answer         scalar
}

// NewFeldmanVSSq creates a new instance of a Feldman VSS protocol
// with a qualification mechanism.
//
// An instance is run by a single node and is usable for only one protocol.
// In order to run the protocol again, a new instance needs to be created
func NewFeldmanVSSQual(size int, threshold int, currentIndex int,
	processor DKGProcessor, leaderIndex int) (DKGState, error) {

	common, err := newDKGCommon(size, threshold, currentIndex, processor, leaderIndex)
	if err != nil {
		return nil, err
	}

	fvss := &feldmanVSSstate{
		dkgCommon:   common,
		leaderIndex: index(leaderIndex),
	}
	fvssq := &feldmanVSSQualState{
		feldmanVSSstate: fvss,
		disqualified:    false,
	}
	fvssq.init()
	return fvssq, nil
}

func (s *feldmanVSSQualState) init() {
	s.feldmanVSSstate.init()
	s.complaints = make(map[index]*complaint)
}

// NextTimeout sets the next protocol timeout
// This function needs to be called twice by every node in
// the Feldman VSS Qual protocol.
// The first call is a timeout for sharing the private shares.
// The second call is a timeout for broadcasting the complaints.
func (s *feldmanVSSQualState) NextTimeout() error {
	if !s.running {
		return errors.New("dkg protocol is not running")
	}
	// if leader is already disqualified, there is nothing to do
	if s.disqualified {
		if s.sharesTimeout {
			s.complaintsTimeout = true
		} else {
			s.sharesTimeout = true
		}
		return nil
	}
	if !s.sharesTimeout && !s.complaintsTimeout {
		s.setSharesTimeout()
		return nil
	}
	if s.sharesTimeout && !s.complaintsTimeout {
		s.setComplaintsTimeout()
		return nil
	}
	return errors.New("the next timeout should be to end DKG protocol")
}

// End ends the protocol in the current node
// It returns the finalized public data and node private key share.
// - the group public key corresponding to the group secret key
// - all the public key shares corresponding to the nodes private
// key shares.
// - the finalized private key which is the current node's own private key share
// This is also a timeout to receiving all complaint answers
func (s *feldmanVSSQualState) End() (PrivateKey, PublicKey, []PublicKey, error) {
	if !s.running {
		return nil, nil, nil, errors.New("dkg protocol is not running")
	}
	if !s.sharesTimeout || !s.complaintsTimeout {
		return nil, nil, nil,
			errors.New("two timeouts should be set before ending dkg")
	}
	s.running = false
	// check if a complaint has remained without an answer
	// a leader is disqualified if a complaint was never answered
	if !s.disqualified {
		for complainer, c := range s.complaints {
			if c.received && !c.answerReceived {
				s.disqualified = true
				s.processor.Disqualify(int(s.leaderIndex),
					fmt.Sprintf("complaint from %d was not answered",
						complainer))
				break
			}
		}
	}

	// If the leader is disqualified, all keys are ignored
	// otherwise, the keys are valid
	if s.disqualified {
		return nil, nil, nil, errors.New("leader is disquified")
	}

	// private key of the current node
	x := &PrKeyBLSBLS12381{
		scalar: s.x, // the private share
	}
	// Group public key
	Y := &PubKeyBLSBLS12381{
		point: s.vA[0],
	}
	// The nodes public keys
	y := make([]PublicKey, s.size)
	for i, p := range s.y {
		y[i] = &PubKeyBLSBLS12381{
			point: p,
		}
	}
	return x, Y, y, nil
}

const (
	complaintSize      = 1
	complainAnswerSize = 1 + PrKeyLenBLSBLS12381
)

// HandleMsg processes a new message received by the current node
// orig is the message origin index
func (s *feldmanVSSQualState) HandleMsg(orig int, msg []byte) error {
	if !s.running {
		return errors.New("dkg is not running")
	}
	if orig >= s.Size() || orig < 0 {
		return fmt.Errorf("wrong origin input, should be less than %d, got %d",
			s.Size(), orig)
	}

	if len(msg) == 0 {
		s.processor.FlagMisbehavior(orig, "received message is empty")
		return nil
	}

	// In case a broadcasted message is received by the origin node,
	// the message is just ignored
	if s.currentIndex == index(orig) {
		return nil
	}

	// if leader is already disqualified, ignore the message
	if s.disqualified {
		return nil
	}

	switch dkgMsgTag(msg[0]) {
	case feldmanVSSShare:
		s.receiveShare(index(orig), msg[1:])
	case feldmanVSSVerifVec:
		s.receiveVerifVector(index(orig), msg[1:])
	case feldmanVSSComplaint:
		s.receiveComplaint(index(orig), msg[1:])
	case feldmanVSSComplaintAnswer:
		s.receiveComplaintAnswer(index(orig), msg[1:])
	default:
		s.processor.FlagMisbehavior(orig,
			fmt.Sprintf("invalid message header, got %d",
				dkgMsgTag(msg[0])))
	}
	return nil
}

// ForceDisqualify forces a node to get disqualified
// for a reason outside of the DKG protocol
// The caller should make sure all honest nodes call this function,
// otherwise, the protocol can be broken
func (s *feldmanVSSQualState) ForceDisqualify(node int) error {
	if !s.running {
		return errors.New("dkg is not running")
	}
	if node >= s.Size() || node < 0 {
		return fmt.Errorf("wrong origin input, should be less than %d, got %d",
			s.Size(), node)
	}
	if index(node) == s.leaderIndex {
		s.disqualified = true
	}
	return nil
}

func (s *feldmanVSSQualState) setSharesTimeout() {
	s.sharesTimeout = true
	// if verif vector is not received, disqualify the leader
	if !s.vAReceived {
		s.disqualified = true
		s.processor.Disqualify(int(s.leaderIndex),
			"verification vector was not received")
		return
	}
	// if share is not received, make a complaint
	if !s.xReceived {
		s.complaints[s.currentIndex] = &complaint{
			received:       true,
			answerReceived: false,
		}
		data := []byte{byte(feldmanVSSComplaint), byte(s.leaderIndex)}
		s.processor.Broadcast(data)
	}
}

func (s *feldmanVSSQualState) setComplaintsTimeout() {
	s.complaintsTimeout = true
	// if more than t complaints are received, the leader is disqualified
	// regardless of the answers.
	// (at this point, all answered complaints should have been already received)
	// (i.e there is no complaint with (!c.received && c.answerReceived)
	if len(s.complaints) > s.threshold {
		s.disqualified = true
		s.processor.Disqualify(int(s.leaderIndex),
			fmt.Sprintf("there are %d complaints, they exceeded the threshold %d",
				len(s.complaints), s.threshold))
	}
}

func (s *feldmanVSSQualState) receiveShare(origin index, data []byte) {
	// check the share timeout
	if s.sharesTimeout {
		s.processor.FlagMisbehavior(int(origin),
			"private share is received after the shares timeout")
		return
	}
	// only accept private shares from the leader.
	if origin != s.leaderIndex {
		return
	}

	if s.xReceived {
		s.processor.FlagMisbehavior(int(origin),
			"private share was already received")
		return
	}
	if (len(data)) != shareSize {
		s.processor.FlagMisbehavior(int(origin),
			fmt.Sprintf("invalid share size, expects %d, got %d",
				shareSize, len(data)))
		return
	}
	// read the node private share
	if C.bn_read_Zr_bin((*C.bn_st)(&s.x),
		(*C.uchar)(&data[0]),
		PrKeyLenBLSBLS12381,
	) != valid {
		s.processor.FlagMisbehavior(int(origin),
			fmt.Sprintf("invalid share value %x", data))
		return
	}
	s.xReceived = true
	if s.vAReceived {
		result := s.verifyShare()
		if result {
			return
		}
		// otherwise, build a complaint to broadcast and add it to the local
		// complaint map
		s.complaints[s.currentIndex] = &complaint{
			received:       true,
			answerReceived: false,
		}
		data := []byte{byte(feldmanVSSComplaint), byte(s.leaderIndex)}
		s.processor.Broadcast(data)
	}
}

func (s *feldmanVSSQualState) receiveVerifVector(origin index, data []byte) {
	// check the share timeout
	if s.sharesTimeout {
		s.processor.FlagMisbehavior(int(origin),
			"verification vector received after the shares timeout")
		return
	}

	// only accept the verification vector from the leader.
	if origin != s.leaderIndex {
		return
	}

	if s.vAReceived {
		s.processor.FlagMisbehavior(int(origin),
			"verification received was already received")
		return
	}
	s.vAReceived = true

	if len(data) != verifVectorSize*(s.threshold+1) {
		s.disqualified = true
		s.processor.Disqualify(int(origin),
			fmt.Sprintf("invalid verification vector size, expects %d, got %d",
				verifVectorSize*(s.threshold+1), len(data)))
		return
	}
	// read the verification vector
	s.vA = make([]pointG2, s.threshold+1)
	err := readVerifVector(s.vA, data)
	if err != nil {
		s.disqualified = true
		s.processor.Disqualify(int(origin),
			fmt.Sprintf("reading the verification vector failed:%s", err))
		return
	}

	s.y = make([]pointG2, s.size)
	s.computePublicKeys()

	// check the (already) registered complaints
	for complainer, c := range s.complaints {
		if c.received && c.answerReceived {
			if s.checkComplaint(complainer, c) {
				s.disqualified = true
				s.processor.Disqualify(int(s.leaderIndex),
					fmt.Sprintf("verification vector received: a complaint answer to %d is invalid",
						complainer))
				return
			}
		}
	}
	// check the private share
	if s.xReceived {
		result := s.verifyShare()
		if result {
			return
		}
		// otherwise, build a complaint to broadcast and add it to the local
		// complaints map
		s.complaints[s.currentIndex] = &complaint{
			received:       true,
			answerReceived: false,
		}
		data := []byte{byte(feldmanVSSComplaint), byte(s.leaderIndex)}
		s.processor.Broadcast(data)
	}
}

// assuming a complaint and its answer were received, this function returns
// - false if the answer is valid
// - true if the complaint is valid
func (s *feldmanVSSQualState) checkComplaint(complainer index, c *complaint) bool {
	// check y[complainer] == share.G2
	return C.verifyshare((*C.bn_st)(&c.answer),
		(*C.ep2_st)(&s.y[complainer])) == 0
}

// data = |complainee|
func (s *feldmanVSSQualState) receiveComplaint(origin index, data []byte) {
	// check the complaints timeout
	if s.complaintsTimeout {
		s.processor.FlagMisbehavior(int(origin),
			"complaint received after the complaint timeout")
		return
	}

	if origin == s.leaderIndex {
		return
	}

	if len(data) != complaintSize {
		s.disqualified = true
		s.processor.Disqualify(int(origin),
			fmt.Sprintf("invalid complaint size, expects %d, got %d",
				complaintSize, len(data)))
		return
	}

	// the byte encodes the complainee
	complainee := index(data[0])

	// if the complainee is not the leader, ignore the complaint
	if complainee != s.leaderIndex {
		return
	}

	c, ok := s.complaints[origin]
	// if the complaint is new, add it
	if !ok {
		s.complaints[origin] = &complaint{
			received:       true,
			answerReceived: false,
		}
		// if the complainee is the current node, prepare an answer
		if s.currentIndex == s.leaderIndex {
			data := make([]byte, complainAnswerSize+1)
			data[0] = byte(feldmanVSSComplaintAnswer)
			data[1] = byte(origin)
			zrPolynomialImage(data[2:], s.a, origin+1, nil)
			s.complaints[origin].answerReceived = true
			s.processor.Broadcast(data)
		}
		return
	}
	// complaint is not new in the map
	// check if the complain has been already received
	if c.received {
		s.processor.FlagMisbehavior(int(origin),
			"complaint was already received")
		return
	}
	c.received = true
	// first flag check is a sanity check
	if c.answerReceived && s.currentIndex != s.leaderIndex {
		s.disqualified = s.checkComplaint(origin, c)
		if s.disqualified {
			s.processor.Disqualify(int(s.leaderIndex),
				fmt.Sprintf("complaint received: complaint answer to %d is invalid",
					origin))
		}
		return
	}
}

// answer = |complainer| private share |
func (s *feldmanVSSQualState) receiveComplaintAnswer(origin index, data []byte) {
	// check for invalid answers
	if origin != s.leaderIndex {
		return
	}

	if len(data) == 0 {
		s.disqualified = true
		s.processor.Disqualify(int(origin), "complaint answer is empty")
		return
	}

	// first byte encodes the complainee
	complainer := index(data[0])
	if int(complainer) >= s.size {
		s.disqualified = true
		s.processor.Disqualify(int(origin),
			fmt.Sprintf("complainer value is invalid, should be less that %d, got %d",
				s.size, int(complainer)))
		return
	}

	c, ok := s.complaints[complainer]
	// if the complaint is new, add it
	if !ok {
		s.complaints[complainer] = &complaint{
			received:       false,
			answerReceived: true,
		}
		// check the answer format
		if len(data) != complainAnswerSize {
			s.disqualified = true
			s.processor.Disqualify(int(s.leaderIndex),
				fmt.Sprintf("the complaint answer has an invalid length, expects %d, got %d",
					complainAnswerSize, len(data)))
			return
		}
		// read the complainer private share
		if C.bn_read_Zr_bin((*C.bn_st)(&s.complaints[complainer].answer),
			(*C.uchar)(&data[1]),
			PrKeyLenBLSBLS12381,
		) != valid {
			s.disqualified = true
			s.processor.Disqualify(int(s.leaderIndex),
				fmt.Sprintf("invalid complaint answer value %x", data))
			return
		}
		return
	}
	// complaint is not new in the map
	// check if the answer has been already received
	if c.answerReceived {
		s.processor.FlagMisbehavior(int(origin),
			"complaint answer was already received")
		return
	}

	c.answerReceived = true
	if len(data) != complainAnswerSize {
		s.disqualified = true
		s.processor.Disqualify(int(s.leaderIndex),
			fmt.Sprintf("invalid complaint answer length, expected %d, got %d",
				complainAnswerSize, len(data)))
		return
	}

	// first flag check is a sanity check
	if c.received {
		// read the complainer private share
		if C.bn_read_Zr_bin((*C.bn_st)(&c.answer),
			(*C.uchar)(&data[1]),
			PrKeyLenBLSBLS12381,
		) != valid {
			s.disqualified = true
			s.processor.Disqualify(int(s.leaderIndex),
				fmt.Sprintf("invalid complaint answer value %x", data))
			return
		}
		s.disqualified = s.checkComplaint(complainer, c)
		if s.disqualified {
			s.processor.Disqualify(int(s.leaderIndex),
				fmt.Sprintf("complaint answer received: complaint answer to %d is invalid",
					complainer))
		}

		// fix the share of the current node if the complaint in invalid
		if !s.disqualified && complainer == s.currentIndex {
			s.x = c.answer
		}
	}
}
