// +build relic

package crypto

// #cgo CFLAGS: -g -Wall -std=c99 -I./ -I./relic/include -I./relic/include/low
// #cgo LDFLAGS: -Lrelic/build/lib -l relic_s
// #include "dkg_include.h"
import "C"
import (
	log "github.com/sirupsen/logrus"
)

func (s *feldmanVSSQualState) setSharesTimeout() []DKGToSend {
	s.sharesTimeout = true
	// if verif vector is not received, disqualify the leader
	if !s.AReceived {
		s.disqualified = true
		return []DKGToSend{}
	}
	// if share is not received, make a complaint
	if !s.xReceived {
		toSend := DKGToSend{
			broadcast: true,
			data:      []byte{byte(FeldmanVSSComplaint), byte(s.leaderIndex)},
		}
		s.complaints[s.currentIndex] = &complaint{
			received:       true,
			answerReceived: false,
		}
		return []DKGToSend{toSend}
	}
	return []DKGToSend{}
}

func (s *feldmanVSSQualState) setComplaintsTimeout() {
	s.complaintsTimeout = true
	// if more than t complaints are received, the leader is disqualified
	// regardless of the answers.
	// (at this point, all answered complaints should have been already received)
	// (i.e there is no complaint with (!c.received && c.answerReceived)
	// TODO: sanity check and return an error?
	if len(s.complaints) > s.threshold {
		s.disqualified = true
	}
}

func (s *feldmanVSSQualState) receiveShare(origin index, data []byte) (DKGresult, []DKGToSend) {
	// check the share timeout
	if s.sharesTimeout {
		return invalid, nil
	}
	// only accept private shares from the leader.
	if origin != s.leaderIndex {
		return invalid, nil
	}

	if s.xReceived {
		return invalid, nil
	}
	if (len(data)) != shareSize {
		return invalid, nil
	}
	// temporary log
	log.Debugf("%d Receiving a share from %d\n", s.currentIndex, origin)
	log.Debugf("the share is %d\n", data)
	// read the node private share
	C.bn_read_bin((*C.bn_st)(&s.x),
		(*C.uchar)(&data[0]),
		PrKeyLenBLS_BLS12381,
	)
	s.xReceived = true
	if s.AReceived {
		result := s.verifyShare()
		if result == valid {
			return valid, nil
		}
		// otherwise, build a complaint to send and add it to the local
		// complaints map
		toSend := DKGToSend{
			broadcast: true,
			data:      []byte{byte(FeldmanVSSComplaint), byte(s.leaderIndex)},
		}
		s.complaints[s.currentIndex] = &complaint{
			received:       true,
			answerReceived: false,
		}
		return valid, []DKGToSend{toSend}
	}
	return valid, nil
}

func (s *feldmanVSSQualState) receiveVerifVector(origin index, data []byte) (DKGresult, []DKGToSend) {
	// check the share timeout
	if s.sharesTimeout {
		return invalid, nil
	}

	// only accept the verification vector from the leader.
	if origin != s.leaderIndex {
		return invalid, nil
	}

	if s.AReceived {
		return invalid, nil
	}
	if len(data) != verifVectorSize*(s.threshold+1) {
		return invalid, nil
	}

	// temporary log
	log.Debugf("%d Receiving vector from %d\n", s.currentIndex, origin)
	log.Debugf("the vector is %d\n", data)

	// read the verification vector
	s.A = make([]pointG2, s.threshold+1)
	readVerifVector(s.A, data)

	s.y = make([]pointG2, s.size)
	s.computePublicKeys()

	s.AReceived = true
	// check the (already) registered complaints
	for complainee, c := range s.complaints {
		if c.received && c.answerReceived {
			if s.checkComplaint(complainee, c) {
				s.disqualified = true
				return valid, nil
			}
		}
	}
	// check the private share
	if s.xReceived {
		result := s.verifyShare()
		if result == valid {
			return result, nil
		}
		// otherwise, build a complaint to send and add it to the local
		// complaints map
		toSend := DKGToSend{
			broadcast: true,
			data:      []byte{byte(FeldmanVSSComplaint), byte(s.leaderIndex)},
		}
		s.complaints[s.currentIndex] = &complaint{
			received:       true,
			answerReceived: false,
		}
		return valid, []DKGToSend{toSend}
	}
	return valid, nil
}

// assuming a complaint and its answer were received, this function returns
// - false if the answer is valid
// - true if the complaint is valid
func (s *feldmanVSSQualState) checkComplaint(complainee index, c *complaint) bool {
	// check y[complainee] == share.G2
	return C.verifyshare((*C.bn_st)(&c.answer),
		(*C.ep2_st)(&s.y[complainee])) == 0
}

// data = |complainee|
func (s *feldmanVSSQualState) receiveComplaint(origin index, data []byte) (DKGresult, []DKGToSend) {
	// check the complaints timeout
	if s.complaintsTimeout {
		return invalid, nil
	}

	if len(data) == 0 || origin == s.leaderIndex {
		return invalid, nil
	}

	// first byte encodes the complainee
	complainee := index(data[0])

	// if the complainee is not the leader, ignore the complaint
	if complainee != s.leaderIndex || len(data) != complaintSize {
		return invalid, nil
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
			data[0] = byte(FeldmanVSSComplaintAnswer)
			data[1] = byte(origin)
			ZrPolynomialImage(data[2:], s.a, origin+1, nil)
			toSend := DKGToSend{
				broadcast: true,
				data:      data,
			}
			s.complaints[origin].answerReceived = true
			return valid, []DKGToSend{toSend}
		}
		return valid, nil
	}
	// complaint is not new in the map
	// check if the complain has been already received
	if c.received {
		return invalid, nil
	}
	c.received = true
	// first flag check is a sanity check
	if c.answerReceived && s.currentIndex != s.leaderIndex {
		s.disqualified = s.checkComplaint(origin, c)
		return valid, nil
	}
	return invalid, nil
}

// answer = |complainer| private share |
func (s *feldmanVSSQualState) receiveComplaintAnswer(origin index, data []byte) DKGresult {
	// check for invalid answers
	if origin != s.leaderIndex || len(data) == 0 {
		return invalid
	}

	// first byte encodes the complainee
	complainer := index(data[0])

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
			return valid
		}
		// read the complainer private share
		C.bn_read_bin((*C.bn_st)(&c.answer),
			(*C.uchar)(&data[1]),
			PrKeyLenBLS_BLS12381,
		)
		return valid
	}
	// complaint is not new in the map
	// check if the answer has been already received
	if c.answerReceived {
		return invalid
	}

	c.answerReceived = true
	if len(data) != complainAnswerSize {
		s.disqualified = true
		return valid
	}

	// first flag check is a sanity check
	if c.received {
		// read the complainer private share
		C.bn_read_bin((*C.bn_st)(&c.answer),
			(*C.uchar)(&data[1]),
			PrKeyLenBLS_BLS12381,
		)
		s.disqualified = s.checkComplaint(complainer, c)

		// fix the share of the current node if the complaint in invalid
		if !s.disqualified && complainer == s.currentIndex {
			s.x = c.answer
		}
		return valid
	}
	return invalid
}
