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

package hash

const (
	rateSHA3_256 = 136
	rateSHA3_384 = 104

	dsByteSHA3 = byte(0x6)
)

// NewSHA3_256 returns a new instance of SHA3-256 hasher.
func NewSHA3_256() Hasher {
	return &spongeState{
		algo:      SHA3_256,
		rate:      rateSHA3_256,
		dsByte:    dsByteSHA3,
		outputLen: HashLenSHA3_256,
		bufIndex:  bufNilValue,
		bufSize:   bufNilValue,
	}
}

// NewSHA3_384 returns a new instance of SHA3-384 hasher.
func NewSHA3_384() Hasher {
	return &spongeState{
		algo:      SHA3_384,
		rate:      rateSHA3_384,
		dsByte:    dsByteSHA3,
		outputLen: HashLenSHA3_384,
		bufIndex:  bufNilValue,
		bufSize:   bufNilValue,
	}
}

// ComputeSHA3_256 computes the SHA3-256 digest of data
// and copies the result to the result buffer.
//
// The function is not part of the Hasher API. It is a pure function
// for simple computation of a hash with minimal heap allocations.
func ComputeSHA3_256(result *[HashLenSHA3_256]byte, data []byte) {
	state := &spongeState{
		rate:      rateSHA3_256,
		dsByte:    dsByteSHA3,
		outputLen: HashLenSHA3_256,
		bufIndex:  bufNilValue,
		bufSize:   bufNilValue,
	}
	state.write(data)
	state.padAndPermute()
	copyOut(result[:], state)
}
