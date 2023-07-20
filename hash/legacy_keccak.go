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
	rateKeccak_256 = 136

	dsByteKeccak = byte(0x1)
)

// NewKeccak_256 returns a new instance of legacy Keccak-256 hasher.
func NewKeccak_256() Hasher {
	return &spongeState{
		algo:      Keccak_256,
		rate:      rateKeccak_256,
		dsByte:    dsByteKeccak,
		outputLen: HashLenKeccak_256,
		bufIndex:  bufNilValue,
		bufSize:   bufNilValue,
	}
}
