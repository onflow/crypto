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

package hash

//revive:disable:var-naming

// HashingAlgorithm is an identifier for a hashing algorithm.
type HashingAlgorithm int

const (
	// Supported hashing algorithms
	UnknownHashingAlgorithm HashingAlgorithm = iota
	// SHA-2
	SHA2_256
	SHA2_384
	// SHA-3
	SHA3_256
	SHA3_384
	// KMAC (Keccak based MAC algorithm)
	KMAC128
	// legacy Keccak
	Keccak_256
)

// String returns the string representation of this hashing algorithm.
func (h HashingAlgorithm) String() string {
	return [...]string{
		"UNKNOWN",
		"SHA2_256",
		"SHA2_384",
		"SHA3_256",
		"SHA3_384",
		"KMAC128",
		"Keccak_256"}[h]
}

const (
	// minimum targeted bits of security
	securityBits = 128

	// Lengths of hash outputs in bytes
	HashLenSHA2_256   = 32
	HashLenSHA2_384   = 48
	HashLenSHA3_256   = 32
	HashLenSHA3_384   = 48
	HashLenKeccak_256 = 32

	// KMAC
	// the minimum key length in bytes
	KmacMinKeyLen = securityBits / 8
)
