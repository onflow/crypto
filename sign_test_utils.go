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
	"fmt"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/onflow/crypto/hash"
	"github.com/onflow/crypto/sign"
	"github.com/onflow/crypto/sign/testutils"
)

func getPRG(t *testing.T) *mrand.Rand {
	random := time.Now().UnixNano()
	t.Logf("rng seed is %d", random)
	rng := mrand.New(mrand.NewSource(random))
	return rng
}

func TestKeyGenErrors(t *testing.T) {
	seed := make([]byte, 50)
	invalidSigAlgo := sign.SigningAlgorithm(20)
	sk, err := sign.GeneratePrivateKey(invalidSigAlgo, seed)
	assert.Nil(t, sk)
	assert.Error(t, err)
	assert.True(t, IsInvalidInputsError(err))
}

func TestHasherErrors(t *testing.T) {
	t.Run("nilHasher error sanity", func(t *testing.T) {
		err := errNilHasher
		invInpError := invalidInputsErrorf("")
		otherError := fmt.Errorf("some error")
		assert.True(t, IsNilHasherError(err))
		assert.False(t, IsInvalidInputsError(err))
		assert.False(t, IsNilHasherError(invInpError))
		assert.False(t, IsNilHasherError(otherError))
		assert.False(t, IsNilHasherError(nil))
	})

	t.Run("nilHasher error sanity", func(t *testing.T) {
		err := invalidHasherSizeErrorf("")
		invInpError := invalidInputsErrorf("")
		otherError := fmt.Errorf("some error")
		assert.True(t, IsInvalidHasherSizeError(err))
		assert.False(t, IsInvalidInputsError(err))
		assert.False(t, IsInvalidHasherSizeError(invInpError))
		assert.False(t, IsInvalidHasherSizeError(otherError))
		assert.False(t, IsInvalidHasherSizeError(nil))
	})
}

func testGenSignVerify(t *testing.T, salg sign.SigningAlgorithm, halg hash.Hasher) {
	testutils.TestGenSignVerify(t, salg, halg)
}

func testKeyGenSeed(t *testing.T, salg sign.SigningAlgorithm, minLen int, maxLen int) {
	testutils.TestKeyGenSeed(t, salg, minLen, maxLen)
}

var BLS12381Order = []byte{0x73, 0xED, 0xA7, 0x53, 0x29, 0x9D, 0x7D, 0x48, 0x33, 0x39,
	0xD8, 0x08, 0x09, 0xA1, 0xD8, 0x05, 0x53, 0xBD, 0xA4, 0x02, 0xFF, 0xFE,
	0x5B, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01}

func testEncodeDecode(t *testing.T, salg sign.SigningAlgorithm) {
	testutils.TestEncodeDecode(t, salg)
}

func testEquals(t *testing.T, salg sign.SigningAlgorithm, otherSigAlgo sign.SigningAlgorithm) {
	testutils.TestEquals(t, salg, otherSigAlgo)
}

func testKeysAlgorithm(t *testing.T, sk sign.PrivateKey, salg sign.SigningAlgorithm) {
	testutils.TestKeysAlgorithm(t, sk, salg)
}

func testKeySize(t *testing.T, sk sign.PrivateKey, skLen int, pkLen int) {
	testutils.TestKeySize(t, sk, skLen, pkLen)
}

func benchVerify(b *testing.B, algo sign.SigningAlgorithm, halg hash.Hasher) {
	testutils.BenchVerify(b, algo, halg)
}

func benchSign(b *testing.B, algo sign.SigningAlgorithm, halg hash.Hasher) {
	testutils.BenchSign(b, algo, halg)
}
