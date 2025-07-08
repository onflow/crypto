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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/onflow/crypto/sign"
)


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

var BLS12381Order = []byte{0x73, 0xED, 0xA7, 0x53, 0x29, 0x9D, 0x7D, 0x48, 0x33, 0x39,
	0xD8, 0x08, 0x09, 0xA1, 0xD8, 0x05, 0x53, 0xBD, 0xA4, 0x02, 0xFF, 0xFE,
	0x5B, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01}
