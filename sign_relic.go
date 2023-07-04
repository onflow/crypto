//go:build relic
// +build relic

/*
 * Flow Go Crypto
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
	"fmt"
)

// newSigner chooses and initializes a signature scheme
func newSigner(algo SigningAlgorithm) (signer, error) {
	// try Relic algos
	if signer := relicSigner(algo); signer != nil {
		return signer, nil
	}
	// return a non-Relic algo
	return newNonRelicSigner(algo)
}

// relicSigner returns a signer that depends on Relic library.
func relicSigner(algo SigningAlgorithm) signer {
	if algo == BLSBLS12381 {
		return blsInstance
	}
	return nil
}

// Initialize Relic with the BLS context on BLS 12-381
func init() {
	initRelic()
	initNonRelic()
}

// Initialize the context of all algos requiring Relic
func initRelic() {
	blsInstance = &blsBLS12381Algo{
		algo: BLSBLS12381,
	}
	if err := blsInstance.init(); err != nil {
		panic(fmt.Sprintf("initialization of BLS failed: %s", err.Error()))
	}
}
