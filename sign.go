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
	"crypto/elliptic"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/onflow/crypto/sign"
)

type SigningAlgorithm = sign.SigningAlgorithm
type Signature = sign.Signature
type PrivateKey = sign.PrivateKey
type PublicKey = sign.PublicKey

// Algorithm instances - these will be initialized in init()
var (
	p256Instance     *ecdsaAlgo
	secp256k1Instance *ecdsaAlgo
	blsInstance      *blsBLS12381Algo
)

// Initialize the context of all algos and register them with sign package
func init() {
	// ECDSA
	p256Instance = &ecdsaAlgo{
		curve: elliptic.P256(),
		algo:  sign.ECDSAP256,
	}
	secp256k1Instance = &ecdsaAlgo{
		curve: btcec.S256(),
		algo:  sign.ECDSASecp256k1,
	}

	// BLS
	initBLS12381()
	blsInstance = &blsBLS12381Algo{
		algo: sign.BLSBLS12381,
	}

	sign.SetSignerInstances(p256Instance, secp256k1Instance, blsInstance)
}

func SignatureFormatCheck(algo SigningAlgorithm, s Signature) (bool, error) {
	return sign.SignatureFormatCheck(algo, s)
}

func GeneratePrivateKey(algo SigningAlgorithm, seed []byte) (PrivateKey, error) {
	return sign.GeneratePrivateKey(algo, seed)
}

func DecodePrivateKey(algo SigningAlgorithm, input []byte) (PrivateKey, error) {
	return sign.DecodePrivateKey(algo, input)
}

func DecodePublicKey(algo SigningAlgorithm, input []byte) (PublicKey, error) {
	return sign.DecodePublicKey(algo, input)
}

func DecodePublicKeyCompressed(algo SigningAlgorithm, data []byte) (PublicKey, error) {
	return sign.DecodePublicKeyCompressed(algo, data)
}
