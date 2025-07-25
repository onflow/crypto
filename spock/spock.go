//go:build cgo && !no_cgo
// +build cgo,!no_cgo

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

package spock

// SPoCK design based on the BLS signature scheme.
// BLS is using BLS12-381 curve and the same settings in bls.go.

// #cgo CFLAGS: -I${SRCDIR}/ -I${SRCDIR}/../internal/bls12381 -I${SRCDIR}/../internal/bls12381/blst_src -I${SRCDIR}../internal/bls12381/blst_src/build -D__BLST_CGO__ -Wall -fno-builtin-memcpy -fno-builtin-memset -Wno-unused-function -Wno-unused-macros -Wno-unused-variable
// #cgo amd64 CFLAGS: -D__ADX__ -mno-avx
// #cgo loong64 mips64 mips64le ppc64 ppc64le riscv64 s390x CFLAGS: -D__BLST_NO_ASM__
// #cgo noescape bls_spock_verify
// #cgo nocallback bls_spock_verify
// #include "include.h"
import "C"
import (
	"fmt"

	"github.com/onflow/crypto/hash"
	"github.com/onflow/crypto/sign"
)

// SPOCKProve generates a spock poof for data under the private key sk.
//
// The function returns:
//   - (false, errNilHasher) if the hasher is nil
//   - (false, invalidHasherSiseError) if hasher's output size is not 128 bytes
//   - (nil, errNotBLSKey) if input key is not a BLS key
//   - (nil, error) if an unexpected error occurs
//   - (proof, nil) otherwise
func SPOCKProve(sk sign.PrivateKey, data []byte, kmac hash.Hasher) (sign.Signature, error) {
	if sk.Algorithm() != sign.BLSBLS12381 {
		return nil, errNotBLSKey
	}

	// BLS signature of data
	return sk.Sign(data, kmac)
}

// SPOCKVerifyAgainstData verifies a SPoCK proof is generated from the given data
// and the prover's public key.
//
// This is a simple BLS signature verifictaion of the proof under the input data
// and public key.
//
// The function returns:
//   - (false, errNotBLSKey) if input key is not a BLS key
//   - (false, errNilHasher) if the hasher is nil
//   - (false, invalidHasherSiseError) if hasher's output size is not 128 bytes
//   - (false, error) if an unexpected error occurs
//   - (validity, nil) otherwise
func SPOCKVerifyAgainstData(pk sign.PublicKey, proof sign.Signature, data []byte, kmac hash.Hasher) (bool, error) {
	if pk.Algorithm() != sign.BLSBLS12381 {
		return false, errNotBLSKey
	}
	// BLS verification of data
	return pk.Verify(proof, data, kmac)
}

// SPOCKVerify checks whether two couples of (SPoCK proof, public key) are consistent.
//
// Two (SPoCK proof, public key) couples are consistent if there exists a message such
// that each proof could be generated from the message and the private key corresponding
// to the respective public key.
//
// If the input proof slices have an invalid length or fail to deserialize into curve
// points, the function returns false without an error.
// The proofs membership checks in G1 are included in the verifcation.
//
// The function does not check the public keys membership in G2 because it is
// guaranteed by the package. However, the caller must make sure each input public key has been
// verified against a proof of possession prior to calling this function.
//
// The function returns:
//   - (false, errNotBLSKey) if at least one key is not a BLS key.
//   - (false, error) if an unexpected error occurs.
//   - (validity, nil) otherwise
func SPOCKVerify(pk1 sign.PublicKey, proof1 sign.Signature, pk2 sign.PublicKey, proof2 sign.Signature) (bool, error) {
	blsPk1, ok1 := pk1.(*pubKeyBLSBLS12381)
	blsPk2, ok2 := pk2.(*pubKeyBLSBLS12381)
	if !ok1 || !ok2 {
		return false, errNotBLSKey
	}

	if len(proof1) != g1BytesLen || len(proof2) != g1BytesLen {
		return false, nil
	}

	// if pk1 and proof1 are identities of their respective groups, any couple (pk2, proof2) would
	// verify the pairing equality which breaks the unforgeability of the SPoCK scheme. This edge case
	// is avoided by not allowing an identity pk1. Similarly, an identity pk2 is not allowed.
	if blsPk1.isIdentity || blsPk2.isIdentity {
		return false, nil
	}

	// verify the spock proof using the secret data
	verif := C.bls_spock_verify((*C.E2)(&blsPk1.point),
		(*C.uchar)(&proof1[0]),
		(*C.E2)(&blsPk2.point),
		(*C.uchar)(&proof2[0]))

	switch verif {
	case invalid:
		return false, nil
	case valid:
		return true, nil
	default:
		return false, fmt.Errorf("SPoCK verification failed")
	}
}
