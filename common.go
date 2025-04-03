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

package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
)

//revive:disable:var-naming

const (
	// Minimum targeted bits of security.
	// This is used as a reference but it doesn't mean all implemented primitives provide this minimum.
	securityBits = 128

	// keygen seed length conditions
	// enforce seed to be at least double the security bits and have enough entropy.
	// it is still recommened that seed is generated using a secure RNG.
	KeyGenSeedMinLen = 2 * (securityBits / 8)
	KeyGenSeedMaxLen = 256
)

// TODO: update this code to make sure
// the function isn't removed by the compiler
// https://github.com/golang/go/issues/21865
func overwrite(data []byte) {
	_, err := rand.Read(data) // checking err is enough
	if err != nil {
		// zero the buffer if randomizing failed
		for i := 0; i < len(data); i++ {
			data[i] = 0
		}
	}
}

// invalidInputsError is an error returned when a crypto API receives invalid inputs.
// It allows a function caller differentiate unexpected program errors from errors caused by
// invalid inputs.
type invalidInputsError struct {
	error
}

func (e invalidInputsError) Unwrap() error {
	return e.error
}

// invalidInputsErrorf constructs a new invalidInputsError
func invalidInputsErrorf(msg string, args ...interface{}) error {
	return &invalidInputsError{
		error: fmt.Errorf(msg, args...),
	}
}

// IsInvalidInputsError checks if the input error is of an invalidInputsError type
// invalidInputsError is returned when the API is provided invalid inputs.
// Some specific errors are assigned specific sentinel errors for a simpler error check
// while the remaining input errors trigger an invalidInputsError.
func IsInvalidInputsError(err error) bool {
	var target *invalidInputsError
	return errors.As(err, &target)
}

var errNilHasher = errors.New("hasher cannot be nil")

// IsErrNilHasher checks if the input error wraps a errNilHasher.
// errNilHasher is returned when a nil hasher is used.
func IsErrNilHasher(err error) bool {
	return errors.Is(err, errNilHasher)
}

// errInvalidHasherSize is an error returned when a crypto API is called with a hasher
// with an output size not suited with the cryptographic operation.
type errInvalidHasherSize struct {
	error
}

func (e errInvalidHasherSize) Unwrap() error {
	return e.error
}

// invalidHasherSizeErrorf constructs a new errInvalidHasherSize
func invalidHasherSizeErrorf(msg string, args ...interface{}) error {
	return &errInvalidHasherSize{
		error: fmt.Errorf(msg, args...),
	}
}

// IsErrInvalidHasherSize checks if the input error is of an errInvalidHasherSize type.
// errInvalidHasherSize is an error returned when a crypto API is called with a hasher
// with an output size not suited with the cryptographic operation.
func IsErrInvalidHasherSize(err error) bool {
	var target *errInvalidHasherSize
	return errors.As(err, &target)
}
