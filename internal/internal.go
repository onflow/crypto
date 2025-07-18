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

package internal

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// Minimum targeted bits of security.
// This is used as a reference but it doesn't mean all implemented primitives provide this minimum.
const SecurityBits = 128

// TODO: update this code to make sure
// the function isn't removed by the compiler
// https://github.com/golang/go/issues/21865
func Overwrite(data []byte) {
	_, err := rand.Read(data) // checking err is enough
	if err != nil {
		// zero the buffer if randomizing failed
		for i := 0; i < len(data); i++ {
			data[i] = 0
		}
	}
}

// InvalidInputsError is an error returned when a crypto API receives invalid inputs.
// It allows a function caller differentiate unexpected program errors from errors caused by
// invalid inputs.
type InvalidInputsError struct {
	error
}

func (e InvalidInputsError) Unwrap() error {
	return e.error
}

// InvalidHasherSizeError is an error returned when a crypto API is called with a hasher
// with an output size not suited with the cryptographic operation.
type InvalidHasherSizeError struct {
	error
}

func (e InvalidHasherSizeError) Unwrap() error {
	return e.error
}

// ErrNilHasher is returned when a nil hasher is used
var ErrNilHasher = errors.New("hasher cannot be nil")

// InvalidInputsErrorf constructs a new InvalidInputsError
func InvalidInputsErrorf(msg string, args ...interface{}) error {
	return &InvalidInputsError{
		error: fmt.Errorf(msg, args...),
	}
}

// InvalidHasherSizeErrorf constructs a new InvalidHasherSizeError
func InvalidHasherSizeErrorf(msg string, args ...interface{}) error {
	return &InvalidHasherSizeError{
		error: fmt.Errorf(msg, args...),
	}
}
