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
	"errors"

	"github.com/onflow/crypto/internal"
)

// IsInvalidInputsError checks if the input error is of an invalidInputsError type
// invalidInputsError is returned when the API is provided invalid inputs.
// Some specific errors are assigned specific sentinel errors for a simpler error check
// while the remaining input errors trigger an invalidInputsError.
func IsInvalidInputsError(err error) bool {
	var target *internal.InvalidInputsError
	return errors.As(err, &target)
}

// InvalidInputsErrorf constructs a new invalidInputsError
var InvalidInputsErrorf = internal.InvalidInputsErrorf

// IsNilHasherError checks if the input error wraps the internal errNilHasher,
// which is returned when a nil hasher is used.
func IsNilHasherError(err error) bool {
	return errors.Is(err, ErrNilHasher)
}

// ErrNilHasher is returned when a nil hasher is used
var ErrNilHasher = internal.ErrNilHasher

// IsInvalidHasherSizeError checks if the input error is of an invalidHasherSizeError type.
// invalidHasherSizeError is an error returned when a crypto API is called with a hasher
// with an output size not suited with the cryptographic operation.
func IsInvalidHasherSizeError(err error) bool {
	var target *internal.InvalidHasherSizeError
	return errors.As(err, &target)
}

// InvalidHasherSizeErrorf constructs a new invalidHasherSizeError
var InvalidHasherSizeErrorf = internal.InvalidHasherSizeErrorf
