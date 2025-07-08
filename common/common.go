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

package common

import (
	"crypto/rand"
)

//
// TODO: update this code to make sure the function isn't removed by the compiler
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
