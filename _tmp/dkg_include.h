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

#ifndef _DKG_INCLUDE_H
#define _DKG_INCLUDE_H

#include "bls12381_utils.h"

void Fr_polynomial_image_write(byte *out, E2 *y, const Fr *a, const int deg,
                               const byte x);
void Fr_polynomial_image(Fr *out, E2 *y, const Fr *a, const int deg,
                         const byte x);
void E2_polynomial_images(E2 *y, const int len_y, const E2 *A, const int deg);
void E2_vector_write_bytes(byte *out, const E2 *A, const int len);
ERROR G2_vector_read_bytes(E2 *A, const byte *src, const int len);
bool G2_check_log(const Fr *x, const E2 *y);

#endif
