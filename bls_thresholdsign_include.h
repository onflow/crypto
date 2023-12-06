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

#ifndef _THRESHOLD_INCLUDE_H
#define _THRESHOLD_INCLUDE_H

#include "bls_include.h"

int E1_lagrange_interpolate_at_zero_write(byte *, const byte *, const byte[],
                                          const int);
extern void Fr_polynomial_image(Fr *out, E2 *y, const Fr *a, const int a_size,
                                const byte x);

#endif
