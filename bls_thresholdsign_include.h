// +build relic

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

#ifndef _REL_THRESHOLD_INCLUDE_H
#define _REL_THRESHOLD_INCLUDE_H

#include "bls_include.h"

// the highest k such that fact(MAX_IND)/fact(MAX_IND-k) < r 
// (approximately Fr_bits/MAX_IND_BITS)
#define MAX_IND_LOOPS   32 

int G1_lagrangeInterpolateAtZero(byte*, const byte* , const uint8_t*, const int);
extern void Zr_polynomialImage(bn_t out, ep2_t y, const bn_st* a, const int a_size, const byte x);

#endif
