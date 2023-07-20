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

#ifndef _REL_DKG_INCLUDE_H
#define _REL_DKG_INCLUDE_H

#include "bls12381_utils.h"

// the highest index of a DKG participant
#define MAX_IND         255
#define MAX_IND_BITS    8

void Zr_polynomialImage_export(byte* out, ep2_t y, const bn_st* a, const int a_size, const byte x);
void Zr_polynomialImage(bn_t out, ep2_t y, const bn_st* a, const int a_size, const byte x);
void G2_polynomialImages(ep2_st* y, const int len_y, const ep2_st* A, const int len_A);
void ep2_vector_write_bin(byte* out, const ep2_st* A, const int len);
int  ep2_vector_read_bin(ep2_st* A, const byte* src, const int len);
int  verifyshare(const bn_t x, const ep2_t y);

#endif
