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

// this file is about the core functions required by the BLS signature scheme

#ifndef _BLS_INCLUDE_H
#define _BLS_INCLUDE_H

#include "bls12381_utils.h"

// BLS signature core (functions in bls_core.c)
int bls_sign(byte *, const Fr *, const byte *, const int);
int bls_verify(const E2 *, const byte *, const byte *, const int);
int bls_verifyPerDistinctMessage(const byte *, const int, const byte *,
                                 const uint32_t *, const uint32_t *,
                                 const E2 *);
int bls_verifyPerDistinctKey(const byte *, const int, const E2 *,
                             const uint32_t *, const byte *, const uint32_t *);
void bls_batch_verify(const int, byte *, const E2 *, const byte *, const byte *,
                      const int, const byte *);

// BLS based SPoCK
int bls_spock_verify(const E2 *, const byte *, const E2 *, const byte *);

#endif
