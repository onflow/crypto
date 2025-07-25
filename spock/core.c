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

 #include "include.h"


// Verifies the validity of 2 SPoCK proofs and 2 public keys.
// Membership check in G1 of both proofs is verified in this function.
// Membership check in G2 of both keys is not verified in this function.
// the membership check in G2 is separated to allow optimizing multiple
// verifications using the same public keys.
int bls_spock_verify(const E2 *pk1, const byte *sig1, const E2 *pk2,
    const byte *sig2) {
E1 elemsG1[2];
E2 elemsG2[2];

// elemsG1[0] = s1
if (E1_read_bytes(&elemsG1[0], sig1, G1_SER_BYTES) != VALID) {
return INVALID;
};
// check s1 is in G1
if (!E1_in_G1(&elemsG1[0])) {
return INVALID;
}

// elemsG1[1] = s2
if (E1_read_bytes(&elemsG1[1], sig2, G1_SER_BYTES) != VALID) {
return INVALID;
};
// check s2 is in G1
if (!E1_in_G1(&elemsG1[1])) {
return INVALID;
}

// elemsG2[1] = pk1
E2_copy(&elemsG2[1], pk1);

// elemsG2[0] = -pk2
E2_neg(&elemsG2[0], pk2);

// double pairing
Fp12 e;
Fp12_multi_pairing(&e, elemsG1, elemsG2, 2);

if (Fp12_is_one(&e)) {
return VALID;
}
return INVALID;
}
