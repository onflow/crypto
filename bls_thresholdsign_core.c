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

#include "bls_thresholdsign_include.h"

// the highest index of a threshold participant
#define MAX_IND 255
#define MAX_IND_BITS 8 // equal to ceiling(log_2(MAX_IND))

// Computes the Lagrange coefficient L_i(0) in Fr with regards to the range
// [indices(0)..indices(t)] and stores it in `res`, where t is the degree of the
// polynomial P.
// `degree` is equal to the polynomial degree `t`.
static void Fr_lagrange_coeff_at_zero(Fr *res, const int i,
                                      const byte indices[], const int degree) {

  // coefficient is computed as N * D^(-1)
  Fr numerator;   // eventually would represent N*R^k
  Fr denominator; // eventually would represent D*R^k

  // Initialize N and D to Montgomery constant R
  Fr_copy(&numerator, &BLS12_381_rR);
  Fr_copy(&denominator, &BLS12_381_rR);

  // sign of D: 0 for positive and 1 for negative
  int sign = 0;

  // the highest k such that fact(MAX_IND)/fact(MAX_IND-k) < 2^64 (approximately
  // 64/MAX_IND_BITS) this means we can multiply up to (k) indices in a limb (64
  // bits) without overflowing.
  const int loops = 64 / MAX_IND_BITS;
  int k, j = 0;
  Fr tmp;
  while (j < degree + 1) {
    limb_t limb_numerator = 1;
    limb_t limb_denominator = 1;
    // batch up to `loops` elements in one limb
    for (k = j; j < MIN(degree + 1, k + loops); j++) {
      if (j == i)
        continue;
      if (indices[j] < indices[i]) {
        sign ^= 1;
        limb_denominator *= indices[i] - indices[j];
      } else {
        limb_denominator *= indices[j] - indices[i];
      }
      limb_numerator *= indices[j];
    }
    // numerator and denominator are both computed in Montgomery form.
    // update numerator
    Fr_set_limb(&tmp, limb_numerator);          // L_N
    Fr_to_montg(&tmp, &tmp);                    // L_N*R
    Fr_mul_montg(&numerator, &numerator, &tmp); // N*R
    // update denominator
    Fr_set_limb(&tmp, limb_denominator);            // L_D
    Fr_to_montg(&tmp, &tmp);                        // L_D*R
    Fr_mul_montg(&denominator, &denominator, &tmp); // D*R
  }
  if (sign) {
    Fr_neg(&denominator, &denominator);
  }

  // at this point, denominator = D*R , numertaor = N*R
  // inversion inv(x) = x^(-1)R
  Fr_inv_montg_eucl(&denominator, &denominator); // (DR)^(-1)*R = D^(-1)
  Fr_mul_montg(res, &numerator, &denominator);   // N*D^(-1)
}

// Computes the Langrange interpolation at zero P(0) = LI(0) with regards to the
// indices [indices(0)..indices(t)] and their G1 images [shares(0)..shares(t)],
// and stores the resulting G1 point in `dest`.
// `degree` is equal to the polynomial degree `t`.
static void E1_lagrange_interpolate_at_zero(E1 *out, const E1 shares[],
                                            const byte indices[],
                                            const int degree) {
  // Purpose is to compute Q(0) where Q(x) = A_0 + A_1*x + ... +  A_t*x^t in G1
  // where A_i = g1 ^ a_i

  // Q(0) = share_i0 ^ L_i0(0) + share_i1 ^ L_i1(0) + .. + share_it ^ L_it(0)
  // where L is the Lagrange coefficient
  Fr *lagrange_coeffs = malloc(sizeof(Fr) * (degree + 1));
  for (int i = 0; i < degree + 1; i++) {
    Fr_lagrange_coeff_at_zero(&lagrange_coeffs[i], i, indices, degree);
  }

  E1_multi_scalar(out, shares, lagrange_coeffs, degree + 1);
  free(lagrange_coeffs);
}

// Computes the Lagrange interpolation at zero LI(0) with regards to the
// indices [indices(0)..indices(t)] and writes their E1 concatenated
// serializations [shares(1)..shares(t+1)] in `dest`.
// `degree` is equal to the polynomial degree `t`.
int E1_lagrange_interpolate_at_zero_write(byte *dest, const byte *shares,
                                          const byte indices[],
                                          const int degree) {
  int read_ret;
  E1 *E1_shares = malloc(sizeof(E1) * (degree + 1));
  for (int i = 0; i < degree + 1; i++) {
    read_ret =
        E1_read_bytes(&E1_shares[i], &shares[G1_SER_BYTES * i], G1_SER_BYTES);
    if (read_ret != VALID) {
      goto out;
    }
  }

  // G1 interpolation at 0
  // computes Q(x) = A_0 + A_1*x + ... +  A_t*x^t  in G1,
  // where A_i = g1 ^ a_i
  E1 res;
  E1_lagrange_interpolate_at_zero(&res, E1_shares, indices, degree);
  // export the result
  E1_write_bytes(dest, &res);
  read_ret = VALID;
out:
  // free the temp memory
  free(E1_shares);
  return read_ret;
}
