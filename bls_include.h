// +build relic

// this file is about the core functions required by the BLS signature scheme

#ifndef _REL_BLS_INCLUDE_H
#define _REL_BLS_INCLUDE_H

#include "relic.h"
#include "bls12381_utils.h"

// Signature, Public key and Private key lengths
#define FULL_SIGNATURE_LEN  G1_BYTES
#define FULL_PK_LEN         G2_BYTES
#define SIGNATURE_LEN       (FULL_SIGNATURE_LEN/(G1_SERIALIZATION+1))
#define PK_LEN              (FULL_PK_LEN/(G2_SERIALIZATION+1))
#define SK_BITS             (Fr_BITS)
#define SK_LEN              BITS_TO_BYTES(SK_BITS)    

// bls core (functions in bls_core.c)
int      get_signature_len();
int      get_pk_len();
int      get_sk_len();  

int      bls_sign(byte*, const Fr*, const byte*, const int);
int      bls_verify(const E2*, const byte*, const byte*, const int);
int      bls_verifyPerDistinctMessage(const byte*, const int, const byte*, const uint32_t*,
                         const uint32_t*, const E2*);
int      bls_verifyPerDistinctKey(const byte*, 
                         const int, const E2*, const uint32_t*,
                         const byte*, const uint32_t*);
void     bls_batch_verify(const int, byte*, const E2*,
            const byte*, const byte*, const int, const byte*);

#endif
