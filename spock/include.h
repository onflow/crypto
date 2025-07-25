#ifndef _SPOCK_INCLUDE_H
#define _SPOCK_INCLUDE_H

#include "bls12381_utils.h"

// BLS based SPoCK
int bls_spock_verify(const E2 *, const byte *, const E2 *, const byte *);

#endif