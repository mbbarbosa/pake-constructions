#ifndef TWOFEISTEL_H
#define TWOFEISTEL_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

/*
  Implementation of the Two-Feistel construction.
*/

void gen_vector(polyvec *v, const uint8_t seed[KYBER_SYMBYTES]);

void twofeistel_eval(uint8_t twofc[KYBER_PUBLICKEYBYTES],
              const uint8_t pk[KYBER_PUBLICKEYBYTES],
              const uint8_t pw[KYBER_SYMBYTES],
              const uint8_t sid[KYBER_SYMBYTES],
              const uint8_t nonce[KYBER_SYMBYTES]);


void twofeistel_inv(uint8_t pk[KYBER_PUBLICKEYBYTES],
             const uint8_t twofc[KYBER_PUBLICKEYBYTES],
             const uint8_t pw[KYBER_SYMBYTES],
             const uint8_t sid[KYBER_SYMBYTES]);

#endif
