#ifndef HIC_H
#define HIC_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

/*
  Implementation of the Half-Ideal-Cipher construction
  stripped down to use the ML-KEM seed as internal 
  randomness.
*/

#define gen_vector KYBER_NAMESPACE(gen_vector)
void gen_vector(polyvec *v, const uint8_t seed[KYBER_SYMBYTES]);

#define hic_eval KYBER_NAMESPACE(hic_eval)
void hic_eval(uint8_t icc[KYBER_PUBLICKEYBYTES],
              const uint8_t pk[KYBER_PUBLICKEYBYTES],
              const uint8_t pw[KYBER_SYMBYTES],
              const uint8_t sid[KYBER_SYMBYTES]);


#define hic_inv KYBER_NAMESPACE(hic_inv)
void hic_inv(uint8_t pk[KYBER_PUBLICKEYBYTES],
             const uint8_t icc[KYBER_PUBLICKEYBYTES],
             const uint8_t pw[KYBER_SYMBYTES],
             const uint8_t sid[KYBER_SYMBYTES]);

#endif
