#ifndef PAKE_H
#define PAKE_H

#include <stdint.h>
#include "params.h"
#include "polyvec.h"

#define MSG1_LEN KYBER_PUBLICKEYBYTES
#define MGS2_LEN KYBER_SYMBYTES+KYBER_CIPHERTEXTBYTES

void initStart(uint8_t msg1[MSG1_LEN], // stupd and out
               uint8_t pk[KYBER_PUBLICKEYBYTES],   // stupd
               uint8_t sk[KYBER_SECRETKEYBYTES],   // stupd
               const uint8_t pw[KYBER_SYMBYTES],   // in
               const uint8_t sid[KYBER_SYMBYTES]); // stin

int initEnd(uint8_t key[KYBER_SYMBYTES],              // out + return 0 iff OK 
            const uint8_t msg2[MGS2_LEN],             // in
            const uint8_t msg1[MSG1_LEN],             // stin
            const uint8_t pk[KYBER_PUBLICKEYBYTES],   // stin
            const uint8_t sk[KYBER_SECRETKEYBYTES],   // stin
            const uint8_t sid[KYBER_SYMBYTES]);       // stin

void resp(uint8_t key[KYBER_SYMBYTES],                // out
          uint8_t msg2[MGS2_LEN],                     // out
            const uint8_t msg1[KYBER_PUBLICKEYBYTES], // in
            const uint8_t pw[KYBER_SYMBYTES],         // in
            const uint8_t sid[KYBER_SYMBYTES]);       // stin

#endif
