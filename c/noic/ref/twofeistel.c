#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "twofeistel.h"
#include "polyvec.h"
#include "symmetric.h"

#include <inttypes.h>
#include <stdio.h>


/*************************************************
* Name:        twofeistel_eval
*
* Description: Computes the "half-ideal cipher" over a Kyber pk
*
* Arguments:   - uint8_t *icc: pointer to output ciphertext
*                             (of length KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *pk: pointer to input public key
*                             (of length KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *pw: pointer to input password
*                             (of length KYBER_SYMBYTES bytes)
*              - uint8_t *sid: pointer to input sid
*                             (of length KYBER_SYMBYTES bytes)
*              - uint8_t *sid: pointer to random nonce
*                             (of length KYBER_SYMBYTES bytes)
**************************************************/
void hic_eval(uint8_t icc[KYBER_PUBLICKEYBYTES],
              const uint8_t pk[KYBER_PUBLICKEYBYTES],
              const uint8_t pw[KYBER_SYMBYTES],
              const uint8_t sid[KYBER_SYMBYTES],
              const uint8_t nonce[KYBER_SYMBYTES])
{
  uint8_t hash_in_lr[3*KYBER_SYMBYTES];
  uint8_t hash_in_rl[2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES];
  uint8_t in_rho[KYBER_SYMBYTES];
  uint8_t key[KYBER_SYMBYTES];
  uint8_t mask_seed_t[KYBER_SYMBYTES];
  polyvec in_t, mask_t;

  //unpack seed part of pk
  memcpy(in_rho,pk+KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES,KYBER_SYMBYTES);

  // H(pw || rho) -> mask_seed_t
  uint8_t *hin_lr_pw = hash_in_lr;
  uint8_t *hin_lr_sid = hash_in_lr+KYBER_SYMBYTES;
  uint8_t *hin_lr_seed = hash_in_lr+2*KYBER_SYMBYTES;
  memcpy(hin_lr_pw,pw,KYBER_SYMBYTES);
  memcpy(hin_lr_sid,sid,KYBER_SYMBYTES);
  memcpy(hin_lr_seed,in_rho,KYBER_SYMBYTES);
  hash_h(mask_seed_t,hash_in_lr,3*KYBER_SYMBYTES);

  //unpack vec part of pk
  polyvec_frombytes(&in_t, pk);

  // H'(mask_seed_t) -> mask_t
  gen_vector(&mask_t,mask_seed_t); 
  polyvec_add(&mask_t,&mask_t,&in_t);
  polyvec_reduce(&mask_t);

  //pack vec part of masked pk for hashing
  polyvec_tobytes(icc, &mask_t);

  // G(pw,vecpartpk) -> key
  uint8_t *hin_rl_pw = hash_in_rl;
  uint8_t *hin_rl_sid = hash_in_rl+KYBER_SYMBYTES;
  uint8_t *hin_rl_pk = hash_in_rl+2*KYBER_SYMBYTES;
  memcpy(hin_rl_pw,pw,KYBER_SYMBYTES);
  memcpy(hin_rl_sid,sid,KYBER_SYMBYTES);
  memcpy(hin_rl_pk,icc,KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES);
  hash_h(key,hash_in_rl,2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES);

  ic256_enc(in_rho,key);

  // pack second part of pk
  memcpy(icc+KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES,in_rho,KYBER_SYMBYTES);

}

/*************************************************
* Name:        hic_inv
*
* Description: Computes the half-ideal cipher over a Kyber pk
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *icc: pointer to inputciphertext
*                             (of length KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *pw: pointer to input password
*                             (of length KYBER_SYMBYTES bytes)
*              - uint8_t *sid: pointer to input sid
*                             (of length KYBER_SYMBYTES bytes)
**************************************************/
void hic_inv(uint8_t pk[KYBER_PUBLICKEYBYTES],
             const uint8_t icc[KYBER_PUBLICKEYBYTES],
              const uint8_t pw[KYBER_SYMBYTES],
              const uint8_t sid[KYBER_SYMBYTES])
{
  uint8_t hash_in_lr[3*KYBER_SYMBYTES];
  uint8_t hash_in_rl[2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES];
  uint8_t in_rho[KYBER_SYMBYTES];
  uint8_t key[KYBER_SYMBYTES];
  uint8_t mask_seed_t[KYBER_SYMBYTES];
  polyvec in_t, mask_t;

  // G(pw,vecpartpk) -> key
  uint8_t *hin_rl_pw = hash_in_rl;
  uint8_t *hin_rl_sid = hash_in_rl+KYBER_SYMBYTES;
  uint8_t *hin_rl_pk = hash_in_rl+2*KYBER_SYMBYTES;

  memcpy(hin_rl_pw,pw,KYBER_SYMBYTES);
  memcpy(hin_rl_sid,sid,KYBER_SYMBYTES);
  memcpy(hin_rl_pk,icc,KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES);
  hash_h(key,hash_in_rl,2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES);

  // unpack and decrypt seed part of icc
  memcpy(in_rho,icc+KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES,KYBER_SYMBYTES);
  ic256_dec(in_rho,key);

  // H(pw || rho) -> mask_seed_t
  uint8_t *hin_lr_pw = hash_in_lr;
  uint8_t *hin_lr_sid = hash_in_lr+KYBER_SYMBYTES;
  uint8_t *hin_lr_seed = hash_in_lr+2*KYBER_SYMBYTES;
  memcpy(hin_lr_pw,pw,KYBER_SYMBYTES);
  memcpy(hin_lr_sid,sid,KYBER_SYMBYTES);
  memcpy(hin_lr_seed,in_rho,KYBER_SYMBYTES);

  hash_h(mask_seed_t,hash_in_lr,3*KYBER_SYMBYTES);

  //unpack vec part of pk
  polyvec_frombytes(&in_t, icc);


  // H'(mask_seed_t) -> mask_t
  gen_vector(&mask_t,mask_seed_t); 
  polyvec_sub(&mask_t,&in_t,&mask_t);
  polyvec_reduce(&mask_t);

  //pack_pk
  polyvec_tobytes(pk, &mask_t);
  memcpy(pk+KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES,in_rho,KYBER_SYMBYTES);


}
