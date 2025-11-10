#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "twofeistel.h"
#include "polyvec.h"
#include "symmetric.h"
#include "rej_uniform.h"

#include <inttypes.h>
#include <stdio.h>


static void arrayxor(uint8_t *out, const uint8_t *in, const uint8_t *mask, size_t len)
{
  for(size_t i=0;i<len/8;i++)
    ((uint64_t*)out)[i]=((uint64_t*)in)[i]^((uint64_t*)mask)[i];
  if(len%8!=0)
  {
    out=out+len/8;
    in=in+len/8;
    mask=mask+len/8;
    for(size_t i=0;i<len%8;i++)
      out[i]=in[i]^mask[i];
  }
}

/*************************************************
* Name:        twofeistel_eval
*
* Description: Computes the "Two-Feistel construction" over a Kyber pk
*
* Arguments:   - uint8_t *twofc: pointer to output ciphertext
*                             (of length KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *pk: pointer to input public key
*                             (of length KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *pw: pointer to input password
*                             (of length KYBER_SYMBYTES bytes)
*              - uint8_t *sid: pointer to input sid
*                             (of length KYBER_SYMBYTES bytes)
*              - uint8_t *nonce: pointer to random nonce
*                             (of length KYBER_SYMBYTES bytes)
**************************************************/


void twofeistel_eval(uint8_t twofc[KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES],
              const uint8_t pk[KYBER_PUBLICKEYBYTES],
              const uint8_t pw[KYBER_SYMBYTES],
              const uint8_t sid[KYBER_SYMBYTES],
              const uint8_t nonce[KYBER_SYMBYTES])
{
  uint8_t hash_in_lr[3*KYBER_SYMBYTES];
  uint8_t hash_in_rl[2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES];
  uint8_t mask_pk[2*KYBER_SYMBYTES];
  uint8_t mask_nonce[KYBER_SYMBYTES];
  polyvec in_t, mask_t;

  uint8_t* twofc_nonce = twofc;
  uint8_t* twofc_t = twofc+KYBER_SYMBYTES;
  uint8_t* twofc_rho = twofc + KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES - KYBER_SYMBYTES;
  const uint8_t* pk_t = pk;
  const uint8_t* pk_rho = pk + KYBER_PUBLICKEYBYTES-KYBER_SYMBYTES;
  uint8_t* mask_pk_t = mask_pk;
  uint8_t* mask_pk_rho = mask_pk+KYBER_SYMBYTES;

  // G(pw || nonce) -> mask_pk (seed for rej, mask for rho)
  uint8_t *hin_lr_pw = hash_in_lr;
  uint8_t *hin_lr_sid = hash_in_lr+KYBER_SYMBYTES;
  uint8_t *hin_lr_nonce = hash_in_lr+2*KYBER_SYMBYTES;
  memcpy(hin_lr_pw,pw,KYBER_SYMBYTES);
  memcpy(hin_lr_sid,sid,KYBER_SYMBYTES);
  memcpy(hin_lr_nonce,nonce,KYBER_SYMBYTES);
  hash_g(mask_pk,hash_in_lr,3*KYBER_SYMBYTES);

  //unpack vec part of pk
  polyvec_frombytes(&in_t, pk_t);

  // H'(mask_seed_t) -> mask_t
  gen_vector(&mask_t,mask_pk_t); 
  polyvec_add(&mask_t,&mask_t,&in_t);
  polyvec_reduce(&mask_t);

  //pack vec part of masked pk for hashing
  polyvec_tobytes(twofc_t, &mask_t);

  //mask rho part of pk
  arrayxor(twofc_rho,pk_rho,mask_pk_rho,KYBER_SYMBYTES);

  // G(pw,vecpartpk) -> mask_nonce
  uint8_t *hin_rl_pw = hash_in_rl;
  uint8_t *hin_rl_sid = hash_in_rl+KYBER_SYMBYTES;
  uint8_t *hin_rl_pk = hash_in_rl+2*KYBER_SYMBYTES;
  memcpy(hin_rl_pw,pw,KYBER_SYMBYTES);
  memcpy(hin_rl_sid,sid,KYBER_SYMBYTES);
  memcpy(hin_rl_pk,twofc_t,KYBER_PUBLICKEYBYTES);
  hash_h(mask_nonce,hash_in_rl,2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES);

  arrayxor(twofc_nonce,nonce,mask_nonce, KYBER_SYMBYTES);

}

/*************************************************
* Name:        twofeistel_inv
*
* Description: Inverts the "Two-Feistel construction" over a Kyber pk
*
* Arguments:   - uint8_t *pk: pointer to output public key
*                             (of length KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *twofc: pointer to inputciphertext
*                             (of length KYBER_PUBLICKEYBYTES bytes)
*              - uint8_t *pw: pointer to input password
*                             (of length KYBER_SYMBYTES bytes)
*              - uint8_t *sid: pointer to input sid
*                             (of length KYBER_SYMBYTES bytes)
**************************************************/
void twofeistel_inv(uint8_t pk[KYBER_PUBLICKEYBYTES],
             const uint8_t twofc[KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES],
              const uint8_t pw[KYBER_SYMBYTES],
              const uint8_t sid[KYBER_SYMBYTES])
{
  uint8_t hash_in_lr[3*KYBER_SYMBYTES];
  uint8_t hash_in_rl[2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES];
  uint8_t mask_pk[2*KYBER_SYMBYTES];
  uint8_t mask_nonce[KYBER_SYMBYTES];
  uint8_t nonce[KYBER_SYMBYTES];
  polyvec in_t, mask_t;

  const uint8_t* twofc_nonce = twofc;
  const uint8_t* twofc_t = twofc+KYBER_SYMBYTES;
  const uint8_t* twofc_rho = twofc + KYBER_SYMBYTES + KYBER_PUBLICKEYBYTES - KYBER_SYMBYTES;
  uint8_t* pk_t = pk;
  uint8_t* pk_rho = pk + KYBER_PUBLICKEYBYTES - KYBER_SYMBYTES;
  uint8_t* mask_pk_t = mask_pk;
  uint8_t* mask_pk_rho = mask_pk + KYBER_SYMBYTES;


  // G(pw,vecpartpk) -> nonce mask
  uint8_t *hin_rl_pw = hash_in_rl;
  uint8_t *hin_rl_sid = hash_in_rl+KYBER_SYMBYTES;
  uint8_t *hin_rl_pk = hash_in_rl+2*KYBER_SYMBYTES;
  memcpy(hin_rl_pw,pw,KYBER_SYMBYTES);
  memcpy(hin_rl_sid,sid,KYBER_SYMBYTES);
  memcpy(hin_rl_pk,twofc_t,KYBER_PUBLICKEYBYTES);
  hash_h(mask_nonce,hash_in_rl,2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES);

  // unmask the nonce
  arrayxor(nonce, twofc_nonce, mask_nonce, KYBER_SYMBYTES);

  // G(pw || rho) -> mask_pk seed for rej, mask for rho
  uint8_t *hin_lr_pw = hash_in_lr;
  uint8_t *hin_lr_sid = hash_in_lr+KYBER_SYMBYTES;
  uint8_t *hin_lr_nonce = hash_in_lr+2*KYBER_SYMBYTES;
  memcpy(hin_lr_pw,pw,KYBER_SYMBYTES);
  memcpy(hin_lr_sid,sid,KYBER_SYMBYTES);
  memcpy(hin_lr_nonce,nonce,KYBER_SYMBYTES);
  hash_g(mask_pk,hash_in_lr,3*KYBER_SYMBYTES);

  //unpack vec part of pk
  polyvec_frombytes(&in_t, twofc_t);

  // H'(mask_seed_t) -> mask_t
  gen_vector(&mask_t,mask_pk_t); 
  polyvec_sub(&mask_t,&in_t,&mask_t);
  polyvec_reduce(&mask_t);

  //pack_pk and unmask rho
  polyvec_tobytes(pk_t, &mask_t);
  arrayxor(pk_rho,twofc_rho,mask_pk_rho, KYBER_SYMBYTES);

}
