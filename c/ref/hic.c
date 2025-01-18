#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include "params.h"
#include "hic.h"
#include "polyvec.h"
#include "symmetric.h"
#include "randombytes.h"

#include <inttypes.h>
#include <stdio.h>

/*************************************************
 * An "ideal cipher" over 256 bits
 * **********************************************/

#include "rijndael256/rijndael.h"
int ic256_enc(uint8_t block[KYBER_SYMBYTES], uint8_t key[KYBER_SYMBYTES]);
int ic256_dec(uint8_t block[KYBER_SYMBYTES], uint8_t key[KYBER_SYMBYTES]);

int ic256_enc(uint8_t block[KYBER_SYMBYTES], uint8_t key[KYBER_SYMBYTES]) {
  roundkey rkk;
  xrijndaelKeySched((xword32 *)key, 256, 256, &rkk);
  xrijndaelEncrypt((xword32 *)block, &rkk);
  return 0;
}

int ic256_dec(uint8_t block[KYBER_SYMBYTES], uint8_t key[KYBER_SYMBYTES]) {
  roundkey rkk;
  xrijndaelKeySched((xword32 *)key, 256, 256, &rkk);
  xrijndaelDecrypt((xword32 *)block, &rkk);
  return 0;
}

/*************************************************
* Name:        rej_uniform
*
* Description: Run rejection sampling on uniform random bytes to generate
*              uniform random integers mod q
*
* Arguments:   - int16_t *r: pointer to output buffer
*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
*              - unsigned int buflen: length of input buffer in bytes
*
* Returns number of sampled 16-bit integers (at most len)
**************************************************/
static unsigned int rej_uniform(int16_t *r,
                                unsigned int len,
                                const uint8_t *buf,
                                unsigned int buflen)
{
  unsigned int ctr, pos;
  uint16_t val0, val1;

  ctr = pos = 0;
  while(ctr < len && pos + 3 <= buflen) {
    val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
    val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
    pos += 3;

    if(val0 < KYBER_Q)
      r[ctr++] = val0;
    if(ctr < len && val1 < KYBER_Q)
      r[ctr++] = val1;
  }

  return ctr;
}

/*************************************************
* Name:        gen_vector
*
* Description: Deterministically generate vector v from a seed. 
*              Entries of the vector are polynomials that look
*              uniformly random. Performs rejection sampling on 
*              output of a XOF
*
* Arguments:   - polyvec *a: pointer to output vector v
*              - const uint8_t *seed: pointer to input seed
**************************************************/
// Fixme: can be smaller?
#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
// Not static for benchmarking
void gen_vector(polyvec *v, const uint8_t seed[KYBER_SYMBYTES])
{
  unsigned int ctr, i, k;
  unsigned int buflen, off;
  uint8_t buf[GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES+2];
  xof_state state;

  for(i=0;i<KYBER_K;i++) {
    xof_absorb(&state, seed, i, 0); // take row 0
    xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
    buflen = GEN_MATRIX_NBLOCKS*XOF_BLOCKBYTES;
    ctr = rej_uniform(v->vec[i].coeffs, KYBER_N, buf, buflen);

    while(ctr < KYBER_N) {
      off = buflen % 3;
      for(k = 0; k < off; k++)
        buf[k] = buf[buflen - off + k];
      xof_squeezeblocks(buf + off, 1, &state);
      buflen = off + XOF_BLOCKBYTES;
      ctr += rej_uniform(v->vec[i].coeffs + ctr, KYBER_N - ctr, buf, buflen);
    }
  }
}

/*
static void print_polyvec(polyvec *v){
  printf("Start polyvec");
  for(int i=0;i < KYBER_K; i++) {
    printf("\n");
    for(int j=0;j < KYBER_N; j++) 
      printf("%" PRIx16 ", ", v->vec[i].coeffs[j]);
  }
  printf("End polyvec\n");

}
*/

/*************************************************
* Name:        hic_eval
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
**************************************************/
void hic_eval(uint8_t icc[KYBER_PUBLICKEYBYTES],
              const uint8_t pk[KYBER_PUBLICKEYBYTES],
              const uint8_t pw[KYBER_SYMBYTES],
              const uint8_t sid[KYBER_SYMBYTES])
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
