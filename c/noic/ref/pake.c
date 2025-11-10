#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "params.h"
#include "twofeistel.h"
#include "kem.h"
#include "pake.h"
#include "symmetric.h"
#include "verify.h"
#include "randombytes.h"

#include<stdio.h>

/*************************************************
* Name:        initStart
*
* Description: First stage of initiator
*
* Results:     uint8_t *msg1: the outgoing message
*                 (of length MSG1_LEN)
*              uint8_t *pk: the pk part of the state
*                 (of length KYBER_PUBLICKEYBYTES)
*              uint8_t *sk: the sk part of the state
*                 (of length KYBER_SECRETKEYBYTES)
* 
* Arguments:   uint8_t *pw: pointer to the input pw
*                 (of length KYBER_SYMBYTES)
*              uint8_t *sid: pointer to the input sid
*                 (of length KYBER_SYMBYTES)
* 
**************************************************/
void initStart(uint8_t msg1[MSG1_LEN], 
               uint8_t pk[KYBER_PUBLICKEYBYTES],   
               uint8_t sk[KYBER_SECRETKEYBYTES],   
               const uint8_t pw[KYBER_SYMBYTES],   
               const uint8_t sid[KYBER_SYMBYTES])  
{
  uint8_t nonce[KYBER_SYMBYTES];
  crypto_kem_keypair(pk,sk);
  randombytes(nonce,KYBER_SYMBYTES);
  twofeistel_eval(msg1,pk,pw,sid, nonce);  
}

/*************************************************
* Name:        initEnd
*
* Description: Last stage of initiator
*
* Results:   uint8_t *key: pointer to the output key
*                 (of length KYBER_SYMBYTES)
*            return value: 0 if ok, -1 of not ok
* 
* Arguments: uint8_t *msg2: the input message
*                 (of length MSG2_LEN)
*            uint8_t *msg1: the previously sent message
*                 (of length MSG1_LEN)
* *            uint8_t *pk: the pk part of the state
*                 (of length KYBER_PUBLICKEYBYTES)
*            uint8_t *sk: the sk part of the state
*                 (of length KYBER_SECRETKEYBYTES)
*            uint8_t *sid: pointer to the input sid
*                 (of length KYBER_SYMBYTES)
* 
**************************************************/
int initEnd(uint8_t key[KYBER_SYMBYTES],              
            const uint8_t msg2[MGS2_LEN],             
            const uint8_t msg1[MSG1_LEN],             
            const uint8_t pk[KYBER_PUBLICKEYBYTES],   
            const uint8_t sk[KYBER_SECRETKEYBYTES],   
            const uint8_t sid[KYBER_SYMBYTES])       
{
  int result;
  uint8_t keytag[2*KYBER_SYMBYTES];
  uint8_t hashin[2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES+KYBER_CIPHERTEXTBYTES];

  crypto_kem_dec(hashin,msg2+KYBER_SYMBYTES,sk);

  // Tag = H(K_s,sid,pk,apk,cph)
  memcpy(hashin+KYBER_SYMBYTES,sid,KYBER_SYMBYTES);
  memcpy(hashin+2*KYBER_SYMBYTES,pk,KYBER_PUBLICKEYBYTES);
  memcpy(hashin+2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES,msg1,KYBER_PUBLICKEYBYTES);
  memcpy(hashin+2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES,msg2+KYBER_SYMBYTES,KYBER_CIPHERTEXTBYTES);
  hash_g(keytag,hashin,2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES+KYBER_CIPHERTEXTBYTES);

  // Check tag
  result = verify(keytag+KYBER_SYMBYTES,msg2,KYBER_SYMBYTES);

  // If all works out
  cmov(key,keytag,KYBER_SYMBYTES,((uint8_t)result&0x1)^0x1);
  return result;
}

/*************************************************
* Name:        resp
*
* Description: First message from initiator
*
* Results:   uint8_t *key: the output key
*                 (of length KYBER_SYMBYTES)
*            uint8_t *msg2: the output message
*                 (of length KYBER_SYMBYTES + KYBER_CIPHERTEXTBYTES)
* 
* Arguments: uint8_t *msg1: the input message
*                 (of length KYBER_PUBLICKEYBYTES)
*            uint8_t *pw: the pw
*                 (of length KYBER_SYMBYTES)
*            uint8_t *sid: pointer to the input sid
*                 (of length KYBER_SYMBYTES)
* 
**************************************************/
void resp(uint8_t key[KYBER_SYMBYTES],                
          uint8_t msg2[MGS2_LEN],                     
            const uint8_t msg1[KYBER_PUBLICKEYBYTES], 
            const uint8_t pw[KYBER_SYMBYTES],         
            const uint8_t sid[KYBER_SYMBYTES])      
{
  uint8_t pk[KYBER_PUBLICKEYBYTES];
  uint8_t keytag[2*KYBER_SYMBYTES];
  uint8_t hashin[2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES+KYBER_CIPHERTEXTBYTES];

  twofeistel_inv(pk,msg1,pw,sid);
  crypto_kem_enc(msg2+KYBER_SYMBYTES,hashin,pk);

  // Tag = H(K_s,sid,pk,apk,cph)
  memcpy(hashin+KYBER_SYMBYTES,sid,KYBER_SYMBYTES);
  memcpy(hashin+2*KYBER_SYMBYTES,pk,KYBER_PUBLICKEYBYTES);
  memcpy(hashin+2*KYBER_SYMBYTES+KYBER_PUBLICKEYBYTES,msg1,KYBER_PUBLICKEYBYTES);
  memcpy(hashin+2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES,msg2+KYBER_SYMBYTES,KYBER_CIPHERTEXTBYTES);
  hash_g(keytag,hashin,2*KYBER_SYMBYTES+2*KYBER_PUBLICKEYBYTES+KYBER_CIPHERTEXTBYTES);
  memcpy(key,keytag,KYBER_SYMBYTES);
  memcpy(msg2,keytag+KYBER_SYMBYTES,KYBER_SYMBYTES);

}


