#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../hic.h"
#include "../pake.h"
#include "kem.h"
#include "randombytes.h"

#define NTESTS 1000

static int test_hic(void);
static int test_pake(void);


static int test_hic(void)
{
  uint8_t sid[CRYPTO_BYTES];
  uint8_t pw[CRYPTO_BYTES];
  uint8_t sk_a[CRYPTO_SECRETKEYBYTES];
  uint8_t pk_a[CRYPTO_PUBLICKEYBYTES];
  uint8_t pk_b[CRYPTO_PUBLICKEYBYTES];
  uint8_t icc[CRYPTO_PUBLICKEYBYTES];

  randombytes(pw,CRYPTO_BYTES);
  randombytes(sid,CRYPTO_BYTES);
 
  crypto_kem_keypair(pk_a, sk_a);

  hic_eval(icc, pk_a, pw,sid);
  hic_inv(pk_b, icc, pw,sid);

  if(memcmp(pk_a, pk_b, CRYPTO_PUBLICKEYBYTES)) {
    printf("ERROR hic\n");
    return 1;
  }

  return 0;
}

static int test_pake(void)
{
  uint8_t sid[CRYPTO_BYTES];
  uint8_t pw[CRYPTO_BYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];
  uint8_t msg1[CRYPTO_PUBLICKEYBYTES];
  uint8_t msg2[CRYPTO_BYTES+CRYPTO_CIPHERTEXTBYTES];

  randombytes(pw,CRYPTO_BYTES);
 
  initStart(msg1,pk,sk,pw,sid);
  resp(key_a,msg2,msg1,pw,sid);
  initEnd(key_b,msg2,msg1,pk,sk,sid);

  if(memcmp(key_a, key_b, CRYPTO_BYTES)) {
    printf("ERROR pake\n");
    return 1;
  }

  return 0;
}
int main(void)
{
  unsigned int i;
  int r;

  for(i=0;i<NTESTS;i++) {
    r  = test_hic();
    r  |= test_pake();
    if(r)
      return 1;
  }

  printf("CRYPTO_SECRETKEYBYTES:  %d\n",CRYPTO_SECRETKEYBYTES);
  printf("CRYPTO_PUBLICKEYBYTES:  %d\n",CRYPTO_PUBLICKEYBYTES);
  printf("CRYPTO_CIPHERTEXTBYTES: %d\n",CRYPTO_CIPHERTEXTBYTES);

  return 0;
}
