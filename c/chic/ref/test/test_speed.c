#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "../hic.h"
#include "../pake.h"
#include "kem.h"
#include "randombytes.h"
#include "test/cpucycles.h"
#include "test/speed_print.h"

#define NTESTS 1000

uint64_t t[NTESTS];
uint8_t seed[KYBER_SYMBYTES] = {0};

int main(void)
{
  unsigned int i;
  uint8_t sid[CRYPTO_BYTES];
  uint8_t pw[CRYPTO_BYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t key[CRYPTO_BYTES];
  uint8_t msg1[MSG1_LEN];
  uint8_t msg2[MSG2_LEN];

  randombytes(pw,CRYPTO_BYTES);
 
  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    initStart(msg1,pk,sk,pw,sid);
  }
  print_results("initStart: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
   resp(key,msg2,msg1,pw,sid);
  }
  print_results("resp: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t[i] = cpucycles();
    initEnd(key,msg2,msg1,pk,sk,sid);
  }
  print_results("initEnd: ", t, NTESTS);


  return 0;
}
