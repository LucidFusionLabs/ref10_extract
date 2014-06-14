#include <stdio.h>
#include <string.h>
#include "crypto_sign.h"

void randombytes(unsigned char *junk, unsigned long long junk2)
{
}

int crypto_verify_32_ref(const unsigned char *b1, const unsigned char *b2)
{
  return memcmp(b1, b2, 32);
}

int crypto_hash_sha512_ref(unsigned char *junk ,const unsigned char *junk2,
                           unsigned long long junk3)
{
  return 0;
}


int main(int argc, char* argv[])
{
  unsigned char sig[64];
  unsigned long long siglen = 64;
  unsigned char pubkey[32];
  unsigned char secretkey[64];
  unsigned char msg[100];
  unsigned long long msglen = 100;

  /* generate keypair */
  crypto_sign_keypair(pubkey, secretkey);

  /* sign */
  crypto_sign(sig, &siglen, msg, msglen, secretkey);

  /* verify */
  int result = crypto_sign_open(msg, &msglen, sig, siglen, pubkey);
  if (result == 0)
    printf("success\n");
  else
    printf("failure\n");
 
  return 0;
}
