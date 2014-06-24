#include <stdio.h>
#include <string.h>
#include "curve_sigs.h"

/* Const-time comparison from SUPERCOP, but here it's only used for 
   signature verification, so doesn't need to be const-time */
int crypto_verify_32_ref(const unsigned char *b1, const unsigned char *b2)
{
  return memcmp(b1, b2, 32);
}

int crypto_hash_sha512_ref(unsigned char *output ,const unsigned char *input,
                           unsigned long long len)
{
  memset(output, 0, 64);
  return 0;
}

int main(int argc, char* argv[])
{
  unsigned char privkey[32];
  unsigned char pubkey[32];
  unsigned char signature[64];
  unsigned char msg[100];
  unsigned long long msg_len = 100;

  curve25519_sign(privkey, signature, msg, msg_len);

  if (curve25519_verify(privkey, signature, msg, msg_len) == 0)
    printf("success\n");
  else
    printf("failure\n");

  return 1;
}
