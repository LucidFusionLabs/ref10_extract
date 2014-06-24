#include <stdio.h>
#include <string.h>
#include "sha512.h"
#include "curve_sigs.h"

/* Const-time comparison from SUPERCOP, but here it's only used for 
   signature verification, so doesn't need to be const-time */
int crypto_verify_32_ref(const unsigned char *b1, const unsigned char *b2)
{
  return memcmp(b1, b2, 32);
}

int main(int argc, char* argv[])
{
  unsigned char privkey[32];
  unsigned char pubkey[32];
  unsigned char signature[64];
  unsigned char msg[100];
  unsigned long long msg_len = 100;

  /* Initialize pubkey, privkey, msg */
  memset(msg, 0, 100);
  memset(privkey, 0, 32);
  memset(pubkey, 0, 32);
  privkey[0] &= 248;
  privkey[31] &= 63;
  privkey[31] |= 64;

  privkey[8] = 189; /* just so there's some bits set */

  curve25519_keygen(pubkey, privkey);

  curve25519_sign(privkey, signature, msg, msg_len);

  if (curve25519_verify(pubkey, signature, msg, msg_len) == 0)
    printf("success #1\n");
  else
    printf("failure #1\n");

  signature[0] ^= 1;

  if (curve25519_verify(pubkey, signature, msg, msg_len) == 0)
    printf("failure #2\n");
  else
    printf("success #2\n");


  return 1;
}
