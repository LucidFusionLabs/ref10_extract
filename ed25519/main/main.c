#include <stdio.h>
#include <string.h>
#include "sha512.h"
#include "curve_sigs.h"

int main(int argc, char* argv[])
{
  unsigned char privkey[32];
  unsigned char pubkey[32];
  unsigned char signature[64];
  unsigned char msg[100];
  unsigned long long msg_len = 100;
  unsigned char random[64];

  /* Initialize pubkey, privkey, msg */
  memset(msg, 0, 100);
  memset(privkey, 0, 32);
  memset(pubkey, 0, 32);
  privkey[0] &= 248;
  privkey[31] &= 63;
  privkey[31] |= 64;

  privkey[8] = 189; /* just so there's some bits set */

  curve25519_keygen(pubkey, privkey);

  curve25519_sign(signature, privkey, msg, msg_len, random);

  if (curve25519_verify(signature, pubkey, msg, msg_len) == 0)
    printf("success #1\n");
  else
    printf("failure #1\n");

  signature[0] ^= 1;

  if (curve25519_verify(signature, pubkey, msg, msg_len) == 0)
    printf("failure #2\n");
  else
    printf("success #2\n");


  printf("Random testing...\n");
  for (int count = 0; count < 10000; count++) {
    unsigned char b[64];
    crypto_hash_sha512_ref(b, privkey, 32);
    memmove(privkey, b, 32);
    crypto_hash_sha512_ref(b, privkey, 32);
    memmove(random, b, 64);

    privkey[0] &= 248;
    privkey[31] &= 63;
    privkey[31] |= 64;

    curve25519_keygen(pubkey, privkey);

    curve25519_sign(signature, privkey, msg, msg_len, random);

    if (curve25519_verify(signature, pubkey, msg, msg_len) != 0) {
      printf("failure #1 %d\n", count);
      return -1;
    }

    if (b[63] & 1)
      signature[count % 64] ^= 1;
    else
      msg[count % 100] ^= 1;
    if (curve25519_verify(signature, pubkey, msg, msg_len) == 0) {
      printf("failure #2 %d\n", count);
      return -1;
    }
  }
  printf("OK\n");
  return 1;
}
