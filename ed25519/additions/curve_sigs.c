#include <string.h>
#include "ge.h"
#include "curve_sigs.h"
#include "crypto_sign.h"

void curve25519_sign(unsigned char* curve25519_privkey,
                     unsigned char* signature,
                     unsigned char* msg, unsigned long msg_len)
{
  ge_p3 ed_pubkey_point; /* Ed25519 pubkey point */
  unsigned char ed_keypair[64]; /* privkey followed by pubkey */
  unsigned char sigbuf[msg_len + 64]; /* working buffer */
  unsigned long long sigbuf_out_len = 0;
  unsigned char sign_bit = 0;

  /* Convert the Curve25519 privkey to an Ed25519 keypair */
  memmove(ed_keypair, curve25519_privkey, 32);
  ge_scalarmult_base(&ed_pubkey_point, curve25519_privkey);
  ge_p3_tobytes(ed_keypair + 32, &ed_pubkey_point);
  sign_bit = ed_keypair[63] & 0x80;

  /* Perform an Ed25519 signature with explicit private key */
  crypto_sign_modified(sigbuf, &sigbuf_out_len, msg, msg_len, ed_keypair);
  memmove(signature, sigbuf, 64);

  /* Encode the sign bit into signature (in unused high bit of S) */
   signature[63] |= sign_bit;
}

int curve25519_verify(unsigned char* curve25519_pubkey,
                      unsigned char* signature,
                      unsigned char* msg, unsigned long msg_len)
{
  fe mont_x, mont_x_minus_1, mont_x_plus_1, inv_mont_x_plus_1;
  fe one;
  fe ed_y;
  unsigned char ed_pubkey[32];
  unsigned long long mlen;

  /* Convert the Curve25519 public key into an Ed25519 public key.  In
     particular, convert Curve25519's "montgomery" x-coordinate into an
     Ed25519 "edwards" y-coordinate:

     ed_y = (mont_x - 1) / (mont_x + 1)

     Then move the sign bit into the pubkey from the signature.
  */
  fe_frombytes(mont_x, curve25519_pubkey);
  fe_1(one);
  fe_sub(mont_x_minus_1, mont_x, one);
  fe_add(mont_x_plus_1, mont_x, one);
  fe_invert(inv_mont_x_plus_1, mont_x_plus_1);
  fe_mul(ed_y, mont_x_plus_1, inv_mont_x_plus_1);
  fe_tobytes(ed_pubkey, ed_y);

  /* Copy the sign bit, and remove it from signature */
  ed_pubkey[31] |= (signature[63] & 0x80);
  signature[63] &= 0x7F;

  /* Then perform a normal Ed25519 verification, return 0 on success */
  mlen = msg_len; /* For some reason this is an output param */
  return crypto_sign_open(msg, &mlen, signature, 64, ed_pubkey);
}
