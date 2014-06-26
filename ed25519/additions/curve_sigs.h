
#ifndef __CURVE_SIGS_H__
#define __CURVE_SIGS_H__

void curve25519_keygen(unsigned char* curve25519_pubkey_out,
                       const unsigned char* curve25519_privkey_in);

void curve25519_sign(unsigned char* signature_out,
                     const unsigned char* curve25519_privkey,
                     const unsigned char* msg, const unsigned long msg_len);

/* returns 0 on success */
int curve25519_verify(const unsigned char* signature,
                      const unsigned char* curve25519_pubkey,                      
                      const unsigned char* msg, const unsigned long msg_len);

/* helper function - modified version of crypto_sign() to use 
   explicit private key */
int crypto_sign_modified(
  unsigned char *sm,unsigned long long *smlen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *sk, /* Curve/Ed25519 private key */
  const unsigned char* pk  /* Ed25519 public key */
  );

#endif
