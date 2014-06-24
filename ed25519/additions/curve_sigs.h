
#ifndef __CURVE_SIGS_H__
#define __CURVE_SIGS_H__

void curve25519_sign(unsigned char* curve25519_privkey,
                     unsigned char* signature,
                     unsigned char* msg, unsigned long msg_len);

int curve25519_verify(unsigned char* curve25519_pubkey,
                      unsigned char* signature,
                      unsigned char* msg, unsigned long msg_len);

/* helper function - modified version of crypto_sign() to use 
   explicit private key */
int crypto_sign_modified(
  unsigned char *sm,unsigned long long *smlen,
  const unsigned char *m,unsigned long long mlen,
  const unsigned char *sk
  );

#endif
