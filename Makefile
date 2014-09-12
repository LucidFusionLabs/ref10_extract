
curve:
	gcc curve25519/*.c -Icurve25519/nacl_includes -o curve

ed:
	gcc -O3 ed25519/*.c ed25519/main/main.c ed25519/additions/*.c ed25519/nacl_sha512/*.c \
  -Ied25519/nacl_includes -Ied25519/additions -Ied25519 -o ed
