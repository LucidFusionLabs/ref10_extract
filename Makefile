
curve:
	gcc curve25519/*.c -Icurve25519/nacl_includes -o curve

ed:
	gcc ed25519/*.c ed25519/main/main.c -Ied25519/nacl_includes -o ed
