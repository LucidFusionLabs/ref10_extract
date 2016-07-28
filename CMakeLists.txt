add_library(libcurve25519 STATIC curve25519/fe_copy.c
            curve25519/fe_mul.c curve25519/fe_tobytes.c 
            curve25519/fe_0.c curve25519/fe_cswap.c
            curve25519/fe_mul121666.c curve25519/scalarmult.c
            curve25519/fe_1.c curve25519/fe_frombytes.c
            curve25519/fe_sq.c curve25519/fe_add.c
            curve25519/fe_invert.c curve25519/fe_sub.c)
target_include_directories(libcurve25519 PRIVATE
                           ${CMAKE_CURRENT_SOURCE_DIR}/curve25519
                           ${CMAKE_CURRENT_SOURCE_DIR}/curve25519/nacl_includes)

add_library(libed25519 STATIC
            ed25519/fe_0.c ed25519/fe_sq2.c ed25519/ge_p3_dbl.c
            ed25519/fe_1.c ed25519/fe_sub.c ed25519/ge_p3_to_cached.c
            ed25519/fe_add.c ed25519/fe_tobytes.c ed25519/ge_p3_to_p2.c
            ed25519/fe_cmov.c ed25519/ge_add.c ed25519/ge_p3_tobytes.c
            ed25519/fe_copy.c ed25519/ge_double_scalarmult.c ed25519/ge_precomp_0.c
            ed25519/fe_frombytes.c ed25519/ge_frombytes.c ed25519/ge_scalarmult_base.c
            ed25519/fe_invert.c ed25519/ge_madd.c ed25519/ge_sub.c
            ed25519/fe_isnegative.c ed25519/ge_msub.c ed25519/ge_tobytes.c
            ed25519/fe_isnonzero.c ed25519/ge_p1p1_to_p2.c ed25519/open.c
            ed25519/fe_mul.c ed25519/ge_p1p1_to_p3.c ed25519/sc_muladd.c
            ed25519/fe_neg.c ed25519/ge_p2_0.c ed25519/sc_reduce.c
            ed25519/fe_pow22523.c ed25519/ge_p2_dbl.c ed25519/sign.c
            ed25519/fe_sq.c ed25519/ge_p3_0.c
            ed25519/additions/compare.c ed25519/additions/sign_modified.c ed25519/nacl_sha512/blocks.c
            ed25519/additions/curve_sigs.c ed25519/additions/zeroize.c ed25519/nacl_sha512/hash.c)
target_include_directories(libed25519 PRIVATE
                           ${CMAKE_CURRENT_SOURCE_DIR}/ed25519
                           ${CMAKE_CURRENT_SOURCE_DIR}/ed25519/additions
                           ${CMAKE_CURRENT_SOURCE_DIR}/ed25519/nacl_includes)
