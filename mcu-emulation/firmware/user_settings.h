#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H
/* Bare-metal wolfCrypt configuration for an ARM Cortex-M4F target.
   Portable C implementations only (no assembly), so that all schemes
   run on the same footing. */
#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_DEV_RANDOM
#define NO_ASN_TIME
#define NO_ERROR_STRINGS
#define WOLFSSL_NO_SOCK
#define WOLFSSL_USER_IO
#define NO_STDIO_FILESYSTEM
#define WOLFSSL_IGNORE_FILE_WARN
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SIZEOF_LONG_LONG 8
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* math */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define SP_WORD_SIZE 32
#define WOLFSSL_SP_NO_DYN_STACK

/* algorithms */
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define WOLFSSL_AES_256
#define WOLFSSL_AES_128
#define HAVE_AES_CBC
#define HAVE_HKDF
#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_SHA512
#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ECC
#define ECC_USER_CURVES
#define HAVE_ECC256
#define ECC_SHAMIR
#define WC_RSA_PSS
#define WOLFSSL_KEY_GEN
#define NO_DSA
#define NO_DH
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_OLD_TLS
#define NO_RC4
#define NO_DES3
#define NO_PSK
#define NO_PWDBASED
#define NO_SESSION_CACHE
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256

/* random: hardware TRNG stand-in */
extern int fw_rng_block(unsigned char* out, unsigned int sz);
#define CUSTOM_RAND_GENERATE_BLOCK fw_rng_block
#define CUSTOM_RAND_TYPE unsigned int

/* memory: XMALLOC/XFREE/XREALLOC are provided by the firmware (fwlib.c) */
#define XMALLOC_USER
#endif
