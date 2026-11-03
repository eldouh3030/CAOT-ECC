/* Device-side (sender) operations of every compared scheme, built for an
   ARM Cortex-M4F and executed in an instruction-level emulator by the host
   harness (host/run.c). Each op_* / pkt_* function is one measured unit;
   setup() creates long-term keys and is not measured.
   The packet logic mirrors src/schemes.cpp and src/caot2.cpp. */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/chacha.h>
#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <string.h>

extern void fw_heap_set_mark(void);
extern void fw_heap_reset(void);

volatile int g_status;
volatile uint32_t g_len = 64;           /* payload length, set by the host */
static uint8_t g_msg[4096];
static uint8_t g_pkt[4096];
static uint8_t g_ct[4096 + 32];

static WC_RNG rng;
static RsaKey rsa_enc, rsa_sig;         /* receiver encryption key, sender signing key */
static ecc_key ecc_rx, ecc_tx;          /* ECIES receiver key, ECDSA sender key */
static curve25519_key gw_x;             /* gateway X25519 key (CAOT-ECC, Sethi) */
static uint8_t gw_x_pub[32];
static ed25519_key dev_ed;              /* device Ed25519 signing key */
static ed25519_key gw_ed;               /* gateway Ed25519 key (Anwar handshake) */
static uint8_t anwar_meta[56], anwar_meta_sig[64], anwar_gwE[32], anwar_gwE_sig[64];
static uint8_t anwar_sk[32];

/* CAOT-ECC routine-mode device state */
static uint8_t chain_key[32], run_hash[32];
static uint32_t sid = 0x1001, ctr = 0;

#define CHK(x) do { int _r = (x); if (_r != 0) { g_status = _r; return; } } while (0)

static void put_u32(uint8_t* p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }
static void put_u64(uint8_t* p, uint64_t v) { put_u32(p, (uint32_t)(v >> 32)); put_u32(p + 4, (uint32_t)v); }
static uint64_t now_ms(void) { static uint64_t t = 1760000000000ull; return t += 1000; }

static int sha256(const uint8_t* d, uint32_t n, uint8_t out[32]) { return wc_Sha256Hash(d, n, out); }
static int hkdf(const uint8_t* ikm, uint32_t ikmn, const uint8_t* salt, uint32_t saltn,
                const uint8_t* info, uint32_t infon, uint8_t* out, uint32_t outn) {
    return wc_HKDF(WC_SHA256, ikm, ikmn, salt, saltn, info, infon, out, outn);
}
static int gcm_enc(const uint8_t key[32], const uint8_t iv[12], const uint8_t* aad, uint32_t aadn,
                   const uint8_t* m, uint32_t n, uint8_t* out /* n + 16 */) {
    Aes aes; int r;
    if ((r = wc_AesInit(&aes, NULL, INVALID_DEVID)) != 0) return r;
    if ((r = wc_AesGcmSetKey(&aes, key, 32)) != 0) return r;
    r = wc_AesGcmEncrypt(&aes, out, m, n, iv, 12, out + n, 16, aad, aadn);
    wc_AesFree(&aes);
    return r;
}

/* ------------------------------------------------------------------ setup */
void setup(void) {
    g_status = 0;
    for (int i = 0; i < (int)sizeof g_msg; ++i) g_msg[i] = (uint8_t)(i * 7 + 1);
    CHK(wc_InitRng(&rng));
    CHK(wc_InitRsaKey(&rsa_enc, NULL)); CHK(wc_MakeRsaKey(&rsa_enc, 2048, 65537, &rng));
    CHK(wc_InitRsaKey(&rsa_sig, NULL)); CHK(wc_MakeRsaKey(&rsa_sig, 2048, 65537, &rng));
    wc_RsaSetRNG(&rsa_enc, &rng); wc_RsaSetRNG(&rsa_sig, &rng);
    CHK(wc_ecc_init(&ecc_rx)); CHK(wc_ecc_make_key_ex(&rng, 32, &ecc_rx, ECC_SECP256R1));
    CHK(wc_ecc_init(&ecc_tx)); CHK(wc_ecc_make_key_ex(&rng, 32, &ecc_tx, ECC_SECP256R1));
    CHK(wc_curve25519_init(&gw_x)); CHK(wc_curve25519_make_key(&rng, 32, &gw_x));
    { word32 l = 32; CHK(wc_curve25519_export_public(&gw_x, gw_x_pub, &l)); }
    CHK(wc_ed25519_init(&dev_ed)); CHK(wc_ed25519_make_key(&rng, 32, &dev_ed));
    CHK(wc_ed25519_init(&gw_ed));  CHK(wc_ed25519_make_key(&rng, 32, &gw_ed));
    /* gateway side of the Anwar handshake (computed by the gateway, verified by the device) */
    {
        word32 l = 64; uint8_t pk[32]; word32 pl = 32;
        put_u64(anwar_meta, now_ms()); wc_RNG_GenerateBlock(&rng, anwar_meta + 8, 16);
        CHK(wc_ed25519_export_public(&gw_ed, pk, &pl)); memcpy(anwar_meta + 24, pk, 32);
        CHK(wc_ed25519_sign_msg(anwar_meta, 56, anwar_meta_sig, &l, &gw_ed));
        curve25519_key e; CHK(wc_curve25519_init(&e)); CHK(wc_curve25519_make_key(&rng, 32, &e));
        pl = 32; CHK(wc_curve25519_export_public(&e, anwar_gwE, &pl));
        l = 64; CHK(wc_ed25519_sign_msg(anwar_gwE, 32, anwar_gwE_sig, &l, &gw_ed));
        wc_RNG_GenerateBlock(&rng, anwar_sk, 32);
    }
    fw_heap_set_mark();
}
void heap_reset(void) { fw_heap_reset(); }

/* ------------------------------------------------------------- primitives */
void op_sha256(void)  { uint8_t h[32]; g_status = sha256(g_msg, g_len, h); }
void op_hkdf44(void)  { uint8_t o[44]; g_status = hkdf(g_msg, 32, g_msg + 32, 16, g_msg + 48, 112, o, 44); }
void op_gcm(void)     { g_status = gcm_enc(g_msg, g_msg + 32, g_msg, 21, g_msg, g_len, g_ct); }
void op_chachapoly(void) { g_status = wc_ChaCha20Poly1305_Encrypt(g_msg, g_msg + 32, g_msg, 12, g_msg, g_len, g_ct, g_ct + g_len); }
void op_x25519_keygen(void) { curve25519_key k; wc_curve25519_init(&k); g_status = wc_curve25519_make_key(&rng, 32, &k); }
void op_x25519_derive(void) {
    static curve25519_key e; static int init = 0; uint8_t ss[32]; word32 l = 32;
    if (!init) { wc_curve25519_init(&e); wc_curve25519_make_key(&rng, 32, &e); init = 1; }
    g_status = wc_curve25519_shared_secret_ex(&e, &gw_x, ss, &l, EC25519_BIG_ENDIAN);
}
void op_ed25519_sign(void) { uint8_t s[64]; word32 l = 64; g_status = wc_ed25519_sign_msg(g_msg, 64, s, &l, &dev_ed); }
void op_ed25519_verify(void) {
    static uint8_t s[64]; static int init = 0; int res = 0; word32 l = 64;
    if (!init) { wc_ed25519_sign_msg(g_msg, 64, s, &l, &dev_ed); init = 1; }
    g_status = wc_ed25519_verify_msg(s, 64, g_msg, 64, &res, &dev_ed); if (!res) g_status = -1;
}
void op_p256_keygen(void) { ecc_key k; wc_ecc_init(&k); g_status = wc_ecc_make_key_ex(&rng, 32, &k, ECC_SECP256R1); }
void op_p256_ecdh(void) {
    static ecc_key e; static int init = 0; uint8_t ss[32]; word32 l = 32;
    if (!init) { wc_ecc_init(&e); wc_ecc_make_key_ex(&rng, 32, &e, ECC_SECP256R1); wc_ecc_set_rng(&e, &rng); init = 1; }
    g_status = wc_ecc_shared_secret(&e, &ecc_rx, ss, &l);
}
void op_ecdsa_sign(void) { uint8_t h[32], s[80]; word32 l = sizeof s; sha256(g_msg, 64, h); g_status = wc_ecc_sign_hash(h, 32, s, &l, &rng, &ecc_tx); }
void op_ecdsa_verify(void) {
    static uint8_t s[80]; static word32 l = sizeof s; static int init = 0; uint8_t h[32]; int res = 0;
    sha256(g_msg, 64, h);
    if (!init) { wc_ecc_sign_hash(h, 32, s, &l, &rng, &ecc_tx); init = 1; }
    g_status = wc_ecc_verify_hash(s, l, h, 32, &res, &ecc_tx); if (!res) g_status = -1;
}
void op_rsa_oaep_enc(void) {
    int r = wc_RsaPublicEncrypt_ex(g_msg, 32, g_ct, 256, &rsa_enc, &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
    g_status = r == 256 ? 0 : r;
}
void op_rsa_pss_sign(void) {
    uint8_t h[32]; sha256(g_msg, 64, h);
    int r = wc_RsaPSS_Sign(h, 32, g_ct, 256, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &rsa_sig, &rng);
    g_status = r == 256 ? 0 : r;
}
void op_rsa_pss_verify(void) {
    static uint8_t s[256]; static int init = 0; uint8_t h[32], out[256];
    sha256(g_msg, 64, h);
    if (!init) { wc_RsaPSS_Sign(h, 32, s, 256, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &rsa_sig, &rng); init = 1; }
    int r = wc_RsaPSS_Verify(s, 256, out, 256, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &rsa_sig);
    g_status = r > 0 ? 0 : r;
}

/* ---------------------------------------------------- per-packet senders */
/* RSA hybrid: random K; AES-256-GCM; RSA-OAEP(K); RSA-PSS over hdr || wk || SHA-256(C) */
void pkt_rsa_hybrid(void) {
    uint32_t n = g_len; uint8_t K[32], iv[12], tbs[24 + 256 + 32], h[32];
    uint8_t* p = g_pkt;
    put_u64(p, now_ms()); CHK(wc_RNG_GenerateBlock(&rng, p + 8, 16));
    CHK(wc_RNG_GenerateBlock(&rng, K, 32)); CHK(wc_RNG_GenerateBlock(&rng, iv, 12));
    memcpy(p + 24, iv, 12);
    CHK(gcm_enc(K, iv, p, 24, g_msg, n, p + 548));
    int r = wc_RsaPublicEncrypt_ex(K, 32, p + 36, 256, &rsa_enc, &rng, WC_RSA_OAEP_PAD, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, NULL, 0);
    if (r != 256) { g_status = r; return; }
    memcpy(tbs, p, 24); memcpy(tbs + 24, p + 36, 256);
    CHK(sha256(p + 548, n + 16, tbs + 280));
    CHK(sha256(tbs, sizeof tbs, h));
    r = wc_RsaPSS_Sign(h, 32, p + 292, 256, WC_HASH_TYPE_SHA256, WC_MGF1SHA256, &rsa_sig, &rng);
    g_status = r == 256 ? 0 : r;
}

/* ECIES-P256: ephemeral P-256; ECDH; HKDF(ss, -, hdr); AES-256-GCM; ECDSA over hdr || SHA-256(C) */
void pkt_ecies(void) {
    uint32_t n = g_len; ecc_key e; uint8_t ss[32], okm[44], tbs[89 + 32], h[32]; word32 l;
    uint8_t* p = g_pkt;
    CHK(wc_ecc_init(&e)); CHK(wc_ecc_make_key_ex(&rng, 32, &e, ECC_SECP256R1)); wc_ecc_set_rng(&e, &rng);
    put_u64(p, now_ms()); CHK(wc_RNG_GenerateBlock(&rng, p + 8, 16));
    l = 65; CHK(wc_ecc_export_x963(&e, p + 24, &l));
    l = 32; CHK(wc_ecc_shared_secret(&e, &ecc_rx, ss, &l));
    CHK(hkdf(ss, 32, NULL, 0, p, 89, okm, 44));
    uint8_t* C = p + 89 + 1 + 72;
    CHK(gcm_enc(okm, okm + 32, p, 89, g_msg, n, C));
    memcpy(tbs, p, 89); CHK(sha256(C, n + 16, tbs + 89)); CHK(sha256(tbs, sizeof tbs, h));
    l = 72; CHK(wc_ecc_sign_hash(h, 32, p + 90, &l, &rng, &ecc_tx));
    p[89] = (uint8_t)l;
    wc_ecc_free(&e);
}

/* Sethi et al. 2025: ephemeral X25519; K = ECDH; C = M xor ChaCha20(K, n) */
void pkt_sethi(void) {
    uint32_t n = g_len; curve25519_key e; uint8_t K[32]; word32 l; ChaCha ch;
    uint8_t* p = g_pkt;
    CHK(wc_curve25519_init(&e)); CHK(wc_curve25519_make_key(&rng, 32, &e));
    l = 32; CHK(wc_curve25519_export_public(&e, p, &l));
    l = 32; CHK(wc_curve25519_shared_secret_ex(&e, &gw_x, K, &l, EC25519_BIG_ENDIAN));
    CHK(wc_RNG_GenerateBlock(&rng, p + 32, 12));
    CHK(wc_Chacha_SetKey(&ch, K, 32)); CHK(wc_Chacha_SetIV(&ch, p + 32, 0));
    CHK(wc_Chacha_Process(&ch, p + 44, g_msg, n));
    wc_curve25519_free(&e);
}

/* Anwar et al. 2025, data plane: ChaCha20-Poly1305 under the session key */
void pkt_anwar(void) {
    uint32_t n = g_len; uint8_t* p = g_pkt;
    put_u32(p, 7); put_u64(p + 4, now_ms());
    CHK(wc_RNG_GenerateBlock(&rng, p + 12, 12));
    CHK(wc_ChaCha20Poly1305_Encrypt(anwar_sk, p + 12, p, 12, g_msg, n, p + 24, p + 24 + n));
}

/* Anwar et al. 2025, device side of the handshake (once per session) */
void sess_anwar_handshake(void) {
    uint8_t id[60], sig[64], E[32], mk[32], salt[8]; word32 l; int res = 0;
    curve25519_key e, gpk;
    put_u32(id, 7); put_u64(id + 4, now_ms()); CHK(wc_RNG_GenerateBlock(&rng, id + 12, 16));
    l = 32; CHK(wc_ed25519_export_public(&dev_ed, id + 28, &l));
    l = 64; CHK(wc_ed25519_sign_msg(id, 60, sig, &l, &dev_ed));
    CHK(wc_curve25519_init(&e)); CHK(wc_curve25519_make_key(&rng, 32, &e));
    l = 32; CHK(wc_curve25519_export_public(&e, E, &l));
    l = 64; CHK(wc_ed25519_sign_msg(E, 32, sig, &l, &dev_ed));
    CHK(wc_ed25519_verify_msg(anwar_meta_sig, 64, anwar_meta, 56, &res, &gw_ed)); if (!res) { g_status = -1; return; }
    CHK(wc_ed25519_verify_msg(anwar_gwE_sig, 64, anwar_gwE, 32, &res, &gw_ed)); if (!res) { g_status = -1; return; }
    CHK(wc_curve25519_init(&gpk)); CHK(wc_curve25519_import_public(anwar_gwE, 32, &gpk));
    l = 32; CHK(wc_curve25519_shared_secret_ex(&e, &gpk, mk, &l, EC25519_BIG_ENDIAN));
    put_u64(salt, now_ms() / 3600000);
    CHK(hkdf(mk, 32, salt, 8, (const uint8_t*)"encryption", 10, anwar_sk, 32));
}

/* ------------------------------------------------------------ CAOT-ECC */
#define FULL_HDR 73
#define SHORT_HDR 21
static void full_header(uint8_t* h, uint8_t mode, uint32_t s, uint32_t c, uint64_t t, const uint8_t N[16], const uint8_t E[32]) {
    h[0] = mode; put_u32(h + 1, 7); put_u32(h + 5, 100); put_u32(h + 9, s); put_u32(h + 13, c);
    put_u64(h + 17, t); memcpy(h + 25, N, 16); memcpy(h + 41, E, 32);
}
static void short_header(uint8_t* h, uint8_t mode, uint32_t s, uint32_t c, uint64_t t) {
    h[0] = mode; put_u32(h + 1, 7); put_u32(h + 5, s); put_u32(h + 9, c); put_u64(h + 13, t);
}

/* critical mode: ephemeral X25519, HKDF, AES-256-GCM(AAD = hdr), Ed25519 over label || hdr || SHA-256(C) */
void pkt_caot_critical(void) {
    uint32_t n = g_len; curve25519_key e; uint8_t N[16], E[32], ss[32], okm[44], info[7 + FULL_HDR + 32], tbs[7 + FULL_HDR + 32];
    word32 l; uint8_t* p = g_pkt;
    CHK(wc_curve25519_init(&e)); CHK(wc_curve25519_make_key(&rng, 32, &e));
    l = 32; CHK(wc_curve25519_export_public(&e, E, &l));
    CHK(wc_RNG_GenerateBlock(&rng, N, 16));
    full_header(p, 1, 0, 0, now_ms(), N, E);
    l = 32; CHK(wc_curve25519_shared_secret_ex(&e, &gw_x, ss, &l, EC25519_BIG_ENDIAN));
    wc_curve25519_free(&e);
    memcpy(info, "CAOT2/C", 7); memcpy(info + 7, p, FULL_HDR); memcpy(info + 7 + FULL_HDR, gw_x_pub, 32);
    CHK(hkdf(ss, 32, N, 16, info, sizeof info, okm, 44));
    uint8_t* C = p + FULL_HDR + 64;
    CHK(gcm_enc(okm, okm + 32, p, FULL_HDR, g_msg, n, C));
    memcpy(tbs, "CAOT2/C", 7); memcpy(tbs + 7, p, FULL_HDR); CHK(sha256(C, n + 16, tbs + 7 + FULL_HDR));
    l = 64; CHK(wc_ed25519_sign_msg(tbs, sizeof tbs, p + FULL_HDR, &l, &dev_ed));
}

/* routine mode: R_INIT (once per session) */
void sess_caot_rinit(void) {
    curve25519_key e; uint8_t N[16], E[32], ss[32], info[7 + FULL_HDR + 32], buf[8 + FULL_HDR]; word32 l;
    uint8_t* p = g_pkt;
    ++sid; ctr = 0;
    CHK(wc_curve25519_init(&e)); CHK(wc_curve25519_make_key(&rng, 32, &e));
    l = 32; CHK(wc_curve25519_export_public(&e, E, &l));
    CHK(wc_RNG_GenerateBlock(&rng, N, 16));
    full_header(p, 2, sid, 0, now_ms(), N, E);
    l = 32; CHK(wc_curve25519_shared_secret_ex(&e, &gw_x, ss, &l, EC25519_BIG_ENDIAN));
    wc_curve25519_free(&e);
    memcpy(info, "CAOT2/I", 7); memcpy(info + 7, p, FULL_HDR); memcpy(info + 7 + FULL_HDR, gw_x_pub, 32);
    CHK(hkdf(ss, 32, N, 16, info, sizeof info, chain_key, 32));
    memcpy(buf, "CAOT2/R0", 8); memcpy(buf + 8, p, FULL_HDR); CHK(sha256(buf, sizeof buf, run_hash));
    l = 64; CHK(wc_ed25519_sign_msg(info, 7 + FULL_HDR, p + FULL_HDR, &l, &dev_ed));
}

/* routine data packet, split into its three parts for the ablation */
static int routine_aead_only(uint32_t n, uint8_t* p, const uint8_t key[32], const uint8_t iv[12]) {
    short_header(p, 3, sid, ctr, now_ms());
    return gcm_enc(key, iv, p, SHORT_HDR, g_msg, n, p + SHORT_HDR);
}
static int routine_ratchet(uint8_t okm[76]) {
    uint8_t info[15]; ++ctr;
    memcpy(info, "CAOT2/R", 7); put_u32(info + 7, sid); put_u32(info + 11, ctr);
    int r = hkdf(chain_key, 32, NULL, 0, info, 15, okm, 76);
    memcpy(chain_key, okm + 44, 32);                    /* old chain key overwritten */
    return r;
}
static int routine_runhash(uint32_t n, const uint8_t* p) {
    uint8_t buf[32 + SHORT_HDR + 32]; int r;
    memcpy(buf, run_hash, 32); memcpy(buf + 32, p, SHORT_HDR);
    if ((r = sha256(p + SHORT_HDR, n + 16, buf + 32 + SHORT_HDR)) != 0) return r;
    return sha256(buf, sizeof buf, run_hash);
}
/* AEAD under a fixed session key: no forward secrecy, no non-repudiation */
void pkt_routine_aead_only(void) { g_status = routine_aead_only(g_len, g_pkt, anwar_sk, anwar_sk); }
/* + forward-secure ratchet */
void pkt_routine_ratchet(void) {
    uint8_t okm[76]; CHK(routine_ratchet(okm));
    g_status = routine_aead_only(g_len, g_pkt, okm, okm + 32);
}
/* full routine data packet: ratchet + AEAD + running hash */
void pkt_caot_routine(void) {
    uint8_t okm[76]; CHK(routine_ratchet(okm));
    CHK(routine_aead_only(g_len, g_pkt, okm, okm + 32));
    g_status = routine_runhash(g_len, g_pkt);
}
/* R_WIN: Ed25519 over label || hdr || RH, then RH = SHA-256("CAOT2/R0" || hdr || sigma) */
void pkt_caot_window(void) {
    /* window header: mode | ID_D | S | first | last | T (25 bytes) */
    uint8_t tbs[7 + 25 + 32], buf[8 + 25 + 64]; word32 l = 64; uint8_t* p = g_pkt;
    p[0] = 4; put_u32(p + 1, 7); put_u32(p + 5, sid); put_u32(p + 9, ctr > 16 ? ctr - 15 : 1); put_u32(p + 13, ctr); put_u64(p + 17, now_ms());
    memcpy(tbs, "CAOT2/W", 7); memcpy(tbs + 7, p, 25); memcpy(tbs + 7 + 25, run_hash, 32);
    CHK(wc_ed25519_sign_msg(tbs, sizeof tbs, p + 25, &l, &dev_ed));
    memcpy(buf, "CAOT2/R0", 8); memcpy(buf + 8, p, 25); memcpy(buf + 8 + 25, p + 25, 64);
    g_status = sha256(buf, sizeof buf, run_hash);
}

/* calibration helpers */
void op_chacha(void) { ChaCha ch; wc_Chacha_SetKey(&ch, g_msg, 32); wc_Chacha_SetIV(&ch, g_msg + 32, 0); g_status = wc_Chacha_Process(&ch, g_ct, g_msg, g_len); }
