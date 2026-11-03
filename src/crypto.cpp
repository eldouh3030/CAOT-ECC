#include "crypto.hpp"
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <cstring>
#include <memory>

namespace cx {

static void fail(const char* what) {
    unsigned long e = ERR_get_error();
    char buf[256] = {0};
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    throw CryptoError(std::string(what) + (e ? std::string(": ") + buf : ""));
}

struct CtxDel   { void operator()(EVP_PKEY_CTX* c) const { EVP_PKEY_CTX_free(c); } };
struct MdDel    { void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); } };
struct CipDel   { void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); } };
using PCtx = std::unique_ptr<EVP_PKEY_CTX, CtxDel>;
using MCtx = std::unique_ptr<EVP_MD_CTX, MdDel>;
using CCtx = std::unique_ptr<EVP_CIPHER_CTX, CipDel>;

// ------------------------------------------------------------ bytes
Bytes random_bytes(size_t n) {
    Bytes b(n);
    if (n && RAND_bytes(b.data(), (int)n) != 1) fail("RAND_bytes");
    return b;
}
void append(Bytes& d, const Bytes& s) { d.insert(d.end(), s.begin(), s.end()); }
void append(Bytes& d, const uint8_t* s, size_t n) { d.insert(d.end(), s, s + n); }
void put_u32(Bytes& d, uint32_t v) { for (int i = 3; i >= 0; --i) d.push_back(uint8_t(v >> (8 * i))); }
void put_u64(Bytes& d, uint64_t v) { for (int i = 7; i >= 0; --i) d.push_back(uint8_t(v >> (8 * i))); }
uint32_t get_u32(const uint8_t* p) { uint32_t v = 0; for (int i = 0; i < 4; ++i) v = (v << 8) | p[i]; return v; }
uint64_t get_u64(const uint8_t* p) { uint64_t v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | p[i]; return v; }
Bytes concat(std::initializer_list<const Bytes*> parts) {
    size_t n = 0; for (auto* p : parts) n += p->size();
    Bytes out; out.reserve(n);
    for (auto* p : parts) append(out, *p);
    return out;
}
Bytes str_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }
void secure_wipe(Bytes& b) { if (!b.empty()) OPENSSL_cleanse(b.data(), b.size()); b.clear(); }
bool ct_equal(const Bytes& a, const Bytes& b) {
    return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}
std::string hex(const Bytes& b, size_t max) {
    static const char* h = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < b.size() && i < max; ++i) { s += h[b[i] >> 4]; s += h[b[i] & 15]; }
    if (b.size() > max) s += "...";
    return s;
}

// ------------------------------------------------------------ hash / kdf
Bytes sha256(const uint8_t* m, size_t n) {
    Bytes out(32);
    unsigned int len = 0;
    if (EVP_Digest(m, n, out.data(), &len, EVP_sha256(), nullptr) != 1) fail("SHA-256");
    return out;
}
Bytes sha256(const Bytes& m) { return sha256(m.data(), m.size()); }

Bytes hkdf_sha256(const Bytes& ikm, const Bytes& salt, const Bytes& info, size_t out_len) {
    // Fetch once per thread; EVP_KDF fetch is comparatively expensive.
    static thread_local EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) fail("EVP_KDF_fetch HKDF");
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    if (!kctx) fail("EVP_KDF_CTX_new");
    Bytes out(out_len);
    char digest[] = "SHA256";
    // Empty salt/info are simply omitted (RFC 5869: absent salt = HashLen zero bytes).
    // Passing a NULL pointer for an empty buffer is rejected by newer OpenSSL 3.x.
    OSSL_PARAM params[5];
    int np = 0;
    params[np++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    params[np++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)ikm.data(), ikm.size());
    if (!salt.empty())
        params[np++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void*)salt.data(), salt.size());
    if (!info.empty())
        params[np++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info.data(), info.size());
    params[np] = OSSL_PARAM_construct_end();
    int ok = EVP_KDF_derive(kctx, out.data(), out_len, params);
    EVP_KDF_CTX_free(kctx);
    if (ok != 1) fail("HKDF derive");
    return out;
}

// ------------------------------------------------------------ AES-GCM
static const EVP_CIPHER* gcm_for(size_t keylen) {
    if (keylen == 16) return EVP_aes_128_gcm();
    if (keylen == 32) return EVP_aes_256_gcm();
    throw CryptoError("AES-GCM: bad key length");
}

Bytes aes_gcm_encrypt(const Bytes& key, const Bytes& iv, const Bytes& aad, const uint8_t* pt, size_t n) {
    CCtx c(EVP_CIPHER_CTX_new());
    if (!c) fail("cipher ctx");
    if (EVP_EncryptInit_ex(c.get(), gcm_for(key.size()), nullptr, nullptr, nullptr) != 1) fail("gcm init");
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) != 1) fail("gcm ivlen");
    if (EVP_EncryptInit_ex(c.get(), nullptr, nullptr, key.data(), iv.data()) != 1) fail("gcm key");
    int len = 0;
    if (!aad.empty() && EVP_EncryptUpdate(c.get(), nullptr, &len, aad.data(), (int)aad.size()) != 1) fail("gcm aad");
    Bytes out(n + 16);
    int total = 0;
    if (n && EVP_EncryptUpdate(c.get(), out.data(), &len, pt, (int)n) != 1) fail("gcm update");
    total = n ? len : 0;
    if (EVP_EncryptFinal_ex(c.get(), out.data() + total, &len) != 1) fail("gcm final");
    total += len;
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_GET_TAG, 16, out.data() + total) != 1) fail("gcm tag");
    out.resize(total + 16);
    return out;
}
Bytes aes_gcm_encrypt(const Bytes& key, const Bytes& iv, const Bytes& aad, const Bytes& pt) {
    return aes_gcm_encrypt(key, iv, aad, pt.data(), pt.size());
}

bool aes_gcm_decrypt(const Bytes& key, const Bytes& iv, const Bytes& aad,
                     const uint8_t* ct_tag, size_t n, Bytes& pt) {
    if (n < 16) return false;
    size_t ctlen = n - 16;
    CCtx c(EVP_CIPHER_CTX_new());
    if (!c) fail("cipher ctx");
    if (EVP_DecryptInit_ex(c.get(), gcm_for(key.size()), nullptr, nullptr, nullptr) != 1) fail("gcm init");
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) != 1) fail("gcm ivlen");
    if (EVP_DecryptInit_ex(c.get(), nullptr, nullptr, key.data(), iv.data()) != 1) fail("gcm key");
    int len = 0;
    if (!aad.empty() && EVP_DecryptUpdate(c.get(), nullptr, &len, aad.data(), (int)aad.size()) != 1) fail("gcm aad");
    pt.assign(ctlen, 0);
    int total = 0;
    if (ctlen && EVP_DecryptUpdate(c.get(), pt.data(), &len, ct_tag, (int)ctlen) != 1) fail("gcm update");
    total = ctlen ? len : 0;
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_GCM_SET_TAG, 16, (void*)(ct_tag + ctlen)) != 1) fail("gcm settag");
    if (EVP_DecryptFinal_ex(c.get(), pt.data() + total, &len) != 1) { secure_wipe(pt); return false; }
    pt.resize(total + len);
    return true;
}

// ------------------------------------------------------------ ChaCha20
Bytes chacha20_xor(const Bytes& key, const Bytes& nonce12, const uint8_t* in, size_t n) {
    // OpenSSL's EVP_chacha20 takes a 16-byte IV = 32-bit LE block counter || 96-bit nonce
    uint8_t iv[16] = {1, 0, 0, 0};   // counter starts at 1, as in RFC 8439 encryption
    std::memcpy(iv + 4, nonce12.data(), 12);
    CCtx c(EVP_CIPHER_CTX_new());
    if (EVP_EncryptInit_ex(c.get(), EVP_chacha20(), nullptr, key.data(), iv) != 1) fail("chacha20 init");
    Bytes out(n);
    int len = 0;
    if (n && EVP_EncryptUpdate(c.get(), out.data(), &len, in, (int)n) != 1) fail("chacha20 update");
    return out;
}
Bytes chacha20poly1305_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad, const Bytes& pt) {
    CCtx c(EVP_CIPHER_CTX_new());
    if (EVP_EncryptInit_ex(c.get(), EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data()) != 1) fail("c20p1305 init");
    int len = 0;
    if (!aad.empty() && EVP_EncryptUpdate(c.get(), nullptr, &len, aad.data(), (int)aad.size()) != 1) fail("c20p1305 aad");
    Bytes out(pt.size() + 16);
    int total = 0;
    if (!pt.empty() && EVP_EncryptUpdate(c.get(), out.data(), &len, pt.data(), (int)pt.size()) != 1) fail("c20p1305 upd");
    total = pt.empty() ? 0 : len;
    if (EVP_EncryptFinal_ex(c.get(), out.data() + total, &len) != 1) fail("c20p1305 final");
    total += len;
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_AEAD_GET_TAG, 16, out.data() + total) != 1) fail("c20p1305 tag");
    out.resize(total + 16);
    return out;
}
bool chacha20poly1305_decrypt(const Bytes& key, const Bytes& nonce, const Bytes& aad,
                              const uint8_t* ct_tag, size_t n, Bytes& pt) {
    if (n < 16) return false;
    size_t ctlen = n - 16;
    CCtx c(EVP_CIPHER_CTX_new());
    if (EVP_DecryptInit_ex(c.get(), EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data()) != 1) fail("c20p1305 dinit");
    int len = 0;
    if (!aad.empty() && EVP_DecryptUpdate(c.get(), nullptr, &len, aad.data(), (int)aad.size()) != 1) fail("c20p1305 aad");
    pt.assign(ctlen, 0);
    int total = 0;
    if (ctlen && EVP_DecryptUpdate(c.get(), pt.data(), &len, ct_tag, (int)ctlen) != 1) fail("c20p1305 upd");
    total = ctlen ? len : 0;
    if (EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_AEAD_SET_TAG, 16, (void*)(ct_tag + ctlen)) != 1) fail("c20p1305 settag");
    if (EVP_DecryptFinal_ex(c.get(), pt.data() + total, &len) != 1) { secure_wipe(pt); return false; }
    pt.resize(total + len);
    return true;
}

// ------------------------------------------------------------ AES-CBC
static const EVP_CIPHER* cbc_for(size_t keylen) {
    if (keylen == 16) return EVP_aes_128_cbc();
    if (keylen == 32) return EVP_aes_256_cbc();
    throw CryptoError("AES-CBC: bad key length");
}
Bytes aes_cbc_encrypt(const Bytes& key, const Bytes& iv, const Bytes& pt) {
    CCtx c(EVP_CIPHER_CTX_new());
    if (EVP_EncryptInit_ex(c.get(), cbc_for(key.size()), nullptr, key.data(), iv.data()) != 1) fail("cbc init");
    Bytes out(pt.size() + 16);
    int len = 0, total = 0;
    if (EVP_EncryptUpdate(c.get(), out.data(), &len, pt.data(), (int)pt.size()) != 1) fail("cbc update");
    total = len;
    if (EVP_EncryptFinal_ex(c.get(), out.data() + total, &len) != 1) fail("cbc final");
    out.resize(total + len);
    return out;
}
bool aes_cbc_decrypt(const Bytes& key, const Bytes& iv, const Bytes& ct, Bytes& pt) {
    CCtx c(EVP_CIPHER_CTX_new());
    if (EVP_DecryptInit_ex(c.get(), cbc_for(key.size()), nullptr, key.data(), iv.data()) != 1) fail("cbc init");
    pt.assign(ct.size() + 16, 0);
    int len = 0, total = 0;
    if (EVP_DecryptUpdate(c.get(), pt.data(), &len, ct.data(), (int)ct.size()) != 1) return false;
    total = len;
    if (EVP_DecryptFinal_ex(c.get(), pt.data() + total, &len) != 1) { pt.clear(); return false; }
    pt.resize(total + len);
    return true;
}

// ------------------------------------------------------------ generic keygen
static Key keygen_id(int id) {
    PCtx c(EVP_PKEY_CTX_new_id(id, nullptr));
    if (!c || EVP_PKEY_keygen_init(c.get()) != 1) fail("keygen init");
    EVP_PKEY* k = nullptr;
    if (EVP_PKEY_keygen(c.get(), &k) != 1) fail("keygen");
    return Key(k);
}
static Bytes raw_public(const Key& k) {
    size_t n = 0;
    if (EVP_PKEY_get_raw_public_key(k.get(), nullptr, &n) != 1) fail("raw pub len");
    Bytes b(n);
    if (EVP_PKEY_get_raw_public_key(k.get(), b.data(), &n) != 1) fail("raw pub");
    return b;
}
static Bytes derive(const Key& priv, const Key& peer) {
    PCtx c(EVP_PKEY_CTX_new(priv.get(), nullptr));
    if (!c || EVP_PKEY_derive_init(c.get()) != 1) fail("derive init");
    if (EVP_PKEY_derive_set_peer(c.get(), peer.get()) != 1) fail("derive peer");
    size_t n = 0;
    if (EVP_PKEY_derive(c.get(), nullptr, &n) != 1) fail("derive len");
    Bytes s(n);
    if (EVP_PKEY_derive(c.get(), s.data(), &n) != 1) fail("derive");
    s.resize(n);
    return s;
}

// ------------------------------------------------------------ X25519
Key   x25519_keygen() { return keygen_id(EVP_PKEY_X25519); }
Bytes x25519_public_raw(const Key& k) { return raw_public(k); }
Key   x25519_from_public_raw(const Bytes& raw) {
    EVP_PKEY* k = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, raw.data(), raw.size());
    if (!k) fail("x25519 pub import");
    return Key(k);
}
Bytes x25519_derive(const Key& priv, const Key& peer) {
    Bytes s = derive(priv, peer);
    // Reject the all-zero output (small-order peer point), RFC 7748 sec. 6.1
    uint8_t acc = 0; for (auto b : s) acc |= b;
    if (acc == 0) throw CryptoError("x25519: low-order point");
    return s;
}

// ------------------------------------------------------------ Ed25519
Key ed25519_keygen() { return keygen_id(EVP_PKEY_ED25519); }
Bytes ed25519_sign(const Key& priv, const Bytes& msg) {
    MCtx m(EVP_MD_CTX_new());
    if (EVP_DigestSignInit(m.get(), nullptr, nullptr, nullptr, priv.get()) != 1) fail("ed25519 init");
    size_t n = 64; Bytes sig(64);
    if (EVP_DigestSign(m.get(), sig.data(), &n, msg.data(), msg.size()) != 1) fail("ed25519 sign");
    sig.resize(n);
    return sig;
}
bool ed25519_verify(const Key& pub, const Bytes& msg, const Bytes& sig) {
    MCtx m(EVP_MD_CTX_new());
    if (EVP_DigestVerifyInit(m.get(), nullptr, nullptr, nullptr, pub.get()) != 1) fail("ed25519 vinit");
    int r = EVP_DigestVerify(m.get(), sig.data(), sig.size(), msg.data(), msg.size());
    ERR_clear_error();
    return r == 1;
}

// ------------------------------------------------------------ P-256
Key p256_keygen() {
    EVP_PKEY* k = EVP_EC_gen("P-256");
    if (!k) fail("P-256 keygen");
    return Key(k);
}
Bytes p256_public_raw(const Key& k) {
    size_t n = 0;
    if (EVP_PKEY_get_octet_string_param(k.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &n) != 1) fail("p256 pub len");
    Bytes b(n);
    if (EVP_PKEY_get_octet_string_param(k.get(), OSSL_PKEY_PARAM_PUB_KEY, b.data(), n, &n) != 1) fail("p256 pub");
    return b;
}
Key p256_from_public_raw(const Bytes& raw) {
    PCtx c(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    if (!c || EVP_PKEY_fromdata_init(c.get()) != 1) fail("p256 fromdata init");
    char grp[] = "P-256";
    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, grp, 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void*)raw.data(), raw.size());
    params[2] = OSSL_PARAM_construct_end();
    EVP_PKEY* k = nullptr;
    if (EVP_PKEY_fromdata(c.get(), &k, EVP_PKEY_PUBLIC_KEY, params) != 1) fail("p256 fromdata");
    return Key(k);
}
Bytes p256_derive(const Key& priv, const Key& peer) { return derive(priv, peer); }

static Bytes digest_sign(const Key& priv, const EVP_MD* md, const Bytes& msg, int pad = 0) {
    MCtx m(EVP_MD_CTX_new());
    EVP_PKEY_CTX* pc = nullptr;
    if (EVP_DigestSignInit(m.get(), &pc, md, nullptr, priv.get()) != 1) fail("sign init");
    if (pad == RSA_PKCS1_PSS_PADDING) {
        if (EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) != 1) fail("pss pad");
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, RSA_PSS_SALTLEN_DIGEST) != 1) fail("pss salt");
    }
    size_t n = 0;
    if (EVP_DigestSign(m.get(), nullptr, &n, msg.data(), msg.size()) != 1) fail("sign len");
    Bytes sig(n);
    if (EVP_DigestSign(m.get(), sig.data(), &n, msg.data(), msg.size()) != 1) fail("sign");
    sig.resize(n);
    return sig;
}
static bool digest_verify(const Key& pub, const EVP_MD* md, const Bytes& msg, const Bytes& sig, int pad = 0) {
    MCtx m(EVP_MD_CTX_new());
    EVP_PKEY_CTX* pc = nullptr;
    if (EVP_DigestVerifyInit(m.get(), &pc, md, nullptr, pub.get()) != 1) fail("verify init");
    if (pad == RSA_PKCS1_PSS_PADDING) {
        EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING);
        EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, RSA_PSS_SALTLEN_DIGEST);
    }
    int r = EVP_DigestVerify(m.get(), sig.data(), sig.size(), msg.data(), msg.size());
    ERR_clear_error();
    return r == 1;
}

Bytes ecdsa_sign_sha256(const Key& priv, const Bytes& msg) { return digest_sign(priv, EVP_sha256(), msg); }
bool  ecdsa_verify_sha256(const Key& pub, const Bytes& msg, const Bytes& sig) { return digest_verify(pub, EVP_sha256(), msg, sig); }

Bytes ecdsa_sign_prehashed(const Key& priv, const Bytes& d) {
    PCtx c(EVP_PKEY_CTX_new(priv.get(), nullptr));
    if (!c || EVP_PKEY_sign_init(c.get()) != 1) fail("ecdsa pre init");
    size_t n = 0;
    if (EVP_PKEY_sign(c.get(), nullptr, &n, d.data(), d.size()) != 1) fail("ecdsa pre len");
    Bytes sig(n);
    if (EVP_PKEY_sign(c.get(), sig.data(), &n, d.data(), d.size()) != 1) fail("ecdsa pre sign");
    sig.resize(n);
    return sig;
}
bool ecdsa_verify_prehashed(const Key& pub, const Bytes& d, const Bytes& sig) {
    PCtx c(EVP_PKEY_CTX_new(pub.get(), nullptr));
    if (!c || EVP_PKEY_verify_init(c.get()) != 1) fail("ecdsa pre vinit");
    int r = EVP_PKEY_verify(c.get(), sig.data(), sig.size(), d.data(), d.size());
    ERR_clear_error();
    return r == 1;
}

// ------------------------------------------------------------ RSA
Key rsa_keygen(int bits) {
    EVP_PKEY* k = EVP_RSA_gen((unsigned)bits);
    if (!k) fail("RSA keygen");
    return Key(k);
}
Bytes rsa_oaep_encrypt(const Key& pub, const Bytes& m) {
    PCtx c(EVP_PKEY_CTX_new(pub.get(), nullptr));
    if (!c || EVP_PKEY_encrypt_init(c.get()) != 1) fail("oaep init");
    EVP_PKEY_CTX_set_rsa_padding(c.get(), RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(c.get(), EVP_sha256());
    size_t n = 0;
    if (EVP_PKEY_encrypt(c.get(), nullptr, &n, m.data(), m.size()) != 1) fail("oaep len");
    Bytes out(n);
    if (EVP_PKEY_encrypt(c.get(), out.data(), &n, m.data(), m.size()) != 1) fail("oaep enc");
    out.resize(n);
    return out;
}
bool rsa_oaep_decrypt(const Key& priv, const Bytes& ct, Bytes& m) {
    PCtx c(EVP_PKEY_CTX_new(priv.get(), nullptr));
    if (!c || EVP_PKEY_decrypt_init(c.get()) != 1) fail("oaep dinit");
    EVP_PKEY_CTX_set_rsa_padding(c.get(), RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(c.get(), EVP_sha256());
    size_t n = 0;
    if (EVP_PKEY_decrypt(c.get(), nullptr, &n, ct.data(), ct.size()) != 1) { ERR_clear_error(); return false; }
    m.assign(n, 0);
    if (EVP_PKEY_decrypt(c.get(), m.data(), &n, ct.data(), ct.size()) != 1) { ERR_clear_error(); m.clear(); return false; }
    m.resize(n);
    return true;
}
Bytes rsa_pss_sign_sha256(const Key& priv, const Bytes& msg) { return digest_sign(priv, EVP_sha256(), msg, RSA_PKCS1_PSS_PADDING); }
bool  rsa_pss_verify_sha256(const Key& pub, const Bytes& msg, const Bytes& sig) { return digest_verify(pub, EVP_sha256(), msg, sig, RSA_PKCS1_PSS_PADDING); }
Bytes rsa_pkcs1_sign_sha256(const Key& priv, const Bytes& msg) { return digest_sign(priv, EVP_sha256(), msg); }
bool  rsa_pkcs1_verify_sha256(const Key& pub, const Bytes& msg, const Bytes& sig) { return digest_verify(pub, EVP_sha256(), msg, sig); }

}  // namespace cx
