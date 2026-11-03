// CAOT-ECC v2 - thin C++17 wrappers around OpenSSL 3.x EVP primitives.
// Every primitive used by the proposed scheme and by the baselines lives here,
// so that all schemes are measured on exactly the same code paths.
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>
#include <openssl/evp.h>

namespace cx {

using Bytes = std::vector<uint8_t>;

struct CryptoError : std::runtime_error {
    explicit CryptoError(const std::string& m) : std::runtime_error(m) {}
};

// ---- RAII for EVP_PKEY ----
struct Key {
    EVP_PKEY* p = nullptr;
    Key() = default;
    explicit Key(EVP_PKEY* k) : p(k) {}
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    Key(Key&& o) noexcept : p(o.p) { o.p = nullptr; }
    Key& operator=(Key&& o) noexcept { if (this != &o) { reset(); p = o.p; o.p = nullptr; } return *this; }
    ~Key() { reset(); }
    void reset() { if (p) EVP_PKEY_free(p); p = nullptr; }
    EVP_PKEY* get() const { return p; }
};

// ---- byte helpers ----
Bytes random_bytes(size_t n);
void  append(Bytes& dst, const Bytes& src);
void  append(Bytes& dst, const uint8_t* src, size_t n);
void  put_u32(Bytes& dst, uint32_t v);
void  put_u64(Bytes& dst, uint64_t v);
uint32_t get_u32(const uint8_t* p);
uint64_t get_u64(const uint8_t* p);
Bytes concat(std::initializer_list<const Bytes*> parts);
Bytes str_bytes(const std::string& s);
void  secure_wipe(Bytes& b);
bool  ct_equal(const Bytes& a, const Bytes& b);
std::string hex(const Bytes& b, size_t max = 64);

// ---- hashing / KDF ----
Bytes sha256(const Bytes& m);
Bytes sha256(const uint8_t* m, size_t n);
// HKDF-SHA256 (RFC 5869), extract+expand
Bytes hkdf_sha256(const Bytes& ikm, const Bytes& salt, const Bytes& info, size_t out_len);

// ---- symmetric ----
// AES-GCM (key 16 or 32 bytes, iv 12 bytes, tag 16 bytes). Returns ciphertext||tag.
Bytes aes_gcm_encrypt(const Bytes& key, const Bytes& iv, const Bytes& aad, const uint8_t* pt, size_t n);
Bytes aes_gcm_encrypt(const Bytes& key, const Bytes& iv, const Bytes& aad, const Bytes& pt);
// Returns false on authentication failure.
bool  aes_gcm_decrypt(const Bytes& key, const Bytes& iv, const Bytes& aad,
                      const uint8_t* ct_tag, size_t n, Bytes& pt_out);
// AES-CBC with PKCS#7 padding (used by the message-locked reference pattern in leakage.cpp).
Bytes aes_cbc_encrypt(const Bytes& key, const Bytes& iv, const Bytes& pt);
bool  aes_cbc_decrypt(const Bytes& key, const Bytes& iv, const Bytes& ct, Bytes& pt_out);

// ChaCha20 stream cipher (RFC 8439), no authentication. key 32 B, nonce 12 B.
Bytes chacha20_xor(const Bytes& key, const Bytes& nonce12, const uint8_t* in, size_t n);
// ChaCha20-Poly1305 AEAD (RFC 8439). Returns ciphertext||tag(16).
Bytes chacha20poly1305_encrypt(const Bytes& key, const Bytes& nonce12, const Bytes& aad, const Bytes& pt);
bool  chacha20poly1305_decrypt(const Bytes& key, const Bytes& nonce12, const Bytes& aad,
                               const uint8_t* ct_tag, size_t n, Bytes& pt_out);

// ---- X25519 ----
Key   x25519_keygen();
Bytes x25519_public_raw(const Key& k);                 // 32 bytes
Key   x25519_from_public_raw(const Bytes& raw);
Bytes x25519_derive(const Key& priv, const Key& peer_pub);

// ---- Ed25519 ----
Key   ed25519_keygen();
Bytes ed25519_sign(const Key& priv, const Bytes& msg);  // 64 bytes
bool  ed25519_verify(const Key& pub_or_priv, const Bytes& msg, const Bytes& sig);

// ---- NIST P-256 (ECDH + ECDSA) ----
Key   p256_keygen();
Bytes p256_public_raw(const Key& k);                    // 65 bytes, uncompressed
Key   p256_from_public_raw(const Bytes& raw);
Bytes p256_derive(const Key& priv, const Key& peer_pub);
Bytes ecdsa_sign_sha256(const Key& priv, const Bytes& msg);           // DER, ~70-72 bytes
bool  ecdsa_verify_sha256(const Key& pub, const Bytes& msg, const Bytes& sig);
// ECDSA over an externally supplied 32-byte digest (no extra hashing).
Bytes ecdsa_sign_prehashed(const Key& priv, const Bytes& digest32);
bool  ecdsa_verify_prehashed(const Key& pub, const Bytes& digest32, const Bytes& sig);

// ---- RSA ----
Key   rsa_keygen(int bits);
Bytes rsa_oaep_encrypt(const Key& pub, const Bytes& m);
bool  rsa_oaep_decrypt(const Key& priv, const Bytes& c, Bytes& m_out);
Bytes rsa_pss_sign_sha256(const Key& priv, const Bytes& msg);
bool  rsa_pss_verify_sha256(const Key& pub, const Bytes& msg, const Bytes& sig);
// PKCS#1 v1.5 signature over raw data hashed with SHA-256
Bytes rsa_pkcs1_sign_sha256(const Key& priv, const Bytes& msg);
bool  rsa_pkcs1_verify_sha256(const Key& pub, const Bytes& msg, const Bytes& sig);

}  // namespace cx
