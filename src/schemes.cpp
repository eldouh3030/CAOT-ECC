#include "schemes.hpp"
#include <chrono>
#include <cstring>
#include <deque>
#include <unordered_map>

namespace schemes {
using namespace cx;

uint64_t now_ms() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

static constexpr uint64_t kDelta = 30000;
static bool fresh(uint64_t t) { uint64_t n = now_ms(); return (t > n ? t - n : n - t) <= kDelta; }

// ======================================================= RSA hybrid
class RsaHybrid : public Scheme {
    Key enc_sk_, sig_sk_;
public:
    RsaHybrid() : enc_sk_(rsa_keygen(2048)), sig_sk_(rsa_keygen(2048)) {}
    std::string name() const override { return "RSA-2048 hybrid (OAEP + PSS + AES-256-GCM)"; }
    std::string short_name() const override { return "RSA-HYB"; }
    Bytes seal(const Bytes& m) override {
        Bytes hdr; put_u64(hdr, now_ms()); append(hdr, random_bytes(16));
        Bytes K = random_bytes(32), iv = random_bytes(12);
        Bytes C = aes_gcm_encrypt(K, iv, hdr, m);
        Bytes wk = rsa_oaep_encrypt(enc_sk_, K);
        Bytes tbs = hdr; append(tbs, wk); append(tbs, sha256(C));
        Bytes sig = rsa_pss_sign_sha256(sig_sk_, tbs);
        Bytes p = hdr; append(p, iv); append(p, wk); append(p, sig); append(p, C);   // 24+12+256+256
        return p;
    }
    bool open(const Bytes& p, Bytes& m) override {
        if (p.size() < 24 + 12 + 512 + 16) return false;
        Bytes hdr(p.begin(), p.begin() + 24);
        if (!fresh(get_u64(hdr.data()))) return false;
        Bytes iv(p.begin() + 24, p.begin() + 36), wk(p.begin() + 36, p.begin() + 292), sig(p.begin() + 292, p.begin() + 548);
        const uint8_t* C = p.data() + 548; size_t cn = p.size() - 548;
        Bytes tbs = hdr; append(tbs, wk); append(tbs, sha256(C, cn));
        if (!rsa_pss_verify_sha256(sig_sk_, tbs, sig)) return false;
        Bytes K;
        if (!rsa_oaep_decrypt(enc_sk_, wk, K)) return false;
        return aes_gcm_decrypt(K, iv, hdr, C, cn, m);
    }
};

// ======================================================= ECIES P-256 + ECDSA
class EciesP256 : public Scheme {
    Key rx_sk_, tx_sk_;
    Bytes rx_pk_;
public:
    EciesP256() : rx_sk_(p256_keygen()), tx_sk_(p256_keygen()) { rx_pk_ = p256_public_raw(rx_sk_); }
    std::string name() const override { return "ECIES-P256 + ECDSA-P256 (AES-256-GCM)"; }
    std::string short_name() const override { return "ECIES-P256"; }
    Bytes seal(const Bytes& m) override {
        Key e = p256_keygen(); Bytes E = p256_public_raw(e);           // 65 bytes
        Bytes hdr; put_u64(hdr, now_ms()); append(hdr, random_bytes(16)); append(hdr, E);
        Key rpk = p256_from_public_raw(rx_pk_);
        Bytes ss = p256_derive(e, rpk);
        Bytes okm = hkdf_sha256(ss, Bytes(), hdr, 44);
        Bytes K(okm.begin(), okm.begin() + 32), iv(okm.begin() + 32, okm.end());
        Bytes C = aes_gcm_encrypt(K, iv, hdr, m);
        Bytes tbs = hdr; append(tbs, sha256(C));
        Bytes sig = ecdsa_sign_sha256(tx_sk_, tbs);
        Bytes p = hdr; p.push_back(uint8_t(sig.size())); append(p, sig); append(p, C);
        return p;
    }
    bool open(const Bytes& p, Bytes& m) override {
        const size_t hl = 8 + 16 + 65;
        if (p.size() < hl + 1 + 16) return false;
        Bytes hdr(p.begin(), p.begin() + hl);
        if (!fresh(get_u64(hdr.data()))) return false;
        size_t sl = p[hl];
        Bytes sig(p.begin() + hl + 1, p.begin() + hl + 1 + sl);
        const uint8_t* C = p.data() + hl + 1 + sl; size_t cn = p.size() - hl - 1 - sl;
        Bytes tbs = hdr; append(tbs, sha256(C, cn));
        if (!ecdsa_verify_sha256(tx_sk_, tbs, sig)) return false;
        Key epk = p256_from_public_raw(Bytes(hdr.begin() + 24, hdr.end()));
        Bytes ss = p256_derive(rx_sk_, epk);
        Bytes okm = hkdf_sha256(ss, Bytes(), hdr, 44);
        Bytes K(okm.begin(), okm.begin() + 32), iv(okm.begin() + 32, okm.end());
        return aes_gcm_decrypt(K, iv, hdr, C, cn, m);
    }
};

// ======================================================= Sethi et al. 2025
// K. Sethi et al., "Lightweight DWT Steganography With ECC-ChaCha20 for Secure
// Medical IoT Systems", IEEE Access 13 (2025) 142948-142960, Algorithms 1-2
// (cryptographic part only; the DWT embedding is out of scope).
// Sender: ephemeral ECC key pair, K = ECDH(e, pk_R), C = M xor ChaCha20(K, n),
// payload = (C, n, E). The paper does not name the curve; X25519 is used here
// (the fastest choice, i.e. favourable to the baseline). No MAC, no signature.
class Sethi2025 : public Scheme {
    Key rx_sk_; Bytes rx_pk_;
public:
    Sethi2025() : rx_sk_(x25519_keygen()) { rx_pk_ = x25519_public_raw(rx_sk_); }
    std::string name() const override { return "Sethi et al. 2025 (ephemeral ECDH + ChaCha20, no MAC/signature)"; }
    std::string short_name() const override { return "SETHI-2025"; }
    Bytes seal(const Bytes& m) override {
        Key e = x25519_keygen(); Bytes E = x25519_public_raw(e);
        Key rpk = x25519_from_public_raw(rx_pk_);
        Bytes K = x25519_derive(e, rpk);
        Bytes n = random_bytes(12);
        Bytes C = chacha20_xor(K, n, m.data(), m.size());
        Bytes p = E; append(p, n); append(p, C);       // 32 + 12 + |M|
        return p;
    }
    bool open(const Bytes& p, Bytes& m) override {
        if (p.size() < 44) return false;
        Key epk = x25519_from_public_raw(Bytes(p.begin(), p.begin() + 32));
        Bytes K = x25519_derive(rx_sk_, epk);
        Bytes n(p.begin() + 32, p.begin() + 44);
        m = chacha20_xor(K, n, p.data() + 44, p.size() - 44);
        return true;
    }
};

// ======================================================= Anwar et al. 2025
// S. Anwar, M. Hendi, J. Anderson, "Energy-Conscious and Regulation-Ready
// Security Protocol for Wearable Medical Devices: From Formal Proofs to
// Deployment", CPSIoTSec '25 (ACM), doi:10.1145/3733801.3764200, Sec. 4 and Fig. 1.
// Device-gateway leg: authenticated handshake once per session (Ed25519 signs
// identity metadata and the ephemeral X25519 key on both sides, ECDH, then
// SK = HKDF(MK, salt, "encryption", 32), valid up to 24 h / 1 GB); every data
// packet: CT = ChaCha20-Poly1305(SK, payload, nonce), timestamp + nonce checked.
// The handshake runs in the constructor; its cost is reported by handshake_us.
class Anwar2025 : public Scheme {
    Bytes sk_dev_, sk_gw_;
    uint32_t uid_ = 7;
    std::unordered_map<std::string, uint64_t> seen_;
    std::deque<std::pair<uint64_t, std::string>> fifo_;
public:
    double handshake_us = 0;
    Anwar2025() {
        auto t0 = std::chrono::steady_clock::now();
        Key dev_sign = ed25519_keygen(), gw_sign = ed25519_keygen();
        // device -> gateway: identity packet and signed ephemeral key
        Bytes id; put_u32(id, uid_); put_u64(id, now_ms()); append(id, random_bytes(16)); append(id, x25519_public_raw(dev_sign));
        Bytes sig_id = ed25519_sign(dev_sign, id);
        Key dev_eph = x25519_keygen(); Bytes dev_E = x25519_public_raw(dev_eph);
        Bytes sig_dev_key = ed25519_sign(dev_sign, dev_E);
        // gateway verifies, answers with signed metadata and ephemeral key
        if (!ed25519_verify(dev_sign, id, sig_id) || !ed25519_verify(dev_sign, dev_E, sig_dev_key)) throw CryptoError("anwar hs");
        Bytes meta; put_u64(meta, now_ms()); append(meta, random_bytes(16)); append(meta, x25519_public_raw(gw_sign));
        Bytes sig_meta = ed25519_sign(gw_sign, meta);
        Key gw_eph = x25519_keygen(); Bytes gw_E = x25519_public_raw(gw_eph);
        Bytes sig_gw_key = ed25519_sign(gw_sign, gw_E);
        // device verifies gateway
        if (!ed25519_verify(gw_sign, meta, sig_meta) || !ed25519_verify(gw_sign, gw_E, sig_gw_key)) throw CryptoError("anwar hs");
        Key gwpk = x25519_from_public_raw(gw_E), devpk = x25519_from_public_raw(dev_E);
        Bytes mk_d = x25519_derive(dev_eph, gwpk), mk_g = x25519_derive(gw_eph, devpk);
        Bytes salt; put_u64(salt, now_ms() / 3600000);           // time-based salt (hour)
        sk_dev_ = hkdf_sha256(mk_d, salt, str_bytes("encryption"), 32);
        sk_gw_  = hkdf_sha256(mk_g, salt, str_bytes("encryption"), 32);
        handshake_us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - t0).count();
    }
    std::string name() const override { return "Anwar et al. 2025 (Ed25519-authenticated X25519 session + ChaCha20-Poly1305)"; }
    std::string short_name() const override { return "ANWAR-2025"; }
    Bytes seal(const Bytes& m) override {
        Bytes hdr; put_u32(hdr, uid_); put_u64(hdr, now_ms());
        Bytes n = random_bytes(12);
        Bytes ct = chacha20poly1305_encrypt(sk_dev_, n, hdr, m);
        Bytes p = hdr; append(p, n); append(p, ct);              // 12 + 12 + |M| + 16
        return p;
    }
    bool open(const Bytes& p, Bytes& m) override {
        if (p.size() < 12 + 12 + 16) return false;
        uint64_t now = now_ms();
        while (!fifo_.empty() && fifo_.front().first < now) { seen_.erase(fifo_.front().second); fifo_.pop_front(); }
        Bytes hdr(p.begin(), p.begin() + 12), n(p.begin() + 12, p.begin() + 24);
        if (!fresh(get_u64(hdr.data() + 4))) return false;
        std::string key(reinterpret_cast<const char*>(n.data()), 12);
        if (seen_.count(key)) return false;
        if (!chacha20poly1305_decrypt(sk_gw_, n, hdr, p.data() + 24, p.size() - 24, m)) return false;
        seen_[key] = now + 2 * kDelta; fifo_.push_back({now + 2 * kDelta, key});
        return true;
    }
};

// ======================================================= CAOT v2 adapters
struct V2Pair {
    caot2::Server server;
    caot2::Device device;
    explicit V2Pair(caot2::Config cfg) : server(100, x25519_keygen(), cfg),
                                         device(7, ed25519_keygen(), 100, server.public_key(), cfg) {
        server.register_device(device.id(), device.public_key());
    }
};

class CaotV2Critical : public Scheme {
    V2Pair v_;
public:
    CaotV2Critical() : v_(caot2::Config{}) {}
    std::string name() const override { return "CAOT-ECC v2 critical (X25519+HKDF+AES-256-GCM+Ed25519)"; }
    std::string short_name() const override { return "CAOT-v2-C"; }
    Bytes seal(const Bytes& m) override { return v_.device.seal_critical(m.data(), m.size(), now_ms()); }
    bool open(const Bytes& p, Bytes& m) override { return v_.server.receive(p, now_ms(), m) == caot2::Status::Ok; }
};

class CaotV2Routine : public Scheme {
    V2Pair v_;
    uint32_t w_;
    // The R_WIN packet that may follow a data packet is handed to open()
    // through this member instead of being concatenated with the data packet,
    // so that large payloads are not copied by the harness.
    Bytes pending_window_;
    size_t extra_wire_ = 0;
public:
    explicit CaotV2Routine(uint32_t w) : v_([w] { caot2::Config c; c.window_size = w; c.max_session_pk = 0xFFFFFFFFu; return c; }()), w_(w) {
        Bytes init = v_.device.open_session(now_ms()), dummy;
        if (v_.server.receive(init, now_ms(), dummy) != caot2::Status::Ok) throw CryptoError("R_INIT rejected");
    }
    std::string name() const override { return "CAOT-ECC v2 routine, w=" + std::to_string(w_); }
    std::string short_name() const override { return "CAOT-v2-R" + std::to_string(w_); }
    Bytes seal(const Bytes& m) override {
        uint64_t t = now_ms();
        Bytes pkt = v_.device.seal_routine(m.data(), m.size(), t);
        pending_window_.clear();
        if (v_.device.pending_in_window() >= w_) pending_window_ = v_.device.close_window(t);
        extra_wire_ = pending_window_.size();
        return pkt;
    }
    bool open(const Bytes& pkt, Bytes& m) override {
        bool ok = v_.server.receive(pkt, now_ms(), m) == caot2::Status::Ok;
        if (!pending_window_.empty()) {
            Bytes tmp;
            ok &= v_.server.receive(pending_window_, now_ms(), tmp) == caot2::Status::Ok;
            pending_window_.clear();
        }
        return ok;
    }
    size_t wire_size(const Bytes& sealed) const override { return sealed.size() + extra_wire_; }
};

std::unique_ptr<Scheme> make_rsa_hybrid()        { return std::make_unique<RsaHybrid>(); }
std::unique_ptr<Scheme> make_ecies_p256()        { return std::make_unique<EciesP256>(); }
std::unique_ptr<Scheme> make_anwar2025()         { return std::make_unique<Anwar2025>(); }
std::unique_ptr<Scheme> make_sethi2025()         { return std::make_unique<Sethi2025>(); }
std::unique_ptr<Scheme> make_caot_v2_critical()  { return std::make_unique<CaotV2Critical>(); }
std::unique_ptr<Scheme> make_caot_v2_routine(uint32_t w) { return std::make_unique<CaotV2Routine>(w); }

}  // namespace schemes
