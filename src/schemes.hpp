// Common interface so that the proposed protocol and all baselines are timed
// by the same harness, on the same primitives and the same payloads.
#pragma once
#include "crypto.hpp"
#include "caot2.hpp"
#include <memory>
#include <string>

namespace schemes {

using cx::Bytes;

uint64_t now_ms();   // wall-clock milliseconds

class Scheme {
public:
    virtual ~Scheme() = default;
    virtual std::string name() const = 0;
    virtual std::string short_name() const = 0;
    virtual Bytes seal(const Bytes& msg) = 0;                    // sender side
    virtual bool  open(const Bytes& pkt, Bytes& msg_out) = 0;    // receiver side
    // Bytes actually transmitted (excludes harness-only framing).
    virtual size_t wire_size(const Bytes& sealed) const { return sealed.size(); }
};

// [RSA-HYB] classic hybrid: random AES-256-GCM key, RSA-2048-OAEP wrap, RSA-PSS signature.
std::unique_ptr<Scheme> make_rsa_hybrid();

// [ECIES-P256] SEC 1 style ECIES on P-256 + ECDSA P-256 signature.
std::unique_ptr<Scheme> make_ecies_p256();

// [SETHI-2025] Sethi et al., IEEE Access 2025: ephemeral ECDH + ChaCha20 (no authentication).
std::unique_ptr<Scheme> make_sethi2025();

// [ANWAR-2025] Anwar, Hendi & Anderson, ACM CPSIoTSec 2025: Ed25519-authenticated
// ephemeral X25519 session (once), then ChaCha20-Poly1305 per packet.
std::unique_ptr<Scheme> make_anwar2025();

// [CAOT v2-C] proposed, critical (one-pass) mode.
std::unique_ptr<Scheme> make_caot_v2_critical();

// [CAOT v2-R] proposed, routine mode; one R_WIN signature every `window`
// packets; the R_INIT packet is sent once at construction. When a window
// closes, the R_WIN packet is delivered together with the data packet and
// counted in wire_size().
std::unique_ptr<Scheme> make_caot_v2_routine(uint32_t window);

}  // namespace schemes
