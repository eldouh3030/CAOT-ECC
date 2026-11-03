// CAOT-ECC v2: Context-Aware One-Time ECC hybrid protocol for IoMT.
//
// Two operating modes selected per message by the clinical context:
//
//  CRITICAL  one-pass, self-contained packet. Fresh ephemeral X25519 key per
//            packet, HKDF-SHA256 key derivation bound to the full header,
//            AES-256-GCM, and an Ed25519 signature on every packet.
//
//  ROUTINE   one signed R_INIT establishes a session secret (ephemeral X25519).
//            Each data packet is protected by a one-time key taken from a
//            forward-secure HKDF chain (old chain keys are erased), AES-256-GCM
//            with the header as AAD, and a strictly increasing counter.
//            Non-repudiation is provided per window: every w packets an R_WIN
//            packet carries one Ed25519 signature over a running hash of the
//            window, so the signature cost is amortised over w packets.
//
// Replay protection: timestamp freshness window (delta) + nonce cache for
// one-pass packets, timestamp + monotonic counter for session packets.
#pragma once
#include "crypto.hpp"
#include <deque>
#include <unordered_map>
#include <string>

namespace caot2 {

using cx::Bytes;

enum class Mode : uint8_t { Critical = 0xC1, RoutineInit = 0xA1, RoutineData = 0xA2, RoutineWindow = 0xA3 };
enum class Priority { Routine, Critical };

// Wire sizes (bytes)
constexpr size_t kNonceLen   = 16;
constexpr size_t kEphLen     = 32;
constexpr size_t kSigLen     = 64;
constexpr size_t kTagLen     = 16;
constexpr size_t kFullHdrLen = 1 + 4 + 4 + 4 + 4 + 8 + kNonceLen + kEphLen;  // 73
constexpr size_t kShortHdrLen = 1 + 4 + 4 + 4 + 8;                            // 21
constexpr size_t kWinHdrLen   = 1 + 4 + 4 + 4 + 4 + 8;                        // 25: first and last counter

struct Config {
    uint64_t freshness_ms   = 30000;   // delta: max |now - T|
    uint32_t window_size    = 16;      // w: routine packets per window signature
    uint32_t max_session_pk = 1u << 20;// re-key after this many routine packets
    uint32_t max_skip       = 64;      // tolerated forward gap in counters (packet loss)
};

enum class Status {
    Ok, Malformed, UnknownDevice, Stale, Replay, BadSignature, BadTag,
    NoSession, BadCounter, WindowMismatch
};
const char* to_string(Status s);

// ------------------------------------------------------------------ device
class Device {
public:
    Device(uint32_t device_id, cx::Key ed25519_sk, uint32_t gateway_id, const Bytes& gateway_x25519_pk,
           Config cfg = {});

    // Policy entry point: chooses the mode from the clinical priority.
    // Returns one or two packets (a routine packet may be followed by R_INIT
    // before it, or an R_WIN after it).
    std::vector<Bytes> send(const uint8_t* msg, size_t n, Priority p, uint64_t now_ms);

    // Explicit mode functions (used by benchmarks / tests)
    Bytes seal_critical(const uint8_t* msg, size_t n, uint64_t now_ms);
    Bytes open_session(uint64_t now_ms);
    Bytes seal_routine(const uint8_t* msg, size_t n, uint64_t now_ms);
    Bytes close_window(uint64_t now_ms);
    bool  has_session() const { return session_active_; }
    uint32_t pending_in_window() const { return in_window_; }

    const Bytes& public_key() const { return ed_pk_; }
    uint32_t id() const { return id_; }

private:
    uint32_t id_, gw_id_;
    cx::Key ed_sk_;
    Bytes ed_pk_;
    cx::Key gw_pk_;
    Bytes gw_pk_raw_;
    Config cfg_;
    uint32_t next_sid_;

    // routine session state
    bool session_active_ = false;
    uint32_t sid_ = 0, ctr_ = 0, in_window_ = 0, win_first_ = 1;
    Bytes chain_key_;
    Bytes running_hash_;
};

// ------------------------------------------------------------------ server
class Server {
public:
    Server(uint32_t gateway_id, cx::Key x25519_sk, Config cfg = {});
    void register_device(uint32_t device_id, const Bytes& ed25519_pk_raw);
    const Bytes& public_key() const { return x_pk_; }

    // Processes one packet. On Ok, plaintext (may be empty for control packets).
    Status receive(const Bytes& pkt, uint64_t now_ms, Bytes& plaintext);

    // Counters for evaluation
    uint64_t windows_verified = 0, windows_unverifiable = 0;

private:
    struct Session {
        Bytes chain_key, running_hash;
        uint32_t next_ctr = 1, last_ctr = 0, win_first = 1;
        bool gap = false;   // a counter was skipped in current window
        uint64_t created_ms = 0;
    };
    class ReplayCache {
    public:
        bool contains(const std::string& k) const { return set_.count(k) != 0; }
        void insert(const std::string& k, uint64_t expiry) { set_[k] = expiry; fifo_.push_back({expiry, k}); }
        void purge(uint64_t now) {
            while (!fifo_.empty() && fifo_.front().first < now) {
                auto it = set_.find(fifo_.front().second);
                if (it != set_.end() && it->second < now) set_.erase(it);
                fifo_.pop_front();
            }
        }
        size_t size() const { return set_.size(); }
    private:
        std::unordered_map<std::string, uint64_t> set_;
        std::deque<std::pair<uint64_t, std::string>> fifo_;
    };

    Status rx_full(const Bytes& pkt, Mode m, uint64_t now, Bytes& out);
    Status rx_data(const Bytes& pkt, uint64_t now, Bytes& out);
    Status rx_window(const Bytes& pkt, uint64_t now);
    bool fresh(uint64_t t, uint64_t now) const;

    uint32_t id_;
    cx::Key x_sk_;
    Bytes x_pk_;
    Config cfg_;
    std::unordered_map<uint32_t, cx::Key> devices_;
    std::unordered_map<uint64_t, Session> sessions_;
    ReplayCache replay_;
};

}  // namespace caot2
