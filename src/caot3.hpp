// CAOT-ECC v3: the v2 protocol with the clinical context hidden on the wire.
//
// v2 told a passive observer which packets were critical: the first byte was
// the mode, critical packets were 116 bytes longer, and window signatures were
// separate packets. v3 removes these channels:
//
//  * one session channel carries every reading. The outer header holds only
//    device id, session id, counter and time; it has no mode byte.
//  * the inner record is fixed size: type, length, payload padded to a bucket,
//    and a 64-byte signature slot. Type and padding sit inside AES-256-GCM.
//  * a critical reading carries an Ed25519 signature in the slot; a routine
//    reading leaves the slot zero, except the reading that closes a window,
//    whose slot carries the window signature (piggybacked, no extra frame).
//    If that reading is critical, the window closes on the next routine
//    reading. Every reading gives exactly one frame, and all frames are
//    indistinguishable on the wire.
//  * signatures are inside the ciphertext, so they are not public verifiers of
//    the reading (rule R2), and a third party can still check them once the
//    gateway discloses the record.
//
// Timing is handled by the sender policy (fixed send slots); see policy notes
// in the paper. Session setup (R_INIT) is unchanged and runs on a timer, not
// on clinical events.
#pragma once
#include "crypto.hpp"
#include <unordered_map>

namespace caot3 {

using cx::Bytes;

enum class Kind : uint8_t { Dummy = 0, Routine = 1, Critical = 2, Window = 3, RoutineWindow = 4 };

constexpr size_t kOuterLen = 4 + 4 + 4 + 8;      // did, sid, ctr, time
constexpr size_t kSigLen   = 64;
constexpr size_t kTagLen   = 16;
constexpr size_t kInitLen  = 1 + 4 + 4 + 4 + 8 + 16 + 32;  // 69, as v2 header without ctr

struct Config {
    uint64_t freshness_ms = 30000;
    uint32_t window_size  = 16;
    uint32_t bucket       = 64;   // payload is padded to this many bytes
    uint32_t max_skip     = 64;
};

inline size_t frame_len(const Config& c) { return kOuterLen + 1 + 2 + c.bucket + kSigLen + kTagLen; }

enum class Status { Ok, Malformed, UnknownDevice, Stale, Replay, BadSignature, BadTag, NoSession, BadCounter, TooLong };
const char* to_string(Status s);

struct Received { Kind kind = Kind::Dummy; Bytes payload; };

class Device {
public:
    Device(uint32_t did, cx::Key ed_sk, uint32_t gid, const Bytes& gw_pk, Config cfg = {});
    Bytes open_session(uint64_t now);                       // R_INIT, timer driven
    // One reading in, exactly one frame out (returned in a vector for symmetry
    // with v2).
    std::vector<Bytes> send(const uint8_t* msg, size_t n, bool critical, uint64_t now);
    Bytes dummy(uint64_t now);                              // cover frame for an empty slot
    const Bytes& public_key() const { return ed_pk_; }
private:
    Bytes frame(Kind k, const uint8_t* msg, size_t n, bool sign, uint64_t now);
    uint32_t id_, gw_id_, sid_ = 0, ctr_ = 0, in_window_ = 0, win_first_ = 1;
    cx::Key ed_sk_; Bytes ed_pk_; cx::Key gw_pk_; Bytes gw_pk_raw_;
    Config cfg_; Bytes chain_key_, running_hash_;
    bool active_ = false;
};

class Server {
public:
    Server(uint32_t gid, cx::Key x_sk, Config cfg = {});
    void register_device(uint32_t did, const Bytes& ed_pk);
    const Bytes& public_key() const { return x_pk_; }
    Status receive(const Bytes& pkt, uint64_t now, Received& out);
private:
    struct Session { Bytes chain_key, running_hash; uint32_t next_ctr = 1, win_first = 1; };
    Status rx_init(const Bytes& pkt, uint64_t now);
    uint32_t id_; cx::Key x_sk_; Bytes x_pk_; Config cfg_;
    std::unordered_map<uint32_t, cx::Key> devices_;
    std::unordered_map<uint64_t, Session> sessions_;
};

}  // namespace caot3
