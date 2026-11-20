#include "caot3.hpp"

namespace caot3 {
using namespace cx;

static const Bytes kLblInit = str_bytes("CAOT3/I");
static const Bytes kLblRun0 = str_bytes("CAOT3/R0");
static const Bytes kLblStep = str_bytes("CAOT3/R");
static const Bytes kLblSig  = str_bytes("CAOT3/S");
static const Bytes kLblWin  = str_bytes("CAOT3/W");
static constexpr uint8_t kInitByte = 0x49;

const char* to_string(Status s) {
    switch (s) {
        case Status::Ok: return "OK";
        case Status::Malformed: return "MALFORMED";
        case Status::UnknownDevice: return "UNKNOWN_DEVICE";
        case Status::Stale: return "STALE_TIMESTAMP";
        case Status::Replay: return "REPLAY";
        case Status::BadSignature: return "BAD_SIGNATURE";
        case Status::BadTag: return "BAD_TAG";
        case Status::NoSession: return "NO_SESSION";
        case Status::BadCounter: return "BAD_COUNTER";
        case Status::TooLong: return "TOO_LONG";
    }
    return "?";
}

struct Step { Bytes key, iv, next; };
static Step chain_step(const Bytes& ck, uint32_t sid, uint32_t ctr) {
    Bytes info = kLblStep; put_u32(info, sid); put_u32(info, ctr);
    Bytes okm = hkdf_sha256(ck, Bytes(), info, 76);
    Step s;
    s.key.assign(okm.begin(), okm.begin() + 32);
    s.iv.assign(okm.begin() + 32, okm.begin() + 44);
    s.next.assign(okm.begin() + 44, okm.end());
    secure_wipe(okm);
    return s;
}
static Bytes outer(uint32_t did, uint32_t sid, uint32_t ctr, uint64_t t) {
    Bytes h; h.reserve(kOuterLen);
    put_u32(h, did); put_u32(h, sid); put_u32(h, ctr); put_u64(h, t);
    return h;
}
static Bytes init_header(uint32_t did, uint32_t gid, uint32_t sid, uint64_t t, const Bytes& N, const Bytes& E) {
    Bytes h; h.push_back(kInitByte);
    put_u32(h, did); put_u32(h, gid); put_u32(h, sid); put_u64(h, t);
    append(h, N); append(h, E);
    return h;
}
static Bytes next_hash(const Bytes& prev, const Bytes& hdr, const Bytes& ct) {
    return sha256(concat({&prev, &hdr, &ct}));
}

// ------------------------------------------------------------------ device
Device::Device(uint32_t did, Key ed_sk, uint32_t gid, const Bytes& gw_pk, Config cfg)
    : id_(did), gw_id_(gid), ed_sk_(std::move(ed_sk)), cfg_(cfg) {
    ed_pk_ = x25519_public_raw(ed_sk_);
    gw_pk_ = x25519_from_public_raw(gw_pk);
    gw_pk_raw_ = gw_pk;
    sid_ = get_u32(random_bytes(4).data()) | 1u;
}

Bytes Device::open_session(uint64_t now) {
    ++sid_; if (sid_ == 0) sid_ = 1;
    ctr_ = 0; in_window_ = 0; win_first_ = 1;
    Key eph = x25519_keygen();
    Bytes E = x25519_public_raw(eph), N = random_bytes(16);
    Bytes hdr = init_header(id_, gw_id_, sid_, now, N, E);
    Bytes ss = x25519_derive(eph, gw_pk_); eph.reset();
    chain_key_ = hkdf_sha256(ss, N, concat({&kLblInit, &hdr, &gw_pk_raw_}), 32);
    secure_wipe(ss);
    running_hash_ = sha256(concat({&kLblRun0, &hdr}));
    active_ = true;
    Bytes pkt = hdr; append(pkt, ed25519_sign(ed_sk_, concat({&kLblInit, &hdr})));
    return pkt;
}

Bytes Device::frame(Kind k, const uint8_t* msg, size_t n, bool sign, uint64_t now) {
    if (!active_) throw CryptoError("no session");
    if (n > cfg_.bucket) throw CryptoError("reading longer than bucket");
    ++ctr_;
    Step st = chain_step(chain_key_, sid_, ctr_);
    secure_wipe(chain_key_); chain_key_ = std::move(st.next);
    Bytes hdr = outer(id_, sid_, ctr_, now);

    Bytes inner; inner.reserve(3 + cfg_.bucket + kSigLen);
    inner.push_back(uint8_t(k));
    inner.push_back(uint8_t(n >> 8)); inner.push_back(uint8_t(n));
    append(inner, msg, n);
    inner.resize(3 + cfg_.bucket, 0);                       // padding
    Bytes sig(kSigLen, 0);
    if (sign) {
        Bytes body(inner.begin(), inner.end());
        bool win = (k == Kind::Window || k == Kind::RoutineWindow);
        Bytes tbs = win ? concat({&kLblWin, &hdr, &body, &running_hash_})
                        : concat({&kLblSig, &hdr, &body});
        sig = ed25519_sign(ed_sk_, tbs);
    }
    append(inner, sig);
    Bytes ct = aes_gcm_encrypt(st.key, st.iv, hdr, inner);
    secure_wipe(st.key); secure_wipe(inner);
    if (k == Kind::Window) running_hash_ = sha256(concat({&kLblRun0, &hdr, &sig}));
    else if (k == Kind::RoutineWindow) running_hash_ = next_hash(sha256(concat({&kLblRun0, &hdr, &sig})), hdr, ct);
    else running_hash_ = next_hash(running_hash_, hdr, ct);
    Bytes pkt = hdr; append(pkt, ct);
    return pkt;
}

std::vector<Bytes> Device::send(const uint8_t* msg, size_t n, bool critical, uint64_t now) {
    // Exactly one frame per reading, whatever the clinical state. A routine
    // reading that arrives after w unsigned frames carries the window
    // signature; during a run of critical readings the window simply stays
    // open, since each critical frame is signed on its own.
    std::vector<Bytes> out;
    if (critical) {
        out.push_back(frame(Kind::Critical, msg, n, true, now));
        ++in_window_;
    } else if (in_window_ >= cfg_.window_size) {
        out.push_back(frame(Kind::RoutineWindow, msg, n, true, now));
        in_window_ = 1; win_first_ = ctr_;
    } else {
        out.push_back(frame(Kind::Routine, msg, n, false, now));
        ++in_window_;
    }
    return out;
}

Bytes Device::dummy(uint64_t now) { return frame(Kind::Dummy, nullptr, 0, false, now); }

// ------------------------------------------------------------------ server
Server::Server(uint32_t gid, Key x_sk, Config cfg) : id_(gid), x_sk_(std::move(x_sk)), cfg_(cfg) {
    x_pk_ = x25519_public_raw(x_sk_);
}
void Server::register_device(uint32_t did, const Bytes& pk) {
    EVP_PKEY* k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pk.data(), pk.size());
    if (!k) throw CryptoError("bad Ed25519 public key");
    devices_[did] = Key(k);
}

Status Server::rx_init(const Bytes& pkt, uint64_t now) {
    const uint8_t* p = pkt.data();
    uint32_t did = get_u32(p + 1), gid = get_u32(p + 5), sid = get_u32(p + 9);
    uint64_t t = get_u64(p + 13);
    if (gid != id_) return Status::Malformed;
    auto dev = devices_.find(did);
    if (dev == devices_.end()) return Status::UnknownDevice;
    uint64_t d = t > now ? t - now : now - t;
    if (d > cfg_.freshness_ms) return Status::Stale;
    Bytes hdr(p, p + kInitLen), sig(p + kInitLen, p + kInitLen + kSigLen);
    if (!ed25519_verify(dev->second, concat({&kLblInit, &hdr}), sig)) return Status::BadSignature;
    uint64_t key = (uint64_t(did) << 32) | sid;
    if (sessions_.count(key)) return Status::Replay;
    Bytes N(p + 21, p + 37), E(p + 37, p + 69);
    Bytes ss = x25519_derive(x_sk_, x25519_from_public_raw(E));
    Session s;
    s.chain_key = hkdf_sha256(ss, N, concat({&kLblInit, &hdr, &x_pk_}), 32);
    secure_wipe(ss);
    s.running_hash = sha256(concat({&kLblRun0, &hdr}));
    sessions_[key] = std::move(s);
    return Status::Ok;
}

Status Server::receive(const Bytes& pkt, uint64_t now, Received& out) {
    out = Received{};
    if (pkt.size() == kInitLen + kSigLen && pkt[0] == kInitByte) return rx_init(pkt, now);
    if (pkt.size() != frame_len(cfg_)) return Status::Malformed;
    const uint8_t* p = pkt.data();
    uint32_t did = get_u32(p), sid = get_u32(p + 4), ctr = get_u32(p + 8);
    uint64_t t = get_u64(p + 12);
    auto dev = devices_.find(did);
    if (dev == devices_.end()) return Status::UnknownDevice;
    auto it = sessions_.find((uint64_t(did) << 32) | sid);
    if (it == sessions_.end()) return Status::NoSession;
    uint64_t d = t > now ? t - now : now - t;
    if (d > cfg_.freshness_ms) return Status::Stale;
    Session& s = it->second;
    if (ctr < s.next_ctr) return Status::Replay;
    if (ctr - s.next_ctr > cfg_.max_skip) return Status::BadCounter;

    Bytes ck = s.chain_key; Step st;
    for (uint32_t j = s.next_ctr; j <= ctr; ++j) { st = chain_step(ck, sid, j); secure_wipe(ck); ck = st.next; }
    Bytes hdr(p, p + kOuterLen), ct(p + kOuterLen, p + pkt.size()), inner;
    bool ok = aes_gcm_decrypt(st.key, st.iv, hdr, ct.data(), ct.size(), inner);
    secure_wipe(st.key);
    if (!ok) { secure_wipe(ck); return Status::BadTag; }

    Kind k = Kind(inner[0]);
    size_t n = (size_t(inner[1]) << 8) | inner[2];
    if (n > cfg_.bucket) return Status::TooLong;
    Bytes body(inner.begin(), inner.begin() + 3 + cfg_.bucket);
    Bytes sig(inner.begin() + 3 + cfg_.bucket, inner.end());
    if (k == Kind::Critical) {
        if (!ed25519_verify(dev->second, concat({&kLblSig, &hdr, &body}), sig)) return Status::BadSignature;
    } else if (k == Kind::Window || k == Kind::RoutineWindow) {
        if (!ed25519_verify(dev->second, concat({&kLblWin, &hdr, &body, &s.running_hash}), sig)) return Status::BadSignature;
    }
    secure_wipe(s.chain_key); s.chain_key = std::move(ck); s.next_ctr = ctr + 1;
    if (k == Kind::Window) s.running_hash = sha256(concat({&kLblRun0, &hdr, &sig}));
    else if (k == Kind::RoutineWindow) s.running_hash = next_hash(sha256(concat({&kLblRun0, &hdr, &sig})), hdr, ct);
    else s.running_hash = next_hash(s.running_hash, hdr, ct);
    out.kind = k;
    out.payload.assign(inner.begin() + 3, inner.begin() + 3 + n);
    return Status::Ok;
}

}  // namespace caot3
