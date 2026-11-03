#include "caot2.hpp"
#include <cstring>

namespace caot2 {
using namespace cx;

static const Bytes kLblCrit  = str_bytes("CAOT2/C");
static const Bytes kLblInit  = str_bytes("CAOT2/I");
static const Bytes kLblRun0  = str_bytes("CAOT2/R0");
static const Bytes kLblStep  = str_bytes("CAOT2/R");
static const Bytes kLblWin   = str_bytes("CAOT2/W");

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
        case Status::WindowMismatch: return "WINDOW_MISMATCH";
    }
    return "?";
}

// --------------------------------------------------------------- helpers
static Bytes full_header(Mode m, uint32_t did, uint32_t gid, uint32_t sid, uint32_t ctr,
                         uint64_t t, const Bytes& nonce, const Bytes& eph) {
    Bytes h; h.reserve(kFullHdrLen);
    h.push_back(uint8_t(m));
    put_u32(h, did); put_u32(h, gid); put_u32(h, sid); put_u32(h, ctr);
    put_u64(h, t);
    append(h, nonce); append(h, eph);
    return h;
}
static Bytes window_header(uint32_t did, uint32_t sid, uint32_t first, uint32_t last, uint64_t t) {
    Bytes h; h.reserve(kWinHdrLen);
    h.push_back(uint8_t(Mode::RoutineWindow));
    put_u32(h, did); put_u32(h, sid); put_u32(h, first); put_u32(h, last);
    put_u64(h, t);
    return h;
}
static Bytes short_header(Mode m, uint32_t did, uint32_t sid, uint32_t ctr, uint64_t t) {
    Bytes h; h.reserve(kShortHdrLen);
    h.push_back(uint8_t(m));
    put_u32(h, did); put_u32(h, sid); put_u32(h, ctr);
    put_u64(h, t);
    return h;
}
struct ChainStep { Bytes key, iv, next; };
static ChainStep chain_step(const Bytes& ck, uint32_t sid, uint32_t ctr) {
    Bytes info = kLblStep; put_u32(info, sid); put_u32(info, ctr);
    Bytes okm = hkdf_sha256(ck, Bytes(), info, 32 + 12 + 32);
    ChainStep s;
    s.key.assign(okm.begin(), okm.begin() + 32);
    s.iv.assign(okm.begin() + 32, okm.begin() + 44);
    s.next.assign(okm.begin() + 44, okm.end());
    secure_wipe(okm);
    return s;
}
static Bytes run_hash(const Bytes& prev, const Bytes& hdr, const uint8_t* ct, size_t n) {
    Bytes buf; buf.reserve(32 + hdr.size() + 32);
    append(buf, prev); append(buf, hdr); append(buf, sha256(ct, n));
    return sha256(buf);
}

// =============================================================== Device
Device::Device(uint32_t did, Key ed_sk, uint32_t gid, const Bytes& gw_pk, Config cfg)
    : id_(did), gw_id_(gid), ed_sk_(std::move(ed_sk)), cfg_(cfg) {
    ed_pk_ = x25519_public_raw(ed_sk_);  // raw public works for Ed25519 too
    gw_pk_ = x25519_from_public_raw(gw_pk);
    gw_pk_raw_ = gw_pk;
    Bytes r = random_bytes(4);
    next_sid_ = get_u32(r.data()) | 1u;
}

Bytes Device::seal_critical(const uint8_t* msg, size_t n, uint64_t now) {
    Key eph = x25519_keygen();
    Bytes E = x25519_public_raw(eph);
    Bytes N = random_bytes(kNonceLen);
    Bytes hdr = full_header(Mode::Critical, id_, gw_id_, 0, 0, now, N, E);

    Bytes ss = x25519_derive(eph, gw_pk_);
    eph.reset();                                         // erase ephemeral secret
    Bytes info = concat({&kLblCrit, &hdr, &gw_pk_raw_});
    Bytes okm = hkdf_sha256(ss, N, info, 32 + 12);
    secure_wipe(ss);
    Bytes K(okm.begin(), okm.begin() + 32), iv(okm.begin() + 32, okm.end());
    secure_wipe(okm);

    Bytes ct = aes_gcm_encrypt(K, iv, hdr, msg, n);
    secure_wipe(K);
    Bytes to_sign = concat({&kLblCrit, &hdr}); append(to_sign, sha256(ct));
    Bytes sig = ed25519_sign(ed_sk_, to_sign);

    Bytes pkt; pkt.reserve(hdr.size() + sig.size() + ct.size());
    append(pkt, hdr); append(pkt, sig); append(pkt, ct);
    return pkt;
}

Bytes Device::open_session(uint64_t now) {
    sid_ = next_sid_++;
    if (next_sid_ == 0) next_sid_ = 1;
    ctr_ = 0; in_window_ = 0; win_first_ = 1;
    Key eph = x25519_keygen();
    Bytes E = x25519_public_raw(eph);
    Bytes N = random_bytes(kNonceLen);
    Bytes hdr = full_header(Mode::RoutineInit, id_, gw_id_, sid_, 0, now, N, E);

    Bytes ss = x25519_derive(eph, gw_pk_);
    eph.reset();
    Bytes info = concat({&kLblInit, &hdr, &gw_pk_raw_});
    chain_key_ = hkdf_sha256(ss, N, info, 32);
    secure_wipe(ss);
    running_hash_ = sha256(concat({&kLblRun0, &hdr}));
    session_active_ = true;

    Bytes sig = ed25519_sign(ed_sk_, concat({&kLblInit, &hdr}));
    Bytes pkt = hdr; append(pkt, sig);
    return pkt;
}

Bytes Device::seal_routine(const uint8_t* msg, size_t n, uint64_t now) {
    if (!session_active_) throw CryptoError("no routine session");
    ++ctr_;
    ChainStep st = chain_step(chain_key_, sid_, ctr_);
    secure_wipe(chain_key_);                              // forward secrecy
    chain_key_ = std::move(st.next);
    Bytes hdr = short_header(Mode::RoutineData, id_, sid_, ctr_, now);
    Bytes ct = aes_gcm_encrypt(st.key, st.iv, hdr, msg, n);
    secure_wipe(st.key);
    running_hash_ = run_hash(running_hash_, hdr, ct.data(), ct.size());
    ++in_window_;
    Bytes pkt; pkt.reserve(hdr.size() + ct.size());
    append(pkt, hdr); append(pkt, ct);
    return pkt;
}

Bytes Device::close_window(uint64_t now) {
    Bytes hdr = window_header(id_, sid_, win_first_, ctr_, now);
    Bytes sig = ed25519_sign(ed_sk_, concat({&kLblWin, &hdr, &running_hash_}));
    in_window_ = 0; win_first_ = ctr_ + 1;
    running_hash_ = sha256(concat({&kLblRun0, &hdr, &sig}));   // start next window
    Bytes pkt = hdr; append(pkt, sig);
    return pkt;
}

std::vector<Bytes> Device::send(const uint8_t* msg, size_t n, Priority p, uint64_t now) {
    std::vector<Bytes> out;
    if (p == Priority::Critical) { out.push_back(seal_critical(msg, n, now)); return out; }
    if (!session_active_ || ctr_ >= cfg_.max_session_pk) {
        if (session_active_ && in_window_ > 0) out.push_back(close_window(now));
        out.push_back(open_session(now));
    }
    out.push_back(seal_routine(msg, n, now));
    if (in_window_ >= cfg_.window_size) out.push_back(close_window(now));
    return out;
}

// =============================================================== Server
Server::Server(uint32_t gid, Key x_sk, Config cfg) : id_(gid), x_sk_(std::move(x_sk)), cfg_(cfg) {
    x_pk_ = x25519_public_raw(x_sk_);
}

void Server::register_device(uint32_t did, const Bytes& pk) {
    EVP_PKEY* k = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pk.data(), pk.size());
    if (!k) throw CryptoError("bad Ed25519 public key");
    devices_[did] = Key(k);
}

bool Server::fresh(uint64_t t, uint64_t now) const {
    uint64_t d = t > now ? t - now : now - t;
    return d <= cfg_.freshness_ms;
}

Status Server::receive(const Bytes& pkt, uint64_t now, Bytes& out) {
    out.clear();
    if (pkt.empty()) return Status::Malformed;
    replay_.purge(now);
    Mode m = Mode(pkt[0]);
    switch (m) {
        case Mode::Critical:
        case Mode::RoutineInit:   return rx_full(pkt, m, now, out);
        case Mode::RoutineData:   return rx_data(pkt, now, out);
        case Mode::RoutineWindow: return rx_window(pkt, now);
    }
    return Status::Malformed;
}

Status Server::rx_full(const Bytes& pkt, Mode m, uint64_t now, Bytes& out) {
    if (pkt.size() < kFullHdrLen + kSigLen + (m == Mode::Critical ? kTagLen : 0)) return Status::Malformed;
    const uint8_t* p = pkt.data();
    uint32_t did = get_u32(p + 1), gid = get_u32(p + 5), sid = get_u32(p + 9);
    uint64_t t = get_u64(p + 17);
    Bytes hdr(p, p + kFullHdrLen);
    Bytes N(p + 25, p + 25 + kNonceLen);
    Bytes E(p + 41, p + 41 + kEphLen);
    Bytes sig(p + kFullHdrLen, p + kFullHdrLen + kSigLen);

    // 1) cheap checks first (no public-key operation before these pass)
    if (gid != id_) return Status::Malformed;
    auto dev = devices_.find(did);
    if (dev == devices_.end()) return Status::UnknownDevice;
    if (!fresh(t, now)) return Status::Stale;
    std::string rkey(reinterpret_cast<const char*>(p + 1), 4);
    rkey.append(reinterpret_cast<const char*>(N.data()), N.size());
    if (replay_.contains(rkey)) return Status::Replay;

    const Bytes& lbl = (m == Mode::Critical) ? kLblCrit : kLblInit;
    if (m == Mode::Critical) {
        const uint8_t* ct = p + kFullHdrLen + kSigLen;
        size_t ctn = pkt.size() - kFullHdrLen - kSigLen;
        // 2) authenticity / non-repudiation
        Bytes to_verify = concat({&lbl, &hdr}); append(to_verify, sha256(ct, ctn));
        if (!ed25519_verify(dev->second, to_verify, sig)) return Status::BadSignature;
        // 3) key agreement + decryption
        Key epk = x25519_from_public_raw(E);
        Bytes ss = x25519_derive(x_sk_, epk);
        Bytes info = concat({&lbl, &hdr, &x_pk_});
        Bytes okm = hkdf_sha256(ss, N, info, 44);
        secure_wipe(ss);
        Bytes K(okm.begin(), okm.begin() + 32), iv(okm.begin() + 32, okm.end());
        secure_wipe(okm);
        bool ok = aes_gcm_decrypt(K, iv, hdr, ct, ctn, out);
        secure_wipe(K);
        if (!ok) return Status::BadTag;
    } else {
        if (pkt.size() != kFullHdrLen + kSigLen) return Status::Malformed;
        if (!ed25519_verify(dev->second, concat({&lbl, &hdr}), sig)) return Status::BadSignature;
        uint64_t skey = (uint64_t(did) << 32) | sid;
        if (sessions_.count(skey)) return Status::Replay;
        Key epk = x25519_from_public_raw(E);
        Bytes ss = x25519_derive(x_sk_, epk);
        Bytes info = concat({&lbl, &hdr, &x_pk_});
        Session s;
        s.chain_key = hkdf_sha256(ss, N, info, 32);
        secure_wipe(ss);
        s.running_hash = sha256(concat({&kLblRun0, &hdr}));
        s.created_ms = now;
        sessions_[skey] = std::move(s);
    }
    replay_.insert(rkey, now + 2 * cfg_.freshness_ms);  // keep for the whole acceptance window
    return Status::Ok;
}

Status Server::rx_data(const Bytes& pkt, uint64_t now, Bytes& out) {
    if (pkt.size() < kShortHdrLen + kTagLen) return Status::Malformed;
    const uint8_t* p = pkt.data();
    uint32_t did = get_u32(p + 1), sid = get_u32(p + 5), ctr = get_u32(p + 9);
    uint64_t t = get_u64(p + 13);
    if (!devices_.count(did)) return Status::UnknownDevice;
    auto it = sessions_.find((uint64_t(did) << 32) | sid);
    if (it == sessions_.end()) return Status::NoSession;
    if (!fresh(t, now)) return Status::Stale;
    Session& s = it->second;
    if (ctr < s.next_ctr) return Status::Replay;                    // old or duplicated
    if (ctr - s.next_ctr > cfg_.max_skip) return Status::BadCounter;

    // Ratchet forward on a copy; commit only if the packet authenticates.
    Bytes ck = s.chain_key;
    ChainStep st;
    for (uint32_t j = s.next_ctr; j <= ctr; ++j) {
        st = chain_step(ck, sid, j);
        secure_wipe(ck);
        ck = st.next;
    }
    Bytes hdr(p, p + kShortHdrLen);
    const uint8_t* ct = p + kShortHdrLen;
    size_t ctn = pkt.size() - kShortHdrLen;
    bool ok = aes_gcm_decrypt(st.key, st.iv, hdr, ct, ctn, out);
    secure_wipe(st.key);
    if (!ok) { secure_wipe(ck); return Status::BadTag; }

    if (ctr != s.next_ctr) s.gap = true;
    secure_wipe(s.chain_key);
    s.chain_key = std::move(ck);
    s.next_ctr = ctr + 1;
    s.last_ctr = ctr;
    s.running_hash = run_hash(s.running_hash, hdr, ct, ctn);
    return Status::Ok;
}

Status Server::rx_window(const Bytes& pkt, uint64_t now) {
    if (pkt.size() != kWinHdrLen + kSigLen) return Status::Malformed;
    const uint8_t* p = pkt.data();
    uint32_t did = get_u32(p + 1), sid = get_u32(p + 5), first = get_u32(p + 9), last = get_u32(p + 13);
    uint64_t t = get_u64(p + 17);
    auto dev = devices_.find(did);
    if (dev == devices_.end()) return Status::UnknownDevice;
    auto it = sessions_.find((uint64_t(did) << 32) | sid);
    if (it == sessions_.end()) return Status::NoSession;
    if (!fresh(t, now)) return Status::Stale;
    Session& s = it->second;
    if (last != s.last_ctr || first != s.win_first) return Status::BadCounter;
    Bytes hdr(p, p + kWinHdrLen);
    Bytes sig(p + kWinHdrLen, p + kWinHdrLen + kSigLen);
    bool ok = ed25519_verify(dev->second, concat({&kLblWin, &hdr, &s.running_hash}), sig);
    s.running_hash = sha256(concat({&kLblRun0, &hdr, &sig}));      // resynchronise next window
    s.win_first = last + 1;
    if (!ok) {
        // With packet loss inside the window the running hashes legitimately
        // differ: packets stay AEAD-authenticated but the window cannot be
        // proven to a third party.
        if (s.gap) { ++windows_unverifiable; s.gap = false; return Status::WindowMismatch; }
        return Status::BadSignature;
    }
    ++windows_verified;
    s.gap = false;
    return Status::Ok;
}

}  // namespace caot2
