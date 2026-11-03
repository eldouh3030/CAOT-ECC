// Functional and adversarial tests for CAOT-ECC v2.
// Each test prints PASS/FAIL; the process exit code is the number of failures.
#include "caot2.hpp"
#include <cstdio>
#include <functional>
#include <string>

using namespace cx;
using namespace caot2;

static int failures = 0, passed = 0;
static void check(bool cond, const std::string& name) {
    std::printf("  [%s] %s\n", cond ? "PASS" : "FAIL", name.c_str());
    cond ? ++passed : ++failures;
}
static Status rx(Server& s, const Bytes& p, uint64_t t) { Bytes o; return s.receive(p, t, o); }

struct Env {
    Config cfg;
    Server srv;
    Device dev;
    explicit Env(Config c = {}) : cfg(c), srv(100, x25519_keygen(), c), dev(7, ed25519_keygen(), 100, srv.public_key(), c) {
        srv.register_device(7, dev.public_key());
    }
};

static void test_critical() {
    std::puts("[critical mode]");
    Env e; uint64_t t = 1700000000000ULL;
    for (size_t n : {0, 1, 16, 1000, 100000}) {
        Bytes m = random_bytes(n), out;
        Bytes p = e.dev.seal_critical(m.data(), m.size(), t);
        check(e.srv.receive(p, t + 5, out) == Status::Ok && out == m, "round trip " + std::to_string(n) + " B");
    }
    Bytes m = str_bytes("HR=72;SpO2=98;T=36.8");
    Bytes p = e.dev.seal_critical(m.data(), m.size(), t);
    check(rx(e.srv, p, t) == Status::Ok, "fresh packet accepted");
    check(rx(e.srv, p, t + 10) == Status::Replay, "exact replay rejected (nonce cache)");
    check(rx(e.srv, p, t + 31000) == Status::Stale, "replay after window rejected (timestamp)");

    // tamper every region: header fields, nonce, ephemeral key, signature, ciphertext, tag
    struct Region { const char* name; size_t off; };
    Region regions[] = {{"mode byte", 0}, {"device id", 2}, {"session id", 10}, {"counter", 14},
                        {"timestamp", 20}, {"nonce", 30}, {"ephemeral key", 50}, {"signature", 80},
                        {"ciphertext", kFullHdrLen + kSigLen + 2}, {"GCM tag", 0}};
    for (auto& r : regions) {
        Bytes q = e.dev.seal_critical(m.data(), m.size(), t);
        size_t off = std::string(r.name) == "GCM tag" ? q.size() - 3 : r.off;
        q[off] ^= 0x01;
        Status s = rx(e.srv, q, t);
        check(s != Status::Ok, std::string("tampered ") + r.name + " rejected (" + to_string(s) + ")");
    }
    // truncated packet
    Bytes q = e.dev.seal_critical(m.data(), m.size(), t); q.resize(q.size() - 20);
    check(rx(e.srv, q, t) != Status::Ok, "truncated packet rejected");

    // future timestamp beyond delta
    Bytes f = e.dev.seal_critical(m.data(), m.size(), t + 60000);
    check(rx(e.srv, f, t) == Status::Stale, "future timestamp rejected");

    // impersonation: attacker device key claims id 7
    Device mallory(7, ed25519_keygen(), 100, e.srv.public_key());
    Bytes im = mallory.seal_critical(m.data(), m.size(), t);
    check(rx(e.srv, im, t) == Status::BadSignature, "impersonation with wrong signing key rejected");

    // unknown device
    Device stranger(99, ed25519_keygen(), 100, e.srv.public_key());
    check(rx(e.srv, stranger.seal_critical(m.data(), m.size(), t), t) == Status::UnknownDevice, "unregistered device rejected");

    // packet for another gateway (wrong recipient)
    Server other(200, x25519_keygen());
    other.register_device(7, e.dev.public_key());
    check(rx(other, e.dev.seal_critical(m.data(), m.size(), t), t) != Status::Ok, "packet re-targeted to another gateway rejected");

    // uniqueness: same message twice -> different keys/ciphertexts
    Bytes a = e.dev.seal_critical(m.data(), m.size(), t), b = e.dev.seal_critical(m.data(), m.size(), t);
    check(Bytes(a.begin() + kFullHdrLen + kSigLen, a.end()) != Bytes(b.begin() + kFullHdrLen + kSigLen, b.end()),
          "identical messages produce unrelated ciphertexts");
}

static void test_routine() {
    std::puts("[routine mode]");
    Config c; c.window_size = 16;
    Env e(c); uint64_t t = 1700000000000ULL;
    Bytes init = e.dev.open_session(t);
    check(rx(e.srv, init, t) == Status::Ok, "R_INIT accepted");
    check(rx(e.srv, init, t + 1) == Status::Replay, "R_INIT replay rejected");

    std::vector<Bytes> data;
    bool all_ok = true;
    for (int i = 0; i < 16; ++i) {
        Bytes m = str_bytes("HR=" + std::to_string(60 + i));
        Bytes p = e.dev.seal_routine(m.data(), m.size(), t + i);
        Bytes out;
        all_ok &= e.srv.receive(p, t + i, out) == Status::Ok && out == m;
        data.push_back(p);
    }
    check(all_ok, "16 routine packets decrypted");
    Bytes w = e.dev.close_window(t + 20);
    check(rx(e.srv, w, t + 20) == Status::Ok && e.srv.windows_verified == 1, "window signature verified (non-repudiation)");
    check(rx(e.srv, data[5], t + 21) == Status::Replay, "old routine packet replay rejected (counter)");
    check(rx(e.srv, data.back(), t + 21) == Status::Replay, "latest routine packet replay rejected");

    Bytes m = str_bytes("HR=75");
    Bytes p = e.dev.seal_routine(m.data(), m.size(), t + 30);
    Bytes bad = p; bad[bad.size() - 1] ^= 1;
    check(rx(e.srv, bad, t + 30) == Status::BadTag, "tampered routine packet rejected");
    Bytes badh = p; badh[16] ^= 1;   // timestamp in header (AAD)
    check(rx(e.srv, badh, t + 30) != Status::Ok, "tampered routine header rejected");
    check(rx(e.srv, p, t + 30) == Status::Ok, "genuine packet still accepted after forgery attempts");

    // packet loss: skip one packet, next one must still decrypt
    Bytes lost = e.dev.seal_routine(m.data(), m.size(), t + 31);
    (void)lost;
    Bytes after = e.dev.seal_routine(m.data(), m.size(), t + 32);
    check(rx(e.srv, after, t + 32) == Status::Ok, "decryption continues after a lost packet");
    check(rx(e.srv, lost, t + 33) == Status::Replay, "late (reordered) packet rejected");
    for (int i = 0; i < 13; ++i) { Bytes q = e.dev.seal_routine(m.data(), m.size(), t + 40); rx(e.srv, q, t + 40); }
    Bytes w2 = e.dev.close_window(t + 41);
    check(rx(e.srv, w2, t + 41) == Status::WindowMismatch, "window with loss flagged as unverifiable, not forged");
    for (int i = 0; i < 16; ++i) { Bytes q = e.dev.seal_routine(m.data(), m.size(), t + 50); rx(e.srv, q, t + 50); }
    check(rx(e.srv, e.dev.close_window(t + 51), t + 51) == Status::Ok, "next window resynchronises and verifies");

    // forged window signature
    Bytes q = e.dev.seal_routine(m.data(), m.size(), t + 60); rx(e.srv, q, t + 60);
    Bytes w3 = e.dev.close_window(t + 61); w3.back() ^= 1;
    check(rx(e.srv, w3, t + 61) == Status::BadSignature, "forged window signature rejected");

    // stale routine packet
    Bytes st = e.dev.seal_routine(m.data(), m.size(), t);
    check(rx(e.srv, st, t + 40000) == Status::Stale, "stale routine packet rejected");

    // counter jump beyond max_skip
    for (int i = 0; i < 70; ++i) e.dev.seal_routine(m.data(), m.size(), t + 70);
    Bytes far = e.dev.seal_routine(m.data(), m.size(), t + 70);
    check(rx(e.srv, far, t + 70) == Status::BadCounter, "counter gap beyond max_skip rejected");

    // data without session
    Env e2(c);
    Bytes i2 = e2.dev.open_session(t);  // never delivered
    Bytes d2 = e2.dev.seal_routine(m.data(), m.size(), t);
    check(rx(e2.srv, d2, t) == Status::NoSession, "routine packet without accepted R_INIT rejected");
    (void)i2;
}

static void test_policy() {
    std::puts("[context policy]");
    Config c; c.window_size = 4;
    Env e(c); uint64_t t = 1700000000000ULL;
    int crit = 0, init = 0, data = 0, win = 0, ok = 0, total = 0;
    for (int i = 0; i < 20; ++i) {
        int hr = (i == 9) ? 180 : 70 + (i % 5);       // one tachycardia event
        Priority pr = (hr > 150 || hr < 40) ? Priority::Critical : Priority::Routine;
        Bytes m = str_bytes("HR=" + std::to_string(hr));
        for (auto& p : e.dev.send(m.data(), m.size(), pr, t + i)) {
            switch (Mode(p[0])) {
                case Mode::Critical: ++crit; break; case Mode::RoutineInit: ++init; break;
                case Mode::RoutineData: ++data; break; case Mode::RoutineWindow: ++win; break;
            }
            ++total; if (rx(e.srv, p, t + i) == Status::Ok) ++ok;
        }
    }
    check(crit == 1 && init == 1 && data == 19 && win == 4, "policy: 1 critical, 1 init, 19 data, 4 windows");
    check(ok == total, "all policy-generated packets accepted");
}

static int real_main() {
    std::puts("CAOT-ECC v2 test suite");
    test_critical();
    test_routine();
    test_policy();
    std::printf("\n%d passed, %d failed\n", passed, failures);
    return failures;
}

int main(int argc, char** argv) {
    try {
        (void)argc; (void)argv; return real_main();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "\nERROR: %s\n", e.what());
        return 99;
    }
}
