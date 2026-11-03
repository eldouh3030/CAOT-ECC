// Low-entropy leakage in published IoMT designs, measured on real ICU vital
// signs (MIMIC numerics, data/vitals-real.csv).
//
// A value that depends only on the reading and on public data lets an
// eavesdropper test candidate readings offline. Three published patterns:
//
//  (L1) public digest  h = SHA-256(D) of each reading stored on a ledger
//       (integrity framework for remote monitoring, Computers 13 (2024) 164).
//       Attack: precomputed dictionary over the reading domain, one lookup per
//       record; and the salted-by-timestamp variant h = SHA-256(D || t).
//  (L2) convergent (message-locked) encryption of templated health records,
//       k = H(P), tag = H(k) visible to the cloud (EURASIP J. Wireless Commun.
//       Netw. 2018:185). Attack: guess-and-confirm against the tag, exhaustive
//       and correlation-guided.
//  (L3) deterministic tag HMAC_K(D) under a long-lived key next to the
//       ciphertext (Sensors 25 (2025) 7583). Not invertible, but equal readings
//       give equal tags: equality and frequency leakage.
//  (L4) generic message-locked hybrid encryption K = H(D || T), AES-CBC,
//       K wrapped under the receiver's RSA key (pattern of Section 3).
//
// usage: caot-leakage --data DIR --out DIR [--sample N]
#include "crypto.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <map>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <tuple>

using namespace cx;
using Clock = std::chrono::steady_clock;
static double ms_since(Clock::time_point t) { return std::chrono::duration<double, std::milli>(Clock::now() - t).count(); }

struct Vital { std::string rec; int minute, hr, spo2, resp; };

static std::vector<Vital> load(const std::string& path) {
    std::ifstream in(path);
    if (!in) { std::fprintf(stderr, "cannot read %s\n", path.c_str()); std::exit(1); }
    std::vector<Vital> v; std::string line; std::getline(in, line);
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::vector<std::string> f; std::stringstream ss(line); std::string c;
        while (std::getline(ss, c, ',')) f.push_back(c);
        while (f.size() < 7) f.push_back("");
        v.push_back({f[0], std::atoi(f[1].c_str()), std::atoi(f[2].c_str()), std::atoi(f[3].c_str()),
                     f[6].empty() ? 0 : std::atoi(f[6].c_str())});
    }
    return v;
}

static const int HR_LO = 30, HR_HI = 250, SP_LO = 40, SP_HI = 100, RE_LO = 0, RE_HI = 60;

struct Stats { std::vector<double> ms, guesses; int ok = 0; };
static void report(std::ofstream& f, const std::string& pattern, const std::string& strategy, const Stats& s) {
    std::vector<double> a = s.ms, g = s.guesses; std::sort(a.begin(), a.end()); std::sort(g.begin(), g.end());
    double mm = 0, mg = 0; for (double x : s.ms) mm += x; for (double x : s.guesses) mg += x;
    mm /= a.size(); mg /= g.size();
    double p95 = a[std::min(a.size() - 1, (size_t)std::ceil(0.95 * a.size()) - 1)];
    f << pattern << "," << strategy << "," << a.size() << "," << s.ok << "," << mg << "," << g[g.size() / 2] << ","
      << mm << "," << a[a.size() / 2] << "," << p95 << "," << a.back() << "\n";
    std::printf("    %-14s %-26s recovered %d/%zu  mean %.1f guesses (median %.0f)  mean %.4f ms  p95 %.4f  max %.4f\n",
                pattern.c_str(), strategy.c_str(), s.ok, a.size(), mg, g[g.size() / 2], mm, p95, a.back());
}

// Correlation-guided enumeration: Chebyshev shells around the previous reading.
// visit(hr, sp, re) returns true to stop. Returns number of candidates tested.
static uint64_t shells3(int ph, int ps, int pr, const std::function<bool(int, int, int)>& visit) {
    uint64_t g = 0;
    int rmax = std::max({HR_HI - HR_LO, SP_HI - SP_LO, RE_HI - RE_LO});
    for (int r = 0; r <= rmax; ++r)
        for (int dh = -r; dh <= r; ++dh)
            for (int ds = -r; ds <= r; ++ds)
                for (int dr = -r; dr <= r; ++dr) {
                    if (std::max({std::abs(dh), std::abs(ds), std::abs(dr)}) != r) continue;
                    int h = ph + dh, s = ps + ds, e = pr + dr;
                    if (h < HR_LO || h > HR_HI || s < SP_LO || s > SP_HI || e < RE_LO || e > RE_HI) continue;
                    ++g; if (visit(h, s, e)) return g;
                }
    return g;
}

// ------------------------------------------------------------------ (L1)
// The framework hashes each MAX30100 reading (heart rate, SpO2). The exact
// serialisation is not given in the paper, so the attacker tries several.
static std::string enc_l1(int fmt, int hr, int sp) {
    char b[96];
    switch (fmt) {
        case 0: std::snprintf(b, sizeof b, "{\"heart_rate\":%d,\"spo2\":%d}", hr, sp); break;
        case 1: std::snprintf(b, sizeof b, "%d,%d", hr, sp); break;
        case 2: std::snprintf(b, sizeof b, "HR=%d;SpO2=%d", hr, sp); break;
        default: std::snprintf(b, sizeof b, "%d.0,%d.0", hr, sp); break;
    }
    return b;
}
static void l1_public_digest(const std::vector<Vital>& vit, std::ofstream& f) {
    std::puts("[L1] public digest h = SHA-256(D) on a ledger (Computers 2024)");
    const int true_fmt = 0, nfmt = 4;
    std::vector<Bytes> ledger;
    for (auto& v : vit) { std::string d = enc_l1(true_fmt, v.hr, v.spo2); ledger.push_back(sha256(str_bytes(d))); }
    // dictionary over all formats and the whole (HR, SpO2) domain
    auto t0 = Clock::now();
    std::unordered_map<std::string, std::pair<int, int>> dict;
    for (int fmt = 0; fmt < nfmt; ++fmt)
        for (int h = HR_LO; h <= HR_HI; ++h)
            for (int s = SP_LO; s <= SP_HI; ++s) {
                Bytes d = sha256(str_bytes(enc_l1(fmt, h, s)));
                dict.emplace(std::string(d.begin(), d.end()), std::make_pair(h, s));
            }
    double pre = ms_since(t0);
    std::printf("    dictionary: %zu entries (4 encodings x %d readings), built in %.1f ms\n",
                dict.size(), (HR_HI - HR_LO + 1) * (SP_HI - SP_LO + 1), pre);
    Stats st;
    for (size_t i = 0; i < vit.size(); ++i) {
        auto t = Clock::now();
        auto it = dict.find(std::string(ledger[i].begin(), ledger[i].end()));
        st.ms.push_back(ms_since(t)); st.guesses.push_back(1);
        st.ok += it != dict.end() && it->second.first == vit[i].hr && it->second.second == vit[i].spo2;
    }
    report(f, "L1", "dictionary lookup", st);
    f << "L1,dictionary build (once)," << dict.size() << ",," << ",,"
      << pre << ",,,\n";
    // variant: the block also binds a public timestamp, h = SHA-256(D || t): no precomputation,
    // per-record search over formats x domain, correlation-guided on (HR, SpO2)
    Stats sv; int ph = 80, ps = 97;
    for (auto& v : vit) {
        std::string ts = std::to_string(1760000000 + 60 * v.minute);
        Bytes h = sha256(str_bytes(enc_l1(true_fmt, v.hr, v.spo2) + ts));
        auto t = Clock::now(); uint64_t g = 0; bool ok = false;
        for (int r = 0; r <= HR_HI - HR_LO && !ok; ++r)
            for (int dh = -r; dh <= r && !ok; ++dh)
                for (int ds = -r; ds <= r && !ok; ++ds) {
                    if (std::max(std::abs(dh), std::abs(ds)) != r) continue;
                    int hh = ph + dh, ss = ps + ds;
                    if (hh < HR_LO || hh > HR_HI || ss < SP_LO || ss > SP_HI) continue;
                    for (int fmt = 0; fmt < nfmt && !ok; ++fmt) {
                        ++g;
                        if (sha256(str_bytes(enc_l1(fmt, hh, ss) + ts)) == h) { ok = true; ph = hh; ps = ss; }
                    }
                }
        sv.ms.push_back(ms_since(t)); sv.guesses.push_back((double)g);
        sv.ok += ok && ph == v.hr && ps == v.spo2;
    }
    report(f, "L1", "with timestamp - correlation-guided", sv);
}

// ------------------------------------------------------------------ (L2)
static std::string phr_doc(const std::string& pid, int minute, int hr, int sp, int re) {
    char b[256];
    std::snprintf(b, sizeof b,
                  "PERSONAL HEALTH RECORD\nPatient ID: %s\nRecorded: minute %d\nHeart rate: %d bpm\n"
                  "SpO2: %d %%\nRespiration rate: %d /min\nSource: bedside monitor\n",
                  pid.c_str(), minute, hr, sp, re);
    return b;
}
static void l2_convergent(const std::vector<Vital>& vit, std::ofstream& f, int sample) {
    std::puts("[L2] convergent encryption of health records, k = H(P), tag = H(k) (EURASIP JWCN 2018)");
    auto tag_of = [](const std::string& doc) { return sha256(sha256(str_bytes(doc))); };
    // exhaustive on a random sample
    {
        std::mt19937 rng(11);
        std::vector<size_t> idx(vit.size()); for (size_t i = 0; i < idx.size(); ++i) idx[i] = i;
        std::shuffle(idx.begin(), idx.end(), rng); idx.resize(std::min<size_t>(sample, idx.size()));
        Stats st;
        for (size_t k : idx) {
            const Vital& v = vit[k];
            Bytes tag = tag_of(phr_doc(v.rec, v.minute, v.hr, v.spo2, v.resp));
            auto t = Clock::now(); uint64_t g = 0; bool ok = false; int fh = 0, fs = 0, fr = 0;
            for (int h = HR_LO; h <= HR_HI && !ok; ++h)
                for (int s = SP_LO; s <= SP_HI && !ok; ++s)
                    for (int r = RE_LO; r <= RE_HI && !ok; ++r) {
                        ++g; if (tag_of(phr_doc(v.rec, v.minute, h, s, r)) == tag) { ok = true; fh = h; fs = s; fr = r; }
                    }
            st.ms.push_back(ms_since(t)); st.guesses.push_back((double)g);
            st.ok += ok && fh == v.hr && fs == v.spo2 && fr == v.resp;
        }
        report(f, "L2", "exhaustive", st);
    }
    // correlation-guided over the whole stream
    {
        Stats st; int ph = 80, ps = 97, pr = 16;
        for (auto& v : vit) {
            Bytes tag = tag_of(phr_doc(v.rec, v.minute, v.hr, v.spo2, v.resp));
            auto t = Clock::now(); bool ok = false; int fh = 0, fs = 0, fr = 0;
            uint64_t g = shells3(ph, ps, pr, [&](int h, int s, int r) {
                if (tag_of(phr_doc(v.rec, v.minute, h, s, r)) == tag) { ok = true; fh = h; fs = s; fr = r; return true; }
                return false; });
            st.ms.push_back(ms_since(t)); st.guesses.push_back((double)g);
            st.ok += ok && fh == v.hr && fs == v.spo2 && fr == v.resp;
            if (ok) { ph = fh; ps = fs; pr = fr; }
        }
        report(f, "L2", "correlation-guided", st);
    }
}

// ------------------------------------------------------------------ (L3)
static Bytes hmac_sha256(const Bytes& key, const std::string& m) {
    unsigned char out[32]; size_t n = 0;
    EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, key.data(), key.size(),
              reinterpret_cast<const unsigned char*>(m.data()), m.size(), out, sizeof out, &n);
    return Bytes(out, out + n);
}
static void l3_deterministic_tag(const std::vector<Vital>& vit, std::ofstream& f) {
    std::puts("[L3] deterministic tag HMAC_K(D) under a session key (Sensors 2025)");
    // one record (patient) = one session key, as in the scheme
    std::map<std::string, std::vector<const Vital*>> by;
    for (auto& v : vit) by[v.rec].push_back(&v);
    // the tag-to-reading assignment breaks ties in tag order, which depends on the random
    // session key; the attack is therefore repeated with RUNS independent keys
    const int RUNS = 50;
    std::vector<double> run_exact, run_near;
    size_t total = 0, repeated = 0, distinct = 0, top1 = 0, n_attacked = 0, hits = 0, near = 0, base_hits = 0, base_near = 0;
    for (int run = 0; run < RUNS; ++run) {
    size_t h0 = hits, n0 = near, a0 = n_attacked;
    for (auto& kv : by) {
        Bytes K = random_bytes(16);
        std::vector<std::string> tags;
        for (auto* v : kv.second) {
            std::string d = "HR=" + std::to_string(v->hr) + ";SpO2=" + std::to_string(v->spo2) + ";RESP=" + std::to_string(v->resp);
            Bytes t = hmac_sha256(K, d); tags.emplace_back(t.begin(), t.end());
        }
        std::unordered_map<std::string, size_t> cnt;
        for (auto& t : tags) { if (cnt[t]++ > 0) ++repeated; }
        total += tags.size(); distinct += cnt.size();
        size_t mx = 0; for (auto& c : cnt) mx = std::max(mx, c.second); top1 += mx;
        // frequency analysis: the attacker knows the first half of the stream (e.g. an earlier,
        // leaked record) and maps tag classes of the second half to readings by frequency rank
        size_t half = tags.size() / 2;
        if (half < 10) continue;
        std::map<std::tuple<int, int, int>, size_t> prior;
        for (size_t i = 0; i < half; ++i) prior[{kv.second[i]->hr, kv.second[i]->spo2, kv.second[i]->resp}]++;
        std::unordered_map<std::string, size_t> c2;
        for (size_t i = half; i < tags.size(); ++i) c2[tags[i]]++;
        std::vector<std::pair<size_t, std::tuple<int, int, int>>> pr;
        for (auto& p : prior) pr.push_back({p.second, p.first});
        std::sort(pr.begin(), pr.end(), [](auto& a, auto& b) { return a.first > b.first; });
        std::vector<std::pair<size_t, std::string>> cl;
        for (auto& c : c2) cl.push_back({c.second, c.first});
        std::sort(cl.begin(), cl.end(), [](auto& a, auto& b) { return a.first > b.first; });
        std::unordered_map<std::string, std::tuple<int, int, int>> guess;
        for (size_t i = 0; i < cl.size() && i < pr.size(); ++i) guess[cl[i].second] = pr[i].second;
        auto [mh, ms, mr] = pr[0].second;                  // baseline without the tags: always guess the prior mode
        for (size_t i = half; i < tags.size(); ++i) {
            const Vital* bv = kv.second[i];
            if (mh == bv->hr && ms == bv->spo2 && mr == bv->resp) ++base_hits;
            if (std::abs(mh - bv->hr) <= 5 && std::abs(ms - bv->spo2) <= 2) ++base_near;
        }
        for (size_t i = half; i < tags.size(); ++i) {
            ++n_attacked;
            auto it = guess.find(tags[i]); if (it == guess.end()) continue;
            auto [h, s, r] = it->second; const Vital* v = kv.second[i];
            if (h == v->hr && s == v->spo2 && r == v->resp) ++hits;
            if (std::abs(h - v->hr) <= 5 && std::abs(s - v->spo2) <= 2) ++near;
        }
    }
    run_exact.push_back(100.0 * (hits - h0) / (n_attacked - a0));
    run_near.push_back(100.0 * (near - n0) / (n_attacked - a0));
    }
    total /= RUNS; repeated /= RUNS; distinct /= RUNS;
    auto msd = [](const std::vector<double>& x) {
        double m = 0, v = 0;
        for (double a : x) m += a;
        m /= x.size();
        for (double a : x) v += (a - m) * (a - m);
        return std::make_pair(m, std::sqrt(v / (x.size() - 1)));
    };
    auto [em, es] = msd(run_exact); auto [nm, ns] = msd(run_near);
    std::printf("    %zu packets, %zu distinct tags; %zu packets (%.1f%%) repeat an earlier tag\n",
                total, distinct, repeated, 100.0 * repeated / total);
    std::printf("    frequency analysis on the second half of each stream (%d keys): exact %.1f +- %.1f%%, "
                "HR within 5 bpm and SpO2 within 2%%: %.1f +- %.1f%%\n", RUNS, em, es, nm, ns);
    std::printf("    baseline without tags (always the most frequent prior reading): exact %.1f%%, near %.1f%%\n",
                100.0 * base_hits / n_attacked, 100.0 * base_near / n_attacked);
    f << "L3,baseline exact pct (no tags)," << n_attacked / RUNS << "," << 100.0 * base_hits / n_attacked << ",,,,,,\n";
    f << "L3,baseline near pct (no tags)," << n_attacked / RUNS << "," << 100.0 * base_near / n_attacked << ",,,,,,\n";
    f << "L3,equality leakage (packets repeating an earlier tag; distinct tags)," << total << "," << repeated << "," << distinct << ",,,,,\n";
    f << "L3,frequency analysis exact pct mean sd," << n_attacked / RUNS << "," << em << "," << es << ",,,,,\n";
    f << "L3,frequency analysis near pct mean sd (HR+-5 SpO2+-2)," << n_attacked / RUNS << "," << nm << "," << ns << ",,,,,\n";
}

// ------------------------------------------------------------------ (L4)
static void l4_mle_hybrid(const std::vector<Vital>& vit, std::ofstream& f) {
    std::puts("[L4] generic message-locked hybrid encryption K = H(D || T), AES-128-CBC");
    Stats st; int ph = 80, ps = 97, pr = 16;
    for (auto& v : vit) {
        std::string d = "HR=" + std::to_string(v.hr) + ";SpO2=" + std::to_string(v.spo2) + ";RESP=" + std::to_string(v.resp);
        Bytes T; put_u64(T, 1760000000000ull + 60000ull * v.minute);
        Bytes m = str_bytes(d), H = sha256(concat({&m, &T})), iv = random_bytes(16);
        Bytes C = aes_cbc_encrypt(Bytes(H.begin(), H.begin() + 16), iv, m);
        auto t = Clock::now(); bool ok = false; int fh = 0, fs = 0, fr = 0;
        uint64_t g = shells3(ph, ps, pr, [&](int h, int s, int r) {
            std::string c = "HR=" + std::to_string(h) + ";SpO2=" + std::to_string(s) + ";RESP=" + std::to_string(r);
            if (c.size() / 16 + 1 != C.size() / 16) return false;            // CBC length leak
            Bytes mc = str_bytes(c), Hc = sha256(concat({&mc, &T}));
            if (aes_cbc_encrypt(Bytes(Hc.begin(), Hc.begin() + 16), iv, mc) == C) { ok = true; fh = h; fs = s; fr = r; return true; }
            return false; });
        st.ms.push_back(ms_since(t)); st.guesses.push_back((double)g);
        st.ok += ok && fh == v.hr && fs == v.spo2 && fr == v.resp;
        if (ok) { ph = fh; ps = fs; pr = fr; }
    }
    report(f, "L4", "correlation-guided", st);
}

int main(int argc, char** argv) {
    try {
        std::string data = "data", out = "results"; int sample = 200;
        for (int i = 1; i + 1 < argc; i += 2) {
            std::string a = argv[i];
            if (a == "--data") data = argv[i + 1];
            else if (a == "--out") out = argv[i + 1];
            else if (a == "--sample") sample = std::atoi(argv[i + 1]);
        }
        auto vit = load(data + "/vitals-real.csv");
        std::printf("loaded %zu real ICU readings\n", vit.size());
        std::ofstream f(out + "/leakage.csv");
        f << "pattern,strategy,records,recovered,mean_guesses,median_guesses,mean_ms,median_ms,p95_ms,max_ms\n";
        l1_public_digest(vit, f);
        l2_convergent(vit, f, sample);
        l3_deterministic_tag(vit, f);
        l4_mle_hybrid(vit, f);
        std::printf("-> %s/leakage.csv\n", out.c_str());
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what()); return 1;
    }
}
