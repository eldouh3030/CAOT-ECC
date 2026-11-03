// Experiments on real PhysioNet data.
//
//  (B) ECG streaming from MIT-BIH record 100: one packet per second (1080 B of
//      raw format-212 samples). Seconds containing an abnormal beat (from the
//      cardiologist annotations) are CRITICAL, the rest ROUTINE.
//  (C) Vital-sign streaming (MIMIC numerics) with an early-warning policy
//      (NEWS2-style thresholds) deciding CRITICAL vs ROUTINE.
//
// usage: caot-realdata --data DIR --out DIR
// (the low-entropy leakage attacks on the same vital signs are in leakage.cpp)
#include "schemes.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <iterator>
#include <random>
#include <sstream>
#include <string>

using namespace cx;
using Clock = std::chrono::steady_clock;
static double us_since(Clock::time_point t) { return std::chrono::duration<double, std::micro>(Clock::now() - t).count(); }

static std::vector<std::vector<std::string>> read_csv(const std::string& path) {
    std::ifstream in(path);
    if (!in) { std::fprintf(stderr, "cannot read %s (run tools/prepare-data.py first)\n", path.c_str()); std::exit(1); }
    std::vector<std::vector<std::string>> rows; std::string line;
    std::getline(in, line);   // header
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::vector<std::string> f; std::stringstream ss(line); std::string c;
        while (std::getline(ss, c, ',')) f.push_back(c);
        if (line.back() == ',') f.push_back("");
        rows.push_back(f);
    }
    return rows;
}
static Bytes read_file(const std::string& p) {
    std::ifstream in(p, std::ios::binary);
    if (!in) { std::fprintf(stderr, "cannot read %s\n", p.c_str()); std::exit(1); }
    return Bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

struct Vital { int hr, spo2, resp, sys, dia; };   // sys/dia = -1 when not measured
static std::string encode_vital(int hr, int spo2, int resp) {
    return "HR=" + std::to_string(hr) + ";SpO2=" + std::to_string(spo2) + ";RESP=" + std::to_string(resp);
}

// ------------------------------------------------------------------ streams
struct Pkt { Bytes data; bool critical; };

struct StreamResult { std::string scheme; size_t packets = 0, critical = 0; double send_us = 0, recv_us = 0, wire = 0, crit_send_us = 0; bool ok = true; };

static StreamResult run_baseline(schemes::Scheme& s, const std::vector<Pkt>& pk) {
    StreamResult r; r.scheme = s.short_name(); Bytes out;
    for (const auto& p : pk) {
        auto t0 = Clock::now(); Bytes w = s.seal(p.data); double ts = us_since(t0);
        auto t1 = Clock::now(); bool ok = s.open(w, out); r.recv_us += us_since(t1);
        r.send_us += ts; r.wire += (double)s.wire_size(w); ++r.packets;
        if (p.critical) { ++r.critical; r.crit_send_us += ts; }
        r.ok &= ok && out == p.data;
    }
    return r;
}

// CAOT-ECC v2 driven by the context policy (or forced to one mode)
enum class V2Mode { Policy, AllCritical, AllRoutine };
static StreamResult run_v2(const std::vector<Pkt>& pk, V2Mode mode, uint32_t w) {
    caot2::Config cfg; cfg.window_size = w;
    caot2::Server srv(100, x25519_keygen(), cfg);
    caot2::Device dev(7, ed25519_keygen(), 100, srv.public_key(), cfg);
    srv.register_device(7, dev.public_key());
    StreamResult r;
    r.scheme = mode == V2Mode::Policy ? "CAOT-v2 (context policy, w=" + std::to_string(w) + ")"
             : mode == V2Mode::AllCritical ? "CAOT-v2 (all critical)" : "CAOT-v2 (all routine, w=" + std::to_string(w) + ")";
    Bytes out;
    for (const auto& p : pk) {
        bool crit = mode == V2Mode::AllCritical || (mode == V2Mode::Policy && p.critical);
        uint64_t now = schemes::now_ms();
        auto t0 = Clock::now();
        auto wire = dev.send(p.data.data(), p.data.size(), crit ? caot2::Priority::Critical : caot2::Priority::Routine, now);
        double ts = us_since(t0);
        r.send_us += ts; ++r.packets;
        if (p.critical) { ++r.critical; r.crit_send_us += ts; }
        bool got = false;
        for (auto& x : wire) {
            r.wire += (double)x.size();
            Bytes tmp;
            auto t1 = Clock::now(); caot2::Status st = srv.receive(x, schemes::now_ms(), tmp); r.recv_us += us_since(t1);
            r.ok &= st == caot2::Status::Ok;
            if (x[0] == uint8_t(caot2::Mode::Critical) || x[0] == uint8_t(caot2::Mode::RoutineData)) { out = tmp; got = true; }
        }
        r.ok &= got && out == p.data;
    }
    return r;
}

static void run_stream(const std::string& title, const std::string& csv, const std::vector<Pkt>& pk) {
    size_t crit = 0, bytes = 0; for (auto& p : pk) { crit += p.critical; bytes += p.data.size(); }
    std::printf("[%s] %zu packets, %zu critical (%.2f %%), payload %zu B\n", title.c_str(), pk.size(), crit,
                100.0 * crit / pk.size(), bytes);
    std::ofstream f(csv);
    f << "scheme,packets,critical_packets,payload_bytes,total_send_ms,total_recv_ms,mean_send_us,mean_recv_us,"
         "mean_critical_send_us,wire_bytes,overhead_bytes,overhead_pct,ok\n";
    std::vector<StreamResult> res;
    { auto s = schemes::make_rsa_hybrid(); res.push_back(run_baseline(*s, pk)); }
    { auto s = schemes::make_ecies_p256(); res.push_back(run_baseline(*s, pk)); }
    { auto s = schemes::make_sethi2025();  res.push_back(run_baseline(*s, pk)); }
    { auto s = schemes::make_anwar2025();  res.push_back(run_baseline(*s, pk)); }
    res.push_back(run_v2(pk, V2Mode::AllCritical, 16));
    res.push_back(run_v2(pk, V2Mode::AllRoutine, 16));
    res.push_back(run_v2(pk, V2Mode::Policy, 16));
    for (auto& r : res) {
        double ov = r.wire - (double)bytes;
        f << '"' << r.scheme << "\"," << r.packets << "," << r.critical << "," << bytes << ","
          << r.send_us / 1000 << "," << r.recv_us / 1000 << "," << r.send_us / r.packets << "," << r.recv_us / r.packets << ","
          << (r.critical ? r.crit_send_us / r.critical : 0) << "," << r.wire << "," << ov << "," << 100 * ov / bytes << ","
          << (r.ok ? "yes" : "NO") << "\n";
        std::printf("    %-36s send %8.1f ms  recv %8.1f ms  overhead %6.1f %%  %s\n", r.scheme.c_str(),
                    r.send_us / 1000, r.recv_us / 1000, 100 * ov / bytes, r.ok ? "" : "FAILED");
    }
}

static int real_main(int argc, char** argv) {
    std::string data = "data", out = ".";
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--data" && i + 1 < argc) data = argv[++i];
        else if (a == "--out" && i + 1 < argc) out = argv[++i];
        else if (a == "--attack-sample" && i + 1 < argc) ++i;     // accepted for compatibility, unused
    }

    // real vital signs
    std::vector<Vital> vit;
    for (auto& r : read_csv(data + "/vitals-real.csv")) {
        Vital v{std::atoi(r[2].c_str()), std::atoi(r[3].c_str()), r[6].empty() ? 0 : std::atoi(r[6].c_str()),
                r[4].empty() ? -1 : std::atoi(r[4].c_str()), r[5].empty() ? -1 : std::atoi(r[5].c_str())};
        vit.push_back(v);
    }
    std::printf("loaded %zu real vital-sign records\n", vit.size());

    // (B) ECG stream: 1 s = 360 samples x 2 channels x 12 bit = 1080 bytes
    Bytes ecg = read_file(data + "/mitbih/100.dat");
    std::vector<bool> abnormal_second(ecg.size() / 1080 + 1, false);
    for (auto& r : read_csv(data + "/mitbih/100-annotations.csv"))
        if (r.size() >= 6 && r[5] == "1") abnormal_second[std::atol(r[0].c_str()) / 360] = true;
    std::vector<Pkt> ecg_pk;
    for (size_t o = 0, s = 0; o + 1080 <= ecg.size(); o += 1080, ++s)
        ecg_pk.push_back({Bytes(ecg.begin() + o, ecg.begin() + o + 1080), abnormal_second[s]});
    run_stream("B: MIT-BIH 100 ECG stream", out + "/stream-ecg.csv", ecg_pk);

    // (C) vital-sign stream, NEWS2-style red flags -> critical
    std::vector<Pkt> vit_pk;
    for (auto& v : vit) {
        bool crit = v.hr <= 40 || v.hr >= 131 || v.spo2 <= 91 || (v.resp > 0 && (v.resp <= 8 || v.resp >= 25)) ||
                    (v.sys > 0 && (v.sys <= 90 || v.sys >= 220));
        std::string m = encode_vital(v.hr, v.spo2, v.resp);
        if (v.sys > 0) m += ";BP=" + std::to_string(v.sys) + "/" + std::to_string(v.dia);
        vit_pk.push_back({Bytes(m.begin(), m.end()), crit});
    }
    run_stream("C: MIMIC vital-sign stream", out + "/stream-vitals.csv", vit_pk);
    return 0;
}

int main(int argc, char** argv) {
    try {
        return real_main(argc, argv);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "\nERROR: %s\n", e.what());
        return 99;
    }
}
