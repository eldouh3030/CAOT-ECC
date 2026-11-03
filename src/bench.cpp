// Benchmark harness: same payloads, same primitives, same statistics for
// every scheme. Writes CSV files that feed the tables/figures of the paper.
//
// usage: caot-bench [--reps N] [--out DIR] [--quick] [--file PATH ...]
#include "schemes.hpp"
#include <openssl/opensslv.h>
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <numeric>
#include <thread>

using namespace cx;
using Clock = std::chrono::steady_clock;

struct Stats { double mean, sd, median, p95, min; };
static Stats stats(std::vector<double> v) {
    Stats s{};
    if (v.empty()) return s;
    std::sort(v.begin(), v.end());
    double sum = std::accumulate(v.begin(), v.end(), 0.0);
    s.mean = sum / v.size();
    double acc = 0; for (double x : v) acc += (x - s.mean) * (x - s.mean);
    s.sd = v.size() > 1 ? std::sqrt(acc / (v.size() - 1)) : 0;
    s.median = v[v.size() / 2];
    s.p95 = v[std::min(v.size() - 1, (size_t)std::ceil(0.95 * v.size()) - 1)];
    s.min = v.front();
    return s;
}
static double us_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::micro>(Clock::now() - t0).count();
}

struct Payload { std::string label; Bytes data; };

static int reps_for(size_t n, int base) {
    if (n >= 1000000) return std::max(30, base / 20);
    if (n >= 60000)   return std::max(50, base / 4);
    return base;
}

// ------------------------------------------------------------- primitives
static void bench_primitives(const std::string& dir, int reps) {
    std::ofstream f(dir + "/primitives.csv");
    f << "primitive,reps,mean_us,sd_us,median_us,p95_us\n";
    auto run = [&](const std::string& name, const std::function<void()>& fn) {
        for (int i = 0; i < 20; ++i) fn();
        std::vector<double> t; t.reserve(reps);
        for (int i = 0; i < reps; ++i) { auto t0 = Clock::now(); fn(); t.push_back(us_since(t0)); }
        Stats s = stats(t);
        f << name << "," << reps << "," << s.mean << "," << s.sd << "," << s.median << "," << s.p95 << "\n";
        std::printf("  %-32s %10.2f us  (sd %.2f)\n", name.c_str(), s.mean, s.sd);
    };
    Key xa = x25519_keygen(), xb = x25519_keygen();
    Key ed = ed25519_keygen();
    Key pa = p256_keygen(), pb = p256_keygen();
    Key rsa = rsa_keygen(2048);
    Bytes msg = random_bytes(64), k32 = random_bytes(32), iv = random_bytes(12), kb = random_bytes(1024);
    Bytes edsig = ed25519_sign(ed, msg), ecsig = ecdsa_sign_sha256(pa, msg);
    Bytes pss = rsa_pss_sign_sha256(rsa, msg), oaep = rsa_oaep_encrypt(rsa, k32);
    Bytes gcm1k = aes_gcm_encrypt(k32, iv, Bytes(), kb);
    std::puts("[primitives]");
    run("SHA-256 (64 B)",            [&] { sha256(msg); });
    run("HKDF-SHA256 (44 B out)",    [&] { hkdf_sha256(k32, iv, msg, 44); });
    run("AES-256-GCM enc (1 KiB)",   [&] { aes_gcm_encrypt(k32, iv, Bytes(), kb); });
    run("AES-256-GCM dec (1 KiB)",   [&] { Bytes o; aes_gcm_decrypt(k32, iv, Bytes(), gcm1k.data(), gcm1k.size(), o); });
    run("X25519 keygen",             [&] { x25519_keygen(); });
    run("X25519 derive",             [&] { x25519_derive(xa, xb); });
    run("Ed25519 sign",              [&] { ed25519_sign(ed, msg); });
    run("Ed25519 verify",            [&] { ed25519_verify(ed, msg, edsig); });
    run("P-256 keygen",              [&] { p256_keygen(); });
    run("P-256 ECDH derive",         [&] { p256_derive(pa, pb); });
    run("ECDSA-P256 sign",           [&] { ecdsa_sign_sha256(pa, msg); });
    run("ECDSA-P256 verify",         [&] { ecdsa_verify_sha256(pa, msg, ecsig); });
    run("RSA-2048 OAEP encrypt",     [&] { rsa_oaep_encrypt(rsa, k32); });
    run("RSA-2048 OAEP decrypt",     [&] { Bytes o; rsa_oaep_decrypt(rsa, oaep, o); });
    run("RSA-2048 PSS sign",         [&] { rsa_pss_sign_sha256(rsa, msg); });
    run("RSA-2048 PSS verify",       [&] { rsa_pss_verify_sha256(rsa, msg, pss); });
}

// ------------------------------------------------------------- schemes
static void bench_schemes(const std::string& dir, const std::vector<Payload>& payloads, int base) {
    std::ofstream f(dir + "/schemes.csv");
    f << "scheme,payload,payload_bytes,reps,send_mean_us,send_sd_us,send_median_us,send_p95_us,"
         "recv_mean_us,recv_sd_us,recv_median_us,recv_p95_us,wire_bytes,overhead_bytes,throughput_MBps\n";
    std::vector<std::function<std::unique_ptr<schemes::Scheme>()>> makers = {
        schemes::make_rsa_hybrid, schemes::make_ecies_p256, schemes::make_sethi2025, schemes::make_anwar2025,
        schemes::make_caot_v2_critical, [] { return schemes::make_caot_v2_routine(16); },
    };
    for (auto& mk : makers) {
        auto s = mk();
        std::printf("[scheme] %s\n", s->name().c_str());
        for (const auto& p : payloads) {
            int reps = reps_for(p.data.size(), base);
            Bytes out;
            for (int i = 0; i < 10; ++i) { Bytes pk = s->seal(p.data); s->open(pk, out); }   // warm-up
            std::vector<double> ts, tr; ts.reserve(reps); tr.reserve(reps);
            double wire_sum = 0;
            for (int i = 0; i < reps; ++i) {
                auto t0 = Clock::now(); Bytes pk = s->seal(p.data); ts.push_back(us_since(t0));
                auto t1 = Clock::now(); bool ok = s->open(pk, out); tr.push_back(us_since(t1));
                if (!ok || out != p.data) { std::fprintf(stderr, "  !! %s failed on %s\n", s->short_name().c_str(), p.label.c_str()); return; }
                wire_sum += (double)s->wire_size(pk);
            }
            Stats a = stats(ts), b = stats(tr);
            double wire = wire_sum / reps;
            double thr = (double)p.data.size() / ((a.mean + b.mean) * 1e-6) / 1e6;
            f << s->short_name() << "," << p.label << "," << p.data.size() << "," << reps << ","
              << a.mean << "," << a.sd << "," << a.median << "," << a.p95 << ","
              << b.mean << "," << b.sd << "," << b.median << "," << b.p95 << ","
              << wire << "," << (wire - p.data.size()) << "," << thr << "\n";
            std::printf("  %-12s send %9.2f us  recv %9.2f us  overhead %7.1f B  thr %8.2f MB/s\n",
                        p.label.c_str(), a.mean, b.mean, wire - p.data.size(), thr);
        }
    }
}

// ------------------------------------------------------------- window sweep
static void bench_windows(const std::string& dir, int base) {
    std::ofstream f(dir + "/window.csv");
    f << "window,payload_bytes,packets,send_mean_us,recv_mean_us,wire_per_packet_bytes,overhead_per_packet_bytes\n";
    std::puts("[routine window sweep, 64-byte sensor payload]");
    Bytes m = random_bytes(64);
    for (uint32_t w : {1u, 2u, 4u, 8u, 16u, 32u, 64u, 128u}) {
        auto s = schemes::make_caot_v2_routine(w);
        int pkts = std::max<int>(base, (int)w * 32);
        pkts -= pkts % (int)w;
        double ts = 0, tr = 0, wire = 0; Bytes out;
        for (int i = 0; i < pkts; ++i) {
            auto t0 = Clock::now(); Bytes pk = s->seal(m); ts += us_since(t0);
            auto t1 = Clock::now(); s->open(pk, out); tr += us_since(t1);
            wire += (double)s->wire_size(pk);
        }
        f << w << ",64," << pkts << "," << ts / pkts << "," << tr / pkts << "," << wire / pkts << "," << wire / pkts - 64 << "\n";
        std::printf("  w=%-4u send %8.2f us/pkt  recv %8.2f us/pkt  overhead %6.1f B/pkt\n", w, ts / pkts, tr / pkts, wire / pkts - 64);
    }
}

static int real_main(int argc, char** argv) {
    int reps = 1000; std::string dir = "."; bool quick = false;
    std::vector<std::string> files;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--reps" && i + 1 < argc) reps = std::atoi(argv[++i]);
        else if (a == "--out" && i + 1 < argc) dir = argv[++i];
        else if (a == "--quick") quick = true;
        else if (a == "--file" && i + 1 < argc) files.push_back(argv[++i]);
    }
    if (quick) reps = 100;
    std::printf("CAOT-ECC v2 benchmark | %s | threads=%u | reps=%d\n", OPENSSL_VERSION_TEXT,
                std::thread::hardware_concurrency(), reps);
    {
        std::ofstream env(dir + "/environment.txt");
        env << "openssl=" << OPENSSL_VERSION_TEXT << "\nreps=" << reps
            << "\nhardware_threads=" << std::thread::hardware_concurrency()
#if defined(_MSC_VER)
            << "\ncompiler=MSVC " << _MSC_VER
#elif defined(__clang__)
            << "\ncompiler=clang " << __clang_major__ << "." << __clang_minor__
#elif defined(__GNUC__)
            << "\ncompiler=gcc " << __GNUC__ << "." << __GNUC_MINOR__
#endif
            << "\n";
    }

    std::vector<Payload> payloads;
    for (size_t n : {16, 64, 256, 1024, 4096, 16384, 65536}) payloads.push_back({std::to_string(n) + "B", random_bytes(n)});
    payloads.push_back({"1950000B", random_bytes(1950000)});   // size of one MIT-BIH .dat record
    for (const auto& path : files) {
        std::ifstream in(path, std::ios::binary);
        if (!in) { std::fprintf(stderr, "cannot read %s\n", path.c_str()); continue; }
        Bytes d((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        std::string label = path.substr(path.find_last_of("/\\") + 1);
        payloads.push_back({label, d});
    }

    bench_primitives(dir, reps);
    bench_schemes(dir, payloads, reps);
    bench_windows(dir, reps);
    std::printf("CSV written to %s\n", dir.c_str());
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
