// Traffic-analysis experiment and checks for CAOT-ECC v3.
//
//   caot-traffic --stream data/vitals-stream.csv --out results
//
// The stream file has columns patient,hr,spo2 (one reading per line). A
// reading is critical when SpO2 < 90 or HR > 130 or HR < 40. Each reading is
// sent through v2 and v3; for every packet the program writes what a passive
// observer sees (first byte, length) and the hidden truth (critical or not).
// It also runs functional checks on v3 and times both versions.
#include "caot2.hpp"
#include "caot3.hpp"
#include <chrono>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using cx::Bytes;
using clk = std::chrono::steady_clock;

struct Reading { std::string patient; int hr, spo2; bool crit; };

static std::vector<Reading> load(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open " + path);
    std::string line; std::getline(f, line);
    std::vector<Reading> v;
    while (std::getline(f, line)) {
        std::stringstream ss(line); std::string a, b, c;
        std::getline(ss, a, ','); std::getline(ss, b, ','); std::getline(ss, c, ',');
        Reading r{a, std::stoi(b), std::stoi(c), false};
        r.crit = r.spo2 < 90 || r.hr > 130 || r.hr < 40;
        v.push_back(r);
    }
    return v;
}
static std::string payload(const Reading& r) {
    return "{\"hr\":" + std::to_string(r.hr) + ",\"spo2\":" + std::to_string(r.spo2) + "}";
}

static int fails = 0;
static void expect(bool ok, const char* what) {
    std::cout << (ok ? "  pass  " : "  FAIL  ") << what << "\n";
    if (!ok) ++fails;
}

static void checks() {
    std::cout << "v3 functional checks\n";
    auto gw = cx::x25519_keygen();
    caot3::Server srv(7, std::move(gw));
    auto ed = cx::ed25519_keygen();
    Bytes edpk = cx::x25519_public_raw(ed);
    caot3::Device dev(42, std::move(ed), 7, srv.public_key());
    srv.register_device(42, edpk);
    uint64_t t = 1000000;
    caot3::Received r;
    expect(srv.receive(dev.open_session(t), t, r) == caot3::Status::Ok, "session opens");
    std::string m = "{\"hr\":72,\"spo2\":97}";
    auto a = dev.send((const uint8_t*)m.data(), m.size(), false, t);
    auto b = dev.send((const uint8_t*)m.data(), m.size(), true, t);
    expect(a[0].size() == b[0].size(), "routine and critical frames have equal length");
    expect(srv.receive(a[0], t, r) == caot3::Status::Ok && r.kind == caot3::Kind::Routine &&
           std::string(r.payload.begin(), r.payload.end()) == m, "routine round trip");
    expect(srv.receive(b[0], t, r) == caot3::Status::Ok && r.kind == caot3::Kind::Critical, "critical round trip with signature");
    expect(srv.receive(b[0], t, r) == caot3::Status::Replay, "replay rejected");
    auto c = dev.send((const uint8_t*)m.data(), m.size(), true, t);
    Bytes bad = c[0]; bad[bad.size() - 20] ^= 1;
    expect(srv.receive(bad, t, r) == caot3::Status::BadTag, "tampered frame rejected");
    expect(srv.receive(c[0], t + 60000, r) == caot3::Status::Stale, "stale frame rejected");
    expect(srv.receive(c[0], t, r) == caot3::Status::Ok, "original still accepted");
    Bytes d = dev.dummy(t);
    expect(d.size() == a[0].size(), "dummy frame has the same length");
    expect(srv.receive(d, t, r) == caot3::Status::Ok && r.kind == caot3::Kind::Dummy, "dummy frame accepted and dropped");
    bool win = false, win_ok = true;
    for (int i = 0; i < 20; ++i) {
        auto v = dev.send((const uint8_t*)m.data(), m.size(), i % 5 == 0, t);
        for (auto& p : v) {
            if (p.size() != a[0].size()) win_ok = false;
            caot3::Status s = srv.receive(p, t, r);
            if (s != caot3::Status::Ok) win_ok = false;
            if (r.kind == caot3::Kind::Window || r.kind == caot3::Kind::RoutineWindow) win = true;
        }
    }
    expect(win && win_ok, "window signatures ride in data frames and verify");
}

int main(int argc, char** argv) {
    std::string stream, out = "results"; uint32_t bucket = 64;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--stream" && i + 1 < argc) stream = argv[++i];
        else if (a == "--out" && i + 1 < argc) out = argv[++i];
        else if (a == "--bucket" && i + 1 < argc) bucket = std::stoul(argv[++i]);
    }
    try {
        checks();
        if (stream.empty()) return fails ? 1 : 0;
        auto rd = load(stream);

        auto gw2 = cx::x25519_keygen(); auto gw3 = cx::x25519_keygen();
        caot2::Server s2(7, std::move(gw2)); caot3::Config c3; c3.bucket = bucket;
        caot3::Server s3(7, std::move(gw3), c3);
        auto e2 = cx::ed25519_keygen(); auto e3 = cx::ed25519_keygen();
        Bytes p2 = cx::x25519_public_raw(e2), p3 = cx::x25519_public_raw(e3);
        caot2::Device d2(42, std::move(e2), 7, s2.public_key()); s2.register_device(42, p2);
        caot3::Device d3(42, std::move(e3), 7, s3.public_key(), c3); s3.register_device(42, p3);

        std::ofstream tr(out + "/traffic-b" + std::to_string(bucket) + ".csv");
        tr << "version,reading,first_byte,length,critical\n";
        uint64_t t = 1000000;
        caot3::Received r3; Bytes pt;
        { auto i = d3.open_session(t); s3.receive(i, t, r3); }
        double us2c = 0, us2r = 0, us3c = 0, us3r = 0; size_t n2c = 0, n2r = 0, n3c = 0, n3r = 0;
        size_t bytes2 = 0, bytes3 = 0;
        for (size_t i = 0; i < rd.size(); ++i, t += 1000) {
            std::string m = payload(rd[i]);
            auto a0 = clk::now();
            auto v2 = d2.send((const uint8_t*)m.data(), m.size(), rd[i].crit ? caot2::Priority::Critical : caot2::Priority::Routine, t);
            auto a1 = clk::now();
            auto v3 = d3.send((const uint8_t*)m.data(), m.size(), rd[i].crit, t);
            auto a2 = clk::now();
            double u2 = std::chrono::duration<double, std::micro>(a1 - a0).count();
            double u3 = std::chrono::duration<double, std::micro>(a2 - a1).count();
            if (rd[i].crit) { us2c += u2; ++n2c; us3c += u3; ++n3c; } else { us2r += u2; ++n2r; us3r += u3; ++n3r; }
            for (auto& p : v2) { tr << "v2," << i << "," << int(p[0]) << "," << p.size() << "," << rd[i].crit << "\n"; bytes2 += p.size(); s2.receive(p, t, pt); }
            for (auto& p : v3) { tr << "v3," << i << "," << int(p[0]) << "," << p.size() << "," << rd[i].crit << "\n"; bytes3 += p.size(); s3.receive(p, t, r3); }
        }
        std::ofstream cs(out + "/v2-v3-cost-b" + std::to_string(bucket) + ".csv");
        cs << "version,critical_us,routine_us,bytes_per_reading\n";
        cs << "v2," << us2c / std::max<size_t>(n2c, 1) << "," << us2r / std::max<size_t>(n2r, 1) << "," << double(bytes2) / rd.size() << "\n";
        cs << "v3," << us3c / std::max<size_t>(n3c, 1) << "," << us3r / std::max<size_t>(n3r, 1) << "," << double(bytes3) / rd.size() << "\n";
        std::cout << "readings " << rd.size() << ", critical " << n2c << "\n";
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n"; return 2;
    }
    return fails ? 1 : 0;
}
