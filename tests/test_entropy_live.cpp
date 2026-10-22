// LiveEntropy: a continuous, policy-gated source for a stream; and the
// floor-calibrated health cutoffs that make a real photo pass.
#include "test_framework.hpp"
#include "../bridge/cryptolib_c.h"
using namespace test;
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <sodium.h>
#include <vector>

using crypto::entropy::HealthReport;
using crypto::entropy::LiveEntropy;
using crypto::entropy::SourcePolicy;
using crypto::entropy::assess_health;

namespace {
std::vector<uint8_t> noise(std::size_t n) {
    std::vector<uint8_t> v(n);
    randombytes_buf(v.data(), n);
    return v;
}
std::vector<uint8_t> flat(std::size_t n, uint8_t b = 0) { return std::vector<uint8_t>(n, b); }
}  // namespace

TEST("health/rct-cutoff-follows-the-floor-not-the-measurement") {
    // Noise with a 10-byte zero run, like EXIF padding in a photo file.
    auto v = noise(65536);
    for (std::size_t i = 100; i < 110; ++i) v[i] = 0;
    auto h1 = assess_health({ v.data(), v.size() }, 1.0);
    CHECK(h1.rct_cutoff == 31);
    CHECK(h1.longest_run == 10);
    CHECK(h1.rct_passed);
    CHECK(h1.floor_bits_per_byte == 1.0);
    CHECK(h1.sample_bytes == 65536);
    CHECK(h1.apt_cutoff > 0 && h1.apt_window == 512);
    auto h4 = assess_health({ v.data(), v.size() }, 4.0);
    CHECK(h4.rct_cutoff == 9);
    CHECK(!h4.rct_passed);
    auto flat_h = assess_health(std::vector<uint8_t>(4096, 0), 1.0);
    CHECK(!flat_h.rct_passed);
    CHECK(flat_h.longest_run == 4096);
}

TEST("health/explain-and-refusals-carry-every-number") {
    auto v = noise(65536);
    for (std::size_t i = 0; i < 40; ++i) v[i] = 7;
    auto h = assess_health({ v.data(), v.size() }, 1.0);
    const auto text = h.explain();
    CHECK(text.find("cutoff 31") != std::string::npos);
    CHECK(text.find("longest run of one byte 40") != std::string::npos);
    CHECK(text.find("policy floor 1.00") != std::string::npos);
    SourcePolicy strict;
    const auto why = strict.reject(h);
    CHECK(why.find("run of 40 identical bytes") != std::string::npos);
    CHECK(why.find("cutoff for the 1.00 bits/byte floor is 31") != std::string::npos);
    CHECK(why.find("require_rct=false") != std::string::npos);
    SourcePolicy reported{1.0, false, false};
    CHECK(reported.reject(h).empty());
    auto weak = assess_health(std::vector<uint8_t>(4096, 0), 1.0);
    const auto why2 = strict.reject(weak);
    CHECK(why2.find("below the policy floor of 1.00") != std::string::npos);
    CHECK(why2.find("most-common-value") != std::string::npos);
}

TEST("live/fails-closed-until-credited-then-flows") {
    LiveEntropy live(SourcePolicy::strict(), 256.0);
    auto early = live.generate(32);
    CHECK(early.is_err());
    CHECK(early.error().message.find("not ready") != std::string::npos);
    auto r1 = live.feed(flat(4096));
    CHECK(!r1.accepted);
    CHECK(r1.credited_bits == 0.0);
    CHECK(r1.reason.find("mixed in but not credited") != std::string::npos);
    auto r2 = live.feed(noise(4096), 1);
    CHECK(r2.accepted);
    CHECK(r2.credited_bits > 256.0);
    CHECK(r2.ready);
    auto a = std::move(live.generate(32).value());
    auto b = std::move(live.generate(32).value());
    CHECK(a.size() == 32 && b.size() == 32);
    CHECK(!std::equal(a.data(), a.data() + 32, b.data()));
    auto s = live.status();
    CHECK(s.chunks_fed == 2 && s.chunks_accepted == 1 && s.chunks_rejected == 1);
    CHECK(s.reseeds == 1);
    CHECK(s.ready);
    CHECK(s.last_health.rct_passed);
}

TEST("live/reseeds-as-credit-arrives-and-rejects-small-chunks") {
    LiveEntropy live(SourcePolicy::strict(), 256.0);
    (void)live.feed(noise(4096));
    (void)live.generate(16).value();
    CHECK(live.status().reseeds == 1);
    (void)live.feed(noise(4096));
    CHECK(live.status().credited_bits_since_reseed > 256.0);
    (void)live.generate(16).value();
    CHECK(live.status().reseeds == 2);
    CHECK(live.status().credited_bits_since_reseed == 0.0);
    auto small = live.feed(noise(100));
    CHECK(!small.accepted);
    CHECK(small.reason.find("below the 1024-byte minimum") != std::string::npos);
}

TEST("live/run-carried-across-chunk-boundaries") {
    LiveEntropy live(SourcePolicy::strict(), 256.0);
    // The bytes next to the planted runs are pinned so the runs are exact:
    // random neighbours would extend them one time in 256.
    auto head = noise(4096);
    for (std::size_t i = 4096 - 20; i < 4096; ++i) head[i] = 0x55;
    head[4096 - 21] = 0xAA;
    auto tail = noise(4096);
    for (std::size_t i = 0; i < 20; ++i) tail[i] = 0x55;
    tail[20] = 0xAA;
    auto r1 = live.feed(head);
    CHECK(r1.accepted);
    CHECK(r1.health.longest_run == 20);
    auto r2 = live.feed(tail);
    CHECK(r2.health.longest_run == 40);
    CHECK(!r2.accepted);
    CHECK(r2.reason.find("run of 40 identical bytes") != std::string::npos);
    auto r3 = live.feed(noise(4096));
    CHECK(r3.accepted);
}

TEST("live/two-sources-never-agree") {
    LiveEntropy a(SourcePolicy::permissive(), 64.0), b(SourcePolicy::permissive(), 64.0);
    auto same = noise(4096);
    (void)a.feed(same);
    (void)b.feed(same);
    auto x = std::move(a.generate(32).value());
    auto y = std::move(b.generate(32).value());
    CHECK(!std::equal(x.data(), x.data() + 32, y.data()));
}

TEST("c-abi/live-entropy-and-health-v2") {
    char* err = nullptr;
    auto* h = cryptolib_live_entropy_new(1.0, 1, 0.0, &err);
    CHECK(h != nullptr && err == nullptr);
    auto early = cryptolib_live_entropy_generate(h, 32);
    CHECK(early.error != nullptr);
    cryptolib_str_free(early.error);
    auto zeros = flat(4096);
    auto r1 = cryptolib_live_entropy_feed(h, zeros.data(), zeros.size(), 0);
    CHECK(r1.accepted == 0 && r1.reason != nullptr && r1.error == nullptr);
    CHECK(r1.rct_cutoff == 31 && r1.longest_run == 4096);
    cryptolib_str_free(r1.reason);
    auto rnd = noise(8192);
    auto r2 = cryptolib_live_entropy_feed(h, rnd.data(), rnd.size(), 1);
    CHECK(r2.accepted == 1 && r2.reason == nullptr && r2.ready == 1);
    CHECK(r2.credited_bits > 256.0);
    auto out = cryptolib_live_entropy_generate(h, 32);
    CHECK(out.error == nullptr && out.buf.len == 32);
    cryptolib_buffer_free(&out.buf);
    auto st = cryptolib_live_entropy_status(h);
    CHECK(st.error == nullptr && st.chunks_fed == 2 && st.chunks_accepted == 1 && st.reseeds == 1);
    CHECK(st.ready == 1 && st.last_reason == nullptr);
    cryptolib_live_entropy_free(h);
    auto bad = cryptolib_live_entropy_feed(nullptr, rnd.data(), rnd.size(), 0);
    CHECK(bad.error != nullptr);
    cryptolib_str_free(bad.error);

    const auto dir = std::filesystem::temp_directory_path() / "cl_live_health";
    std::filesystem::create_directories(dir);
    const auto path = dir / "noise.bin";
    { std::ofstream f(path, std::ios::binary); f.write(reinterpret_cast<const char*>(rnd.data()), 8192); }
    auto hr = cryptolib_entropy_assess_file_health_v2(path.string().c_str(), 0, 1.0);
    CHECK(hr.error == nullptr && hr.summary != nullptr);
    CHECK(hr.rct_cutoff == 31 && hr.sample_bytes == 8192 && hr.rct_passed == 1);
    CHECK(std::string(hr.summary).find("cutoff 31") != std::string::npos);
    cryptolib_str_free(hr.summary);
    auto missing = cryptolib_entropy_assess_file_health_v2("/nonexistent/file", 0, 1.0);
    CHECK(missing.error != nullptr && missing.summary == nullptr);
    cryptolib_str_free(missing.error);
    std::filesystem::remove_all(dir);
}

void run_tests_entropy_live() {
    RUN("health/rct-cutoff-follows-the-floor-not-the-measurement");
    RUN("health/explain-and-refusals-carry-every-number");
    RUN("live/fails-closed-until-credited-then-flows");
    RUN("live/reseeds-as-credit-arrives-and-rejects-small-chunks");
    RUN("live/run-carried-across-chunk-boundaries");
    RUN("live/two-sources-never-agree");
    RUN("c-abi/live-entropy-and-health-v2");
}
