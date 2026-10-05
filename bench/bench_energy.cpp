// Energy-per-operation harness, for a later CPU-vs-FPGA comparison.
//
// Runs a fixed schedule with a printed wall-clock timestamp at every phase boundary, so
// a concurrently-running `powermetrics` capture can be split into phases afterwards.
// Deterministic entry points on both sides, as in the head-to-head benchmark.
//
// Operations completed per phase are counted, and throughput is reported for the first
// and second half of each compute phase separately -- a sustained run on a laptop can
// thermally throttle, and a figure that drifts within its own phase must be labelled.
#include "kem.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <vector>
extern "C" {
int pqcrystals_kyber768_avx2_keypair_derand(uint8_t*, uint8_t*, const uint8_t*);
int pqcrystals_kyber768_avx2_enc_derand(uint8_t*, uint8_t*, const uint8_t*, const uint8_t*);
int pqcrystals_kyber768_avx2_dec(uint8_t*, const uint8_t*, const uint8_t*);
}
using namespace mlkem768;
using clk = std::chrono::steady_clock;
static volatile int sink = 0;

static void stamp(const char* tag) {
  const auto now = std::chrono::system_clock::now();
  const auto t = std::chrono::system_clock::to_time_t(now);
  const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
      now.time_since_epoch()).count() % 1000000;
  char b[32]; std::strftime(b, sizeof b, "%H:%M:%S", std::localtime(&t));
  std::printf("PHASE %-18s %s.%06lld\n", tag, b, static_cast<long long>(us));
  std::fflush(stdout);
}

static void idle(const char* tag, int secs) {
  stamp(tag);
  const auto end = clk::now() + std::chrono::seconds(secs);
  while (clk::now() < end) {
    struct timespec ts{0, 50'000'000};   // 50 ms; sleeping, not spinning
    nanosleep(&ts, nullptr);
  }
}

template <typename F>
static void run(const char* tag, int secs, F&& f) {
  stamp(tag);
  const auto t0 = clk::now();
  const auto mid = t0 + std::chrono::seconds(secs / 2);
  const auto end = t0 + std::chrono::seconds(secs);
  long long n = 0, nmid = 0;
  bool took_mid = false;
  while (clk::now() < end) {
    for (int i = 0; i < 64; ++i) f();
    n += 64;
    if (!took_mid && clk::now() >= mid) { nmid = n; took_mid = true; }
  }
  const double el = std::chrono::duration<double>(clk::now() - t0).count();
  const double h1 = static_cast<double>(nmid) / (el / 2.0);
  const double h2 = static_cast<double>(n - nmid) / (el / 2.0);
  std::printf("COUNT %-18s ops=%lld  elapsed=%.3fs  ops/s=%.1f  "
              "firsthalf=%.1f secondhalf=%.1f drift=%+.1f%%\n",
              tag, n, el, n / el, h1, h2, 100.0 * (h2 - h1) / h1);
  std::fflush(stdout);
}

int main() {
  std::uint8_t d[32], z[32], m[32], coins[64];
  for (int i = 0; i < 32; ++i) { d[i] = (std::uint8_t)i; z[i] = (std::uint8_t)(i + 64);
                                 m[i] = (std::uint8_t)(i * 3 + 1); }
  std::memcpy(coins, d, 32); std::memcpy(coins + 32, z, 32);
  std::vector<std::uint8_t> ek(EK_BYTES), dk(DK_BYTES), ct(CT_BYTES), ss(SS_BYTES);
  keygen_internal(d, z, ek.data(), dk.data());
  encaps_internal(ek.data(), m, ct.data(), ss.data());
  std::vector<std::uint8_t> pk(1184), sk(2400), kct(1088), kss(32);
  pqcrystals_kyber768_avx2_keypair_derand(pk.data(), sk.data(), coins);
  pqcrystals_kyber768_avx2_enc_derand(kct.data(), kss.data(), pk.data(), m);

  std::printf("SCHEDULE total 280 s\n"); std::fflush(stdout);
  idle("idle_start", 30);
  run("ours_keygen", 30, [&]{ std::uint8_t e[EK_BYTES], k[DK_BYTES];
                              keygen_internal(d, z, e, k); sink ^= e[0]; });
  idle("idle_1", 10);
  run("ours_encaps", 30, [&]{ std::uint8_t c[CT_BYTES], s[SS_BYTES];
                              encaps_internal(ek.data(), m, c, s); sink ^= s[0]; });
  idle("idle_2", 10);
  run("ours_decaps", 30, [&]{ std::uint8_t s[SS_BYTES];
                              decaps_internal(dk.data(), ct.data(), s); sink ^= s[0]; });
  idle("idle_3", 10);
  run("kyber_keygen", 30, [&]{ std::uint8_t p[1184], s[2400];
                               pqcrystals_kyber768_avx2_keypair_derand(p, s, coins); sink ^= p[0]; });
  idle("idle_4", 10);
  run("kyber_encaps", 30, [&]{ std::uint8_t c[1088], s[32];
                               pqcrystals_kyber768_avx2_enc_derand(c, s, pk.data(), m); sink ^= s[0]; });
  idle("idle_5", 10);
  run("kyber_decaps", 30, [&]{ std::uint8_t s[32];
                               pqcrystals_kyber768_avx2_dec(s, kct.data(), sk.data()); sink ^= s[0]; });
  idle("idle_end", 30);
  stamp("done");
  return 0;
}
