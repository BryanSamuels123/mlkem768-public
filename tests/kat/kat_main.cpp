// ACVP known-answer-test harness for ML-KEM-768 (spec §10.1).
//
// Parses the ACVP internalProjection JSON, runs every ML-KEM-768 group against the
// linked backend, and compares byte-for-byte. Shared by `make kat-model` and `make kat`;
// the backend is selected at link time (tests/kat/kat_backend.hpp).
//
// Field map is documented in tests/kat/PROVENANCE.md and was derived once, in Phase 0,
// so this file did not need to re-open the vectors to be written.
//
// Groups are keyed on `function`, NOT `testType`: three different functions all carry
// testType "VAL".

#include "kat_backend.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

using nlohmann::json;
using namespace mlkem768::kat;

namespace {

// ---------------------------------------------------------------------------
// Expected ML-KEM-768 case counts. A harness that silently skips every case also
// reports zero failures, so these are asserted, not merely printed.
// ---------------------------------------------------------------------------
constexpr int kExpectKeyGen      = 25;
constexpr int kExpectEncapsAFT   = 25;
constexpr int kExpectDecapsVAL   = 10;
constexpr int kExpectEkCheckVAL  = 10;
constexpr int kExpectDkCheckVAL  = 10;
constexpr int kExpectTotal = kExpectKeyGen + kExpectEncapsAFT + kExpectDecapsVAL +
                             kExpectEkCheckVAL + kExpectDkCheckVAL;   // 80

int g_pass = 0;
int g_fail = 0;

// Per-group bookkeeping, so a mutation test can see exactly which groups reacted.
// Reporting only — the comparison logic above is untouched.
struct GroupResult {
  int tgId;
  std::string testType;
  std::string function;
  int cases;
  int passed;
  int failed;
};
std::vector<GroupResult> g_groups;

// Snapshot the global counters around one group.
struct GroupScope {
  int pass0, fail0;
  GroupScope() : pass0(g_pass), fail0(g_fail) {}
  void record(const json& g, const char* fn, int n) {
    g_groups.push_back(GroupResult{g.value("tgId", -1), g.value("testType", "?"),
                                   fn, n, g_pass - pass0, n - (g_pass - pass0)});
  }
};

std::vector<std::uint8_t> unhex(const std::string& s) {
  std::vector<std::uint8_t> out;
  out.reserve(s.size() / 2);
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;   // ACVP hex is UPPERCASE
    return -1;
  };
  for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
    const int hi = nib(s[i]), lo = nib(s[i + 1]);
    if (hi < 0 || lo < 0) return {};
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

std::string tohex(const std::uint8_t* p, std::size_t n) {
  static const char* d = "0123456789ABCDEF";
  std::string s;
  s.reserve(n * 2);
  for (std::size_t i = 0; i < n; ++i) {
    s += d[p[i] >> 4];
    s += d[p[i] & 15];
  }
  return s;
}

// On mismatch: group, case id, field, first differing byte offset, and a bounded hex
// diff. Printing 2400 bytes of hex twice helps nobody.
void report_mismatch(const char* group, int tcid, const char* field,
                     const std::uint8_t* got, const std::vector<std::uint8_t>& want) {
  ++g_fail;
  std::size_t off = 0;
  while (off < want.size() && got[off] == want[off]) ++off;

  std::printf("\n  FAIL  %s tcId=%d field=%s\n", group, tcid, field);
  std::printf("        length %zu, first differing byte at offset %zu\n", want.size(), off);

  const std::size_t start = (off > 8) ? off - 8 : 0;
  const std::size_t len = (want.size() - start < 24) ? want.size() - start : 24;
  std::printf("        expected[%zu..] %s\n", start, tohex(want.data() + start, len).c_str());
  std::printf("        actual  [%zu..] %s\n", start, tohex(got + start, len).c_str());
  std::printf("                        %*s^^\n", static_cast<int>((off - start) * 2), "");
}

bool expect_bytes(const char* group, int tcid, const char* field,
                  const std::uint8_t* got, const std::vector<std::uint8_t>& want) {
  if (want.empty()) {
    std::printf("\n  FAIL  %s tcId=%d field=%s missing or unparsable in vectors\n",
                group, tcid, field);
    ++g_fail;
    return false;
  }
  if (std::memcmp(got, want.data(), want.size()) == 0) return true;
  report_mismatch(group, tcid, field, got, want);
  return false;
}

// ---------------------------------------------------------------------------
// Group runners
// ---------------------------------------------------------------------------

int run_keygen(const json& g) {
  const Backend& be = backend();
  int n = 0;
  for (const auto& t : g.at("tests")) {
    const int tcid = t.at("tcId").get<int>();
    const auto d = unhex(t.at("d").get<std::string>());
    const auto z = unhex(t.at("z").get<std::string>());
    const auto want_ek = unhex(t.at("ek").get<std::string>());
    const auto want_dk = unhex(t.at("dk").get<std::string>());

    std::vector<std::uint8_t> ek(EK_BYTES), dk(DK_BYTES);
    be.keygen_internal(d.data(), z.data(), ek.data(), dk.data());

    // Both are checked deliberately — not short-circuited — so a case with two bad
    // fields reports both rather than hiding the second behind the first.
    const bool ek_ok = expect_bytes("keyGen", tcid, "ek", ek.data(), want_ek);
    const bool dk_ok = expect_bytes("keyGen", tcid, "dk", dk.data(), want_dk);
    if (ek_ok && dk_ok) ++g_pass;
    ++n;
  }
  return n;
}

int run_encaps_aft(const json& g) {
  const Backend& be = backend();
  int n = 0;
  for (const auto& t : g.at("tests")) {
    const int tcid = t.at("tcId").get<int>();
    const auto ek = unhex(t.at("ek").get<std::string>());
    const auto m = unhex(t.at("m").get<std::string>());
    const auto want_c = unhex(t.at("c").get<std::string>());
    const auto want_k = unhex(t.at("k").get<std::string>());   // lowercase k

    std::vector<std::uint8_t> ct(CT_BYTES), ss(SS_BYTES);
    be.encaps_internal(ek.data(), m.data(), ct.data(), ss.data());

    // Both checked deliberately; see run_keygen.
    const bool c_ok = expect_bytes("encaps/AFT", tcid, "c", ct.data(), want_c);
    const bool k_ok = expect_bytes("encaps/AFT", tcid, "k", ss.data(), want_k);
    if (c_ok && k_ok) ++g_pass;
    ++n;
  }
  return n;
}

// Includes the implicit-rejection cases: 5 of these 10 carry
// reason == "modified ciphertext" and expect K = J(z || c). They are the ONLY automated
// check that implicit rejection works, so they are never filtered out.
int run_decaps_val(const json& g) {
  const Backend& be = backend();
  int n = 0, rejects = 0;
  for (const auto& t : g.at("tests")) {
    const int tcid = t.at("tcId").get<int>();
    const auto dk = unhex(t.at("dk").get<std::string>());
    const auto c = unhex(t.at("c").get<std::string>());
    const auto want_k = unhex(t.at("k").get<std::string>());
    const std::string reason = t.value("reason", "");
    if (reason == "modified ciphertext") ++rejects;

    std::vector<std::uint8_t> ss(SS_BYTES);
    be.decaps_internal(dk.data(), c.data(), ss.data());

    if (expect_bytes("decaps/VAL", tcid, "k", ss.data(), want_k)) ++g_pass;
    ++n;
  }
  if (rejects == 0) {
    std::printf("\n  FAIL  decaps/VAL contained NO implicit-rejection cases — the only\n"
                "        automated check of implicit rejection is missing.\n");
    ++g_fail;
  } else {
    std::printf("    (%d of %d are implicit-rejection cases)\n", rejects, n);
  }
  return n;
}

// The two KeyCheck groups expect a boolean `testPassed` rather than bytes. They give
// free KAT coverage of the §7.2 modulus check and the §7.3 hash check.
int run_key_check(const json& g, bool encaps_key) {
  const Backend& be = backend();
  const char* group = encaps_key ? "encapsKeyCheck/VAL" : "decapsKeyCheck/VAL";
  const char* field = encaps_key ? "ek" : "dk";
  int n = 0;
  for (const auto& t : g.at("tests")) {
    const int tcid = t.at("tcId").get<int>();
    const auto key = unhex(t.at(field).get<std::string>());
    const bool want = t.at("testPassed").get<bool>();

    const bool got = encaps_key ? be.check_encaps_key(key.data(), key.size())
                                : be.check_decaps_key(key.data(), key.size());
    if (got == want) {
      ++g_pass;
    } else {
      std::printf("\n  FAIL  %s tcId=%d  expected testPassed=%s, got %s  (reason: %s)\n",
                  group, tcid, want ? "true" : "false", got ? "true" : "false",
                  t.value("reason", "<none>").c_str());
      ++g_fail;
    }
    ++n;
  }
  return n;
}

json load(const char* path) {
  std::FILE* f = std::fopen(path, "rb");
  if (!f) {
    std::printf("ERROR: cannot open %s\n", path);
    std::exit(2);
  }
  std::string buf;
  char chunk[65536];
  std::size_t got;
  while ((got = std::fread(chunk, 1, sizeof chunk, f)) > 0) buf.append(chunk, got);
  std::fclose(f);
  return json::parse(buf);
}

}  // namespace

int main(int argc, char** argv) {
  const char* dir = (argc > 1) ? argv[1] : "tests/kat/vectors";
  const std::string keygen_path =
      std::string(dir) + "/ML-KEM-keyGen-FIPS203-internalProjection.json";
  const std::string encdec_path =
      std::string(dir) + "/ML-KEM-encapDecap-FIPS203-internalProjection.json";

  const Backend& be = backend();
  std::printf("ACVP ML-KEM-768 KAT  —  backend: %s\n", be.name);
  std::printf("vectors: %s\n\n", dir);

  int n_keygen = 0, n_encaps = 0, n_decaps = 0, n_ekchk = 0, n_dkchk = 0;

  {
    const json j = load(keygen_path.c_str());
    for (const auto& g : j.at("testGroups")) {
      if (g.value("parameterSet", "") != "ML-KEM-768") continue;   // 512/1024 filtered out
      { GroupScope sc; const int n = run_keygen(g); sc.record(g, "keyGen", n); n_keygen += n; }
    }

  }

  {
    const json j = load(encdec_path.c_str());
    for (const auto& g : j.at("testGroups")) {
      if (g.value("parameterSet", "") != "ML-KEM-768") continue;
      const std::string fn = g.value("function", "");
      GroupScope sc;
      if (fn == "encapsulation") {
        const int n = run_encaps_aft(g);      sc.record(g, "encapsulation", n);        n_encaps += n;
      } else if (fn == "decapsulation") {
        const int n = run_decaps_val(g);      sc.record(g, "decapsulation", n);        n_decaps += n;
      } else if (fn == "encapsulationKeyCheck") {
        const int n = run_key_check(g, true); sc.record(g, "encapsulationKeyCheck", n); n_ekchk += n;
      } else if (fn == "decapsulationKeyCheck") {
        const int n = run_key_check(g, false); sc.record(g, "decapsulationKeyCheck", n); n_dkchk += n;
      }
      else {
        std::printf("  WARNING: unhandled function %s (tgId %d) — not exercised\n",
                    fn.c_str(), g.value("tgId", -1));
      }
    }

  }

  const int total = n_keygen + n_encaps + n_decaps + n_ekchk + n_dkchk;

  // Per-group breakdown. Printed always, pass or fail: it is how you confirm every
  // group is actually represented rather than silently skipped.
  std::printf("\n  %-5s %-8s %-24s %6s %6s %6s\n",
              "tgId", "testType", "function", "cases", "pass", "fail");
  std::printf("  %-5s %-8s %-24s %6s %6s %6s\n",
              "----", "--------", "------------------------", "-----", "----", "----");
  for (const auto& r : g_groups) {
    std::printf("  %-5d %-8s %-24s %6d %6d %6d\n", r.tgId, r.testType.c_str(),
                r.function.c_str(), r.cases, r.passed, r.failed);
  }
  std::printf("  %-5s %-8s %-24s %6d %6d %6d\n", "", "", "TOTAL", total, g_pass,
              total - g_pass);

  // Count assertions: a harness that runs nothing must not report success.
  bool counts_ok = true;
  auto check_count = [&](const char* what, int got, int want) {
    if (got != want) {
      std::printf("\nERROR: %s ran %d cases, expected %d "
                  "(see tests/kat/PROVENANCE.md)\n", what, got, want);
      counts_ok = false;
    }
  };
  check_count("keyGen", n_keygen, kExpectKeyGen);
  check_count("encaps/AFT", n_encaps, kExpectEncapsAFT);
  check_count("decaps/VAL", n_decaps, kExpectDecapsVAL);
  check_count("encapsKeyCheck/VAL", n_ekchk, kExpectEkCheckVAL);
  check_count("decapsKeyCheck/VAL", n_dkchk, kExpectDkCheckVAL);
  check_count("total", total, kExpectTotal);

  std::printf("\n");
  if (g_fail == 0 && counts_ok && total == kExpectTotal) {
    std::printf("PASS %d/%d\n", g_pass, kExpectTotal);
    return 0;
  }
  std::printf("FAIL: %d passed, %d failed, of %d cases run (expected %d)\n",
              g_pass, g_fail, total, kExpectTotal);
  return 1;
}
