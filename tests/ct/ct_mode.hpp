#pragma once
// Mode dispatch shared by every constant-time binary.
//
// WHY THIS EXISTS. ct_keccak used to treat any unrecognized argument as "run the default
// path", so `ct_keccak --sefltest` silently ran the CLEAN checks and exited 0. For a
// clean-expected mode that is a VACUOUS PASS: the typo runs something else, the something
// else is clean, and the gate reports success while never testing what it claims.
//
// Phase 6a adds several new modes, which multiplies the chance of exactly that typo.
//
// Two rules enforced here:
//   1. There is NO default mode. Exactly one argument, and it must be a known name.
//      Anything else -- unknown, missing, or extra -- exits nonzero and lists the modes.
//   2. Every run prints "CT-MODE: <name>" before doing any work. The Makefile asserts on
//      that banner, so a target cannot pass unless the mode it INTENDED actually ran.
//
// Exit codes: 0 clean, 2 usage error. valgrind's --error-exitcode=99 signals findings,
// so 99 must never collide with a usage path.

#include <cstdio>
#include <cstddef>
#include <cstring>

namespace ctmode {

struct Mode {
  const char* name;
  int (*run)();
  const char* expectation;   // "clean" or "findings expected" -- printed in usage
};

inline void print_usage(const char* binary, const Mode* modes, std::size_t n) {
  std::fprintf(stderr, "usage: %s <mode>\n\nmodes:\n", binary);
  for (std::size_t i = 0; i < n; ++i)
    std::fprintf(stderr, "  %-22s %s\n", modes[i].name, modes[i].expectation);
  std::fprintf(stderr,
               "\nThere is no default mode: an unknown or missing mode exits 2 rather\n"
               "than running something else and passing vacuously.\n");
}

inline int dispatch(int argc, char** argv, const Mode* modes, std::size_t n,
                    const char* binary) {
  if (argc != 2) {
    std::fprintf(stderr, "%s: expected exactly one mode argument, got %d\n",
                 binary, argc - 1);
    print_usage(binary, modes, n);
    return 2;
  }
  for (std::size_t i = 0; i < n; ++i) {
    if (std::strcmp(argv[1], modes[i].name) == 0) {
      // The banner the Makefile asserts on. Printed BEFORE the work so it survives
      // even if the mode later crashes.
      std::printf("CT-MODE: %s\n", modes[i].name);
      std::fflush(stdout);
      return modes[i].run();
    }
  }
  std::fprintf(stderr, "%s: unknown mode '%s'\n", binary, argv[1]);
  print_usage(binary, modes, n);
  return 2;
}

}  // namespace ctmode
