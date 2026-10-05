# ML-KEM-768 (FIPS 203) — see docs/spec/MLKEM768_SPEC.md §13 for the target contract.

# ---------------------------------------------------------------------------
# REQUIRE GNU Make >= 4.0.  Hard error, never a warning.
# ---------------------------------------------------------------------------
#
# macOS ships GNU Make 3.81 (2006), which compares file timestamps at 1-SECOND
# granularity. An edit landing in the same second as the previous build is invisible
# to it, so it reuses a stale object and the binary silently does not contain your
# change. This has produced a plausible WRONG ANSWER twice in this project:
#
#   * sanitizer objects reused across differing flag sets (Phase 1 pre-flight)
#   * KAT mutation N re-running mutation N-1's binary, reporting N-1's signature
#     and making the harness look less sensitive than it is (tests/kat/MUTATION.md)
#
# Phase 2's edit-test loop is exactly where this is most dangerous: a stale object
# makes a FAILING differential test report GREEN. Refuse to build rather than risk it.
#
# Verified on this host: 3.81 misses a same-second edit; 4.4.1 rebuilds correctly.

MAKE_MAJOR := $(word 1,$(subst ., ,$(MAKE_VERSION)))

ifneq ($(shell test "$(MAKE_MAJOR)" -ge 4 2>/dev/null && echo ok),ok)
$(info )
$(info ===========================================================================)
$(info  ERROR: GNU Make $(MAKE_VERSION) is too old. This project requires >= 4.0.)
$(info )
$(info  Make 3.81 compares mtimes at 1-second granularity and will silently reuse)
$(info  stale object files after a same-second edit, producing a binary that does)
$(info  not contain your change. That has already caused two wrong-but-plausible)
$(info  results here; see tests/kat/MUTATION.md.)
$(info )
$(info  Use gmake instead:)
$(info )
$(info      brew install make      # installs GNU Make 4.x as `gmake`)
$(info      gmake test)
$(info      gmake kat-model)
$(info )
$(info  Or put it first on PATH for this shell:)
$(info      PATH="/usr/local/opt/make/libexec/gnubin:$$PATH")
$(info ===========================================================================)
$(info )
$(error unsupported GNU Make version)
endif
#
# Phase 0 status: the build graph, the flag sets, and the two flag exceptions (§13) are
# wired. Targets whose deliverable belongs to a later phase fail loudly naming that phase
# rather than silently succeeding — a green target that does nothing is worse than no
# target at all.

# ---------------------------------------------------------------------------
# Variables (§13: CXX, CXXFLAGS, PREFIX, CPU, DEBUG)
# ---------------------------------------------------------------------------

# Pinned rather than left to make's builtin default: GNU Make defaults CXX/CC per
# platform (clang++ on macOS, g++ elsewhere; cc for C), so an unpinned compiler
# silently differs between the host and the Linux container.
#
# `?=` is NOT enough: make's builtins are already "defined", so ?= leaves them alone.
# Overriding only when the origin is `default` keeps a command-line or environment
# CXX=... working while still beating the builtin.
ifeq ($(origin CXX),default)
CXX := clang++
endif
ifeq ($(origin CC),default)
CC := clang
endif
PREFIX   ?= /usr/local
CPU      ?= portable          # portable | avx2 | avx512 | native
DEBUG    ?= 0
BUILD    ?= build

# Baseline flags for the LIBRARY (§13). Exception-free, RTTI-free, hidden visibility.
CXXSTD   ?= -std=c++20
WARN      = -Wall -Wextra -Wpedantic -Werror

# The library flag set. NOT `?=`.
#
# `CXXFLAGS ?=` looks safe but is not: an EXPORTED CXXFLAGS from the environment counts
# as "already defined", so `?=` leaves it alone and the entire set -- -Werror,
# -fno-exceptions, -fno-rtti, -fvisibility=hidden -- silently disappears. The build
# still succeeds, and a stray `export CXXFLAGS=-O0` in a shell profile would quietly
# ship a library compiled with none of the guarantees this project depends on.
#
# Same failure shape as CC/CXX earlier: make's builtins count as defined, so `?=` never
# fired and CC silently stayed `cc`.
#
# Environment is therefore IGNORED for this variable. A command-line
# `gmake CXXFLAGS=...` still wins (make command-line variables beat plain `=`), which
# is the documented override in spec §13; the sanitizer targets rely on it.
CXXFLAGS = $(CXXSTD) -O3 $(WARN) -fno-exceptions -fno-rtti -fvisibility=hidden

ifeq ($(DEBUG),1)
  CXXFLAGS = $(CXXSTD) -O0 -g $(WARN) -fno-exceptions -fno-rtti -fvisibility=hidden
  CPPFLAGS += -DMLKEM_DEBUG=1
else
  CPPFLAGS += -DNDEBUG
endif

# -march=native is NEVER in the default flags (§9.4): it SIGILLs on other machines.
# `make CPU=native` opts in, for local benchmarking only.
ifeq ($(CPU),native)
  ARCHFLAGS = -march=native
endif

CPPFLAGS += -Iinclude -Isrc -Ithird_party/fips202

# Appended to every compile. A command-line CPPFLAGS= would REPLACE the include paths
# above (command-line variables beat `+=`), so instrumented builds use this instead.
EXTRA_CPPFLAGS ?=
DEPFLAGS  = -MMD -MP

# --- FLAG EXCEPTION 1 (§13): test and bench TUs need exceptions --------------
# doctest uses exceptions for assertion reporting and will not compile under
# -fno-exceptions. The LIBRARY stays exception-free; only the harness links with them.
TEST_CXXFLAGS = $(filter-out -fno-exceptions -fno-rtti,$(CXXFLAGS))
# Test TUs legitimately exercise the deterministic _internal interfaces (spec §3.1
# permits exactly that: "other than for testing purposes"). The LIBRARY build never
# defines this, so an application including kem.hpp gets no declaration.
TEST_CPPFLAGS = $(CPPFLAGS) -DMLKEM_ENABLE_INTERNAL_API=1 \
                -Ithird_party/doctest -Ithird_party -Itests -Itests/model -Itests/kat

# --- FLAG EXCEPTION 2 (§13): vendored third-party C gets relaxed warnings ----
# Vendored Keccak is C written to different conventions and will not survive
# -Werror -Wpedantic. Never reformat these files: their value is being byte-identical
# to an audited upstream. They are excluded from `make format`.
#
# INSTRUMENTATION STILL APPLIES. The exception is about WARNINGS, not about sanitizers:
# MSan reports every byte produced by UNinstrumented code as uninitialized, so leaving
# the vendored Keccak out of -fsanitize=memory made `docker-msan` fail the moment
# Phase 3 linked it in -- every H/G/J output looked poisoned. SANITIZE_FLAGS is set by
# the asan/ubsan/msan targets and reaches both C++ and vendored C.
SANITIZE_FLAGS ?=
THIRDPARTY_CFLAGS = -O3 -Wall $(SANITIZE_FLAGS)
THIRDPARTY_CPPFLAGS = -Ithird_party/fips202

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

LIB_SRCS  = $(wildcard src/*.cpp) $(wildcard src/arch/*.cpp) \
            $(wildcard src/arch/generic/*.cpp)

# AVX2 translation units, compiled with -mavx2 and reached only after cpuid says the
# CPU supports it (spec §9.4). NEVER -march=native: that SIGILLs on other machines.
AVX2_SRCS = $(wildcard src/arch/avx2/*.cpp)
AVX2_OBJS = $(AVX2_SRCS:%.cpp=$(BUILD)/%.o)
AVX2_CSRCS = third_party/fips202/fips202x4.c \
             third_party/fips202/keccak4x/KeccakP-1600-times4-SIMD256.c
AVX2_COBJS = $(AVX2_CSRCS:%.c=$(BUILD)/%.avx2.o)
AVX2_FLAGS = -mavx2 -mbmi2 -mfma

# Vendored C, built with THIRDPARTY_CFLAGS (flag exception 2, §13): no -Werror, no
# -Wpedantic, never reformatted, excluded from `format`. Scalar FIPS 202 only --
# the 4-way batched path (fips202x4) is Phase 8 and is deliberately NOT wired yet.
# Baseline-compiled vendored C. The 4-way AVX2 path is EXCLUDED here and built by the
# .avx2.o rule below with -mavx2; compiling it at baseline fails outright, which is the
# desired failure mode rather than a silently scalar build.
THIRDPARTY_SRCS = $(filter-out third_party/fips202/fips202x4.c, \
                    $(wildcard third_party/fips202/*.c))
THIRDPARTY_OBJS = $(THIRDPARTY_SRCS:%.c=$(BUILD)/%.o)

LIB_OBJS  = $(LIB_SRCS:%.cpp=$(BUILD)/%.o) $(THIRDPARTY_OBJS) \
            $(AVX2_OBJS) $(AVX2_COBJS)
LIB       = $(BUILD)/libmlkem768.a

UNIT_SRCS = $(wildcard tests/unit/*.cpp)
UNIT_OBJS = $(UNIT_SRCS:%.cpp=$(BUILD)/%.o)
UNIT_BIN  = $(BUILD)/test_unit

# Golden model (spec §10.2). Test-only; never linked into libmlkem768.a.
MODEL_SRCS = $(wildcard tests/model/*.cpp)
MODEL_OBJS = $(MODEL_SRCS:%.cpp=$(BUILD)/%.o)

# ACVP KAT harness (spec §10.1). One harness, two backends, selected at link time.
KAT_SRCS       = tests/kat/kat_main.cpp
KAT_OBJS       = $(KAT_SRCS:%.cpp=$(BUILD)/%.o)
KAT_MODEL_OBJS = $(BUILD)/tests/kat/backend_model.o
KAT_MODEL_BIN  = $(BUILD)/kat_model
KAT_IMPL_BIN   = $(BUILD)/kat_impl

DEPS = $(LIB_OBJS:.o=.d) $(THIRDPARTY_OBJS:.o=.d) $(UNIT_OBJS:.o=.d) $(MODEL_OBJS:.o=.d) $(KAT_OBJS:.o=.d) $(KAT_MODEL_OBJS:.o=.d)

# ---------------------------------------------------------------------------
# Primary targets
# ---------------------------------------------------------------------------

.PHONY: all
all: $(LIB)

$(LIB): $(LIB_OBJS)
	@mkdir -p $(dir $@)
	$(AR) rcs $@ $^
	@echo "  AR    $@"

$(BUILD)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(ARCHFLAGS) $(CPPFLAGS) $(EXTRA_CPPFLAGS) $(DEPFLAGS) -c $< -o $@

# Test TUs: relaxed flags (exception 1). Pattern-specific variables override the above.
$(BUILD)/tests/%.o: CXXFLAGS := $(TEST_CXXFLAGS)
$(BUILD)/tests/%.o: CPPFLAGS := $(TEST_CPPFLAGS)
$(BUILD)/bench/%.o:  CXXFLAGS := $(TEST_CXXFLAGS)
$(BUILD)/bench/%.o:  CPPFLAGS := $(TEST_CPPFLAGS)

# Vendored C: relaxed warnings (exception 2).
# AVX2 C: vendored 4-way Keccak. THIRDPARTY_CFLAGS (relaxed warnings, flag exception 2)
# plus the arch flags; SANITIZE_FLAGS still reaches it.
$(BUILD)/third_party/%.avx2.o: third_party/%.c
	@mkdir -p $(dir $@)
	$(CC) $(THIRDPARTY_CFLAGS) $(AVX2_FLAGS) $(THIRDPARTY_CPPFLAGS) \
	  -Ithird_party/fips202/keccak4x $(EXTRA_CPPFLAGS) $(DEPFLAGS) -c $< -o $@

# AVX2 C++: our own batched wrappers.
$(BUILD)/src/arch/avx2/%.o: src/arch/avx2/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(AVX2_FLAGS) $(CPPFLAGS) -Ithird_party/fips202/keccak4x \
	  $(EXTRA_CPPFLAGS) $(DEPFLAGS) -c $< -o $@

# The AVX2 unit test includes the AVX2 headers directly, so it needs the same flags as
# the backend itself. Without this it compiles at baseline and fails on _mm256_*.
$(BUILD)/tests/unit/test_avx2.o: tests/unit/test_avx2.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $(AVX2_FLAGS) $(TEST_CPPFLAGS) $(DEPFLAGS) -c $< -o $@
	@echo "  CXX   $@ (+AVX2)"


$(BUILD)/third_party/%.o: third_party/%.c
	@mkdir -p $(dir $@)
	$(CC) $(THIRDPARTY_CFLAGS) $(THIRDPARTY_CPPFLAGS) $(EXTRA_CPPFLAGS) $(DEPFLAGS) -c $< -o $@

.PHONY: debug
debug:
	@$(MAKE) DEBUG=1 all

# ---------------------------------------------------------------------------
# Test targets
# ---------------------------------------------------------------------------

$(UNIT_BIN): $(UNIT_OBJS) $(MODEL_OBJS) $(LIB)
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $^ $(LDFLAGS) -o $@
	@echo "  LINK  $@"

.PHONY: test
test: $(UNIT_BIN)
	@echo "=== unit tests ==="
	@$(UNIT_BIN)

# High-count differential run. The model is KAT-clean, so these differentials carry more
# statistical power than the 80 ACVP vectors do -- see docs/bounds.md "Statistical power".
# Stays wired through Phase 8: every lazy-reduction and SIMD change re-runs this at count.
MLKEM_DIFF_ITERS ?= 10000000

.PHONY: test-deep
test-deep: $(UNIT_BIN)
	@echo "=== deep differential run (MLKEM_DIFF_ITERS=$(MLKEM_DIFF_ITERS)) ==="
	@MLKEM_DIFF_ITERS=$(MLKEM_DIFF_ITERS) $(UNIT_BIN)

$(KAT_MODEL_BIN): $(KAT_OBJS) $(KAT_MODEL_OBJS) $(MODEL_OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $^ $(LDFLAGS) -o $@
	@echo "  LINK  $@"

# The real-implementation backend. Compiled with MLKEM_ENABLE_INTERNAL_API=1 (spec §3.1);
# the default `gmake` build never defines it, so keygen_internal/encaps_internal/
# decaps_internal are not reachable from a shipped libmlkem768.a consumer.
$(BUILD)/tests/kat/backend_impl.o: tests/kat/backend_impl.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $(TEST_CPPFLAGS) -DMLKEM_ENABLE_INTERNAL_API=1 \
	  $(DEPFLAGS) -c $< -o $@

$(KAT_IMPL_BIN): $(KAT_OBJS) $(BUILD)/tests/kat/backend_impl.o $(LIB)
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $^ $(LDFLAGS) -o $@
	@echo "  LINK  $@"

.PHONY: kat kat-model
# Phase 1 exit criterion and the hard gate before Phase 2 (ADR-002).
kat-model: $(KAT_MODEL_BIN) verify-vectors
	@$(KAT_MODEL_BIN) tests/kat/vectors

# Phase 7 correctness gate: the real implementation against NIST's vectors.
#
# POSITIVE CONTROL BUILT IN. `gmake kat` can fail in a way no other gate would catch:
# if the link silently picked up backend_model.o, it would report PASS 80/80 while
# testing nothing about the real library -- a vacuous pass of the most important gate in
# the project. kat_main.cpp prints the backend name, so the target ASSERTS on that
# banner. Proven to fail: see `kat-control-check`.
kat: $(KAT_IMPL_BIN) verify-vectors
	@set +e; out=$$($(KAT_IMPL_BIN) tests/kat/vectors 2>&1); rc=$$?; set -e; \
	echo "$$out"; \
	if ! echo "$$out" | grep -qF "backend: real implementation"; then \
	  echo ""; \
	  echo "FAIL: the KAT binary did not report 'backend: real implementation'."; \
	  echo "      It linked the wrong backend -- a PASS here would have been vacuous."; \
	  exit 1; \
	fi; \
	exit $$rc

# Proves the banner assertion above can actually fail, by running the MODEL binary
# through the same check. Must report FAIL.
.PHONY: kat-control-check
kat-control-check: $(KAT_MODEL_BIN)
	@set +e; out=$$($(KAT_MODEL_BIN) tests/kat/vectors 2>&1); set -e; \
	if echo "$$out" | grep -qF "backend: real implementation"; then \
	  echo "FAIL: the model binary claims to be the real implementation."; exit 1; \
	else \
	  echo "  OK: backend-identity check rejects the model binary"; \
	  echo "      (so a silently mislinked kat cannot pass)"; \
	fi

# Produces the observed-maximum column of docs/bounds.md (spec §5.4).
BOUNDS_BIN = $(BUILD)/measure_bounds

# Machine-level div/idiv audit with a built-in positive control. See tools/audit_div.sh
# for why source-level enumeration is insufficient (Phase 4 found a compiler-inserted
# division that appears nowhere in the source).
.PHONY: audit-div
audit-div: $(LIB)
	@BUILD=$(BUILD) OBJDUMP=$(OBJDUMP) CC=$(CC) sh tools/audit_div.sh

OBJDUMP ?= objdump

# Every ADR-nnn cited anywhere must resolve in DECISIONS.md. Catches DANGLING
# references only -- a resolving reference is not a TRUE one. See ADR-019.
.PHONY: audit-refs
audit-refs:
	@ROOT=. sh tools/audit_refs.sh

# Spec §8.3: secure_zero must survive -O3. Verified by disassembly, with a plain
# memset as the negative control (it is eliminated entirely). See ADR-021.
.PHONY: audit-zeroize
audit-zeroize:
	@CXX="$(CXX)" OBJDUMP=$(OBJDUMP) sh tools/audit_zeroize.sh

# audit-zeroize proves secure_zero survives -O3 IN ISOLATION. It says nothing about
# whether the Zeroizing<T> destructor actually runs at each of the 27 wrap sites --
# an inlined destructor on a large PolyVec is exactly where the optimizer could be
# cleverer than expected. This checks every site, by DWARF, at the real build flags.
# Ground truth is parsed from the .cpp sources so it is not circular. See ADR-034.
#
# Deliberately EMPTY by default: macOS has `dwarfdump`, Debian's llvm-16 ships only
# `llvm-dwarfdump-16`. Defaulting to a name means passing a nonexistent tool on one of
# the two targets, so the script probes for it instead. Set DWARFDUMP to override.
DWARFDUMP ?=
.PHONY: audit-zeroize-sites
audit-zeroize-sites:
	@CXX="$(CXX)" CXXFLAGS="$(CXXFLAGS)" CPPFLAGS="$(CPPFLAGS)" \
	  OBJDUMP=$(OBJDUMP) DWARFDUMP=$(DWARFDUMP) \
	  python3 tools/audit_zeroize_sites.py

# Builds a FULLY INSTRUMENTED library -- MLKEM_TRACK_BOUNDS on every library TU -- and
# links the measurement tool against it.
#
# The previous form compiled tools/measure_bounds.cpp against src/ntt.cpp ALONE, so it
# could not reach kpke_keygen, kpke_encrypt or anything above the arithmetic layer. That
# is how basemul's input bound stayed wrong for three phases: the harness ran ntt()
# first, barrett-reducing the input before basemul ever saw a canonical A_hat.
# A measurement harness that cannot reproduce the real call shape measures the wrong
# thing, so from Phase 6a it measures the real K-PKE path.
BOUNDS_BUILD = $(BUILD)/bounds

.PHONY: bounds
bounds:
	@$(MAKE) --no-print-directory BUILD=$(BOUNDS_BUILD) \
	  EXTRA_CPPFLAGS=-DMLKEM_TRACK_BOUNDS $(BOUNDS_BUILD)/libmlkem768.a
	@mkdir -p $(BUILD)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) -DMLKEM_TRACK_BOUNDS $(TEST_CPPFLAGS) \
	  tools/measure_bounds.cpp $(BOUNDS_BUILD)/libmlkem768.a $(LDFLAGS) -o $(BOUNDS_BIN)
	@$(BOUNDS_BIN) $(BOUNDS_ITERS)

BENCH_BIN = $(BUILD)/bench_phase3

.PHONY: bench
bench: $(LIB)
	@mkdir -p $(BUILD)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $(TEST_CPPFLAGS) \
	  bench/bench_phase3.cpp $(LIB) $(LDFLAGS) -o $(BENCH_BIN)
	@$(BENCH_BIN)

# End-to-end KeyGen/Encaps/Decaps. Separate binary from bench_phase3 so the component
# breakdown and the whole-operation numbers can be run independently.
.PHONY: bench-kem
bench-kem: $(LIB)
	@mkdir -p $(BUILD)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $(TEST_CPPFLAGS) \
	  bench/bench_kem.cpp $(LIB) $(LDFLAGS) -o $(BUILD)/bench_kem
	@$(BUILD)/bench_kem

# --- comparison and energy targets -----------------------------------------
# These need the pq-crystals AVX2 library, built OUTSIDE this repo by
# tools/build_kyber_ref.sh. Nothing from that project is vendored here
# (ADR-003/ADR-022); it is benchmark-only. KYBER_LIB overrides the path.
KYBER_LIB ?= /tmp/libkyber768.a

.PHONY: kyber-ref
kyber-ref:
	@sh tools/build_kyber_ref.sh

$(KYBER_LIB):
	@echo "$(KYBER_LIB) missing -- run: gmake kyber-ref"; exit 1

# Spec 1 criterion 4. Both implementations in ONE process, interleaved (ADR-030).
.PHONY: bench-vs-kyber
bench-vs-kyber: $(LIB) $(KYBER_LIB)
	@mkdir -p $(BUILD)
	$(CXX) $(TEST_CXXFLAGS) -march=native $(TEST_CPPFLAGS) \
	  bench/bench_vs_kyber.cpp $(LIB) $(KYBER_LIB) $(LDFLAGS) -o $(BUILD)/bench_vs_kyber
	@$(BUILD)/bench_vs_kyber

# Cross-implementation interop, spec 10.5. 10^4 iterations each direction.
.PHONY: interop
interop: $(LIB) $(KYBER_LIB)
	@mkdir -p $(BUILD)
	$(CXX) $(TEST_CXXFLAGS) $(TEST_CPPFLAGS) \
	  tests/interop_kyber.cpp $(LIB) $(KYBER_LIB) $(LDFLAGS) -o $(BUILD)/interop
	@$(BUILD)/interop

# Energy harness. Builds ONLY -- it must not be launched casually: the run takes 280 s
# and is meaningless unless a powermetrics capture is already running alongside it.
# The full procedure is in docs/notes/09-energy.md.
.PHONY: bench-energy-build
bench-energy-build: $(LIB) $(KYBER_LIB)
	@mkdir -p $(BUILD)
	$(CXX) $(TEST_CXXFLAGS) -march=native $(TEST_CPPFLAGS) \
	  bench/bench_energy.cpp $(LIB) $(KYBER_LIB) $(LDFLAGS) -o $(BUILD)/bench_energy
	@echo "  built $(BUILD)/bench_energy -- 280 s schedule."
	@echo "  DO NOT RUN IT YET: start the powermetrics capture first."
	@echo "  See docs/notes/09-energy.md."

# Spec §8.4 / §10.3: statistical timing test. The dimension ctgrind is structurally
# blind to (ADR-016) -- a variable-latency instruction on secret data has no branch and
# no secret memory index for ctgrind to see.
#
# RUNS ON THE HOST, NOT IN DOCKER, and is deliberately NOT in docker-all. Docker on this
# Mac is a VM: it interposes a virtualization layer on exactly the quantity being
# measured, and adds nothing, since timing behaviour is a property of this silicon.
# `docker-dudect` exists for comparison only -- see ADR-035 and docs/notes/09-dudect.md.
#
# Calibration runs FIRST and the target fails if a planted leak is NOT detected: a
# t-test that cannot report a leak is a gate that cannot fail.
#   gmake dudect                   default budget, ~2 min
#   gmake dudect DUDECT_ARGS=--quick   smoke test
#   gmake dudect DUDECT_ARGS=--deep    the statistically serious run
DUDECT_ARGS ?=
.PHONY: dudect
dudect: $(LIB)
	@mkdir -p $(BUILD)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $(TEST_CPPFLAGS) -Itests/ct \
	  tests/ct/dudect_mlkem.cpp $(LIB) $(LDFLAGS) -o $(BUILD)/dudect_mlkem
	@$(BUILD)/dudect_mlkem $(DUDECT_ARGS)

# Comparison only. See the note above: this measures the VM, not the machine.
.PHONY: docker-dudect
docker-dudect: docker-check
	@$(DOCKER_RUN) make dudect DUDECT_ARGS="$(DUDECT_ARGS)"

# Phase 9b follow-up: decide the `ntt` timing row by DIFFERENTIAL control. Runs our AVX2
# ntt, our portable scalar ntt and pq-crystals' AVX2 ntt through the IDENTICAL harness.
# If only ours shows the value-following signature that is a real finding; if all three
# do, it is this CPU or the instrument. pq-crystals is benchmark-comparison only
# (ADR-022): built outside this repo, nothing vendored, never in the shipped library.
.PHONY: dudect-ntt-diff
dudect-ntt-diff: $(LIB) $(KYBER_LIB)
	@mkdir -p $(BUILD)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $(TEST_CPPFLAGS) -Itests/ct \
	  tests/ct/dudect_ntt_diff.cpp $(LIB) $(KYBER_LIB) $(LDFLAGS) -o $(BUILD)/dudect_ntt_diff
	@$(BUILD)/dudect_ntt_diff $(DUDECT_ARGS)

# Phase 9b follow-up: is poly_tomsg's timing effect about EXACT repetition, or graded by
# similarity between successive inputs? The second would carry information about the
# secret-derived w. See docs/notes/09-dudect.md.
.PHONY: dudect-tomsg-sim
dudect-tomsg-sim: $(LIB)
	@mkdir -p $(BUILD)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $(TEST_CPPFLAGS) -Itests/ct \
	  tests/ct/dudect_tomsg_sim.cpp $(LIB) $(LDFLAGS) -o $(BUILD)/dudect_tomsg_sim
	@$(BUILD)/dudect_tomsg_sim $(DUDECT_ARGS)

.PHONY: fuzz
# Spec §10.4. libFuzzer + ASan + UBSan, DOCKER-ONLY: Apple clang ships no libFuzzer, so
# the host target fails loudly rather than pretending (ADR-008's pattern).
#
# Two targets. Both derive a VALID key pair from the fuzzer's own bytes and perturb from
# there, because a fuzzer whose inputs die at the first check only tests the first check.
# Both also run a DIFFERENTIAL ORACLE against the golden model -- on the decrypt path that
# is the only correctness gate there is, since KATs cannot see small errors there
# (`docs/reference/invariants.md`). Corpus is seeded from the ACVP vectors.
#
#   FUZZ_RUNS=n     executions per target (default 1000000)
#   FUZZ_ARGS=...   passed through to libFuzzer
FUZZ_RUNS ?= 1000000
FUZZ_ARGS ?=
FUZZ_SRCS = tests/fuzz/fuzz_decaps.cpp tests/fuzz/fuzz_keycheck.cpp
# THE LIBRARY ITSELF MUST BE INSTRUMENTED, not just the fuzz entry point. The first
# version linked the plain -O3 library and a sanitized target TU, and ASan then could not
# see a deliberately planted out-of-bounds read INSIDE src/kpke.cpp -- a hand-crafted
# triggering input produced nothing. Instrumenting only the harness makes the fuzzer a
# crash detector for the harness, which is not the point.
#
# fuzzer-no-link on library/model objects (coverage instrumentation without pulling in the
# fuzzer's main), fuzzer on the entry TU. Built via a recursive make into its own BUILD
# directory, the same way asan/ubsan do it, so the per-TU AVX2 flags still apply.
FUZZ_LIB_FLAGS = -fsanitize=fuzzer-no-link,address,undefined \
                 -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g
FUZZ_BIN_FLAGS = -fsanitize=fuzzer,address,undefined \
                 -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g

.PHONY: fuzz
fuzz:
	@echo "ERROR: gmake fuzz cannot run on this host -- Apple clang ships no libFuzzer."
	@echo ""
	@echo "  Use: gmake docker-fuzz    (spec §10.4, runs in the Linux container)"
	@echo "  This target is NOT removed, so the gap stays visible. See ADR-008."
	@exit 1

# Rebuilds the library AND the model with the sanitizers, then builds and runs the
# targets. Invoked inside the container by docker-fuzz.
.PHONY: fuzz-run
fuzz-run:
	@$(MAKE) BUILD=$(BUILD)/fz \
	  CXXFLAGS="$(CXXSTD) -O1 -g $(WARN) -fno-rtti -fvisibility=hidden $(FUZZ_LIB_FLAGS)" \
	  SANITIZE_FLAGS="-g $(FUZZ_LIB_FLAGS)" \
	  FUZZ_RUNS=$(FUZZ_RUNS) FUZZ_ARGS="$(FUZZ_ARGS)" fuzz-exec

.PHONY: fuzz-exec
fuzz-exec: $(LIB)
	@mkdir -p $(BUILD)/fuzz
	@for f in $(FUZZ_SRCS); do \
	  n=$$(basename $$f .cpp); \
	  echo "  BUILD $$n"; \
	  $(CXX) $(TEST_CXXFLAGS) $(FUZZ_BIN_FLAGS) $(ARCHFLAGS) $(TEST_CPPFLAGS) \
	    $$f $(MODEL_SRCS) $(LIB) $(LDFLAGS) -o $(BUILD)/fuzz/$$n || exit 1; \
	done
	@for f in $(FUZZ_SRCS); do \
	  n=$$(basename $$f .cpp); t=$${n#fuzz_}; \
	  echo ""; echo "=== $$n : $(FUZZ_RUNS) runs ==="; \
	  rm -rf $(BUILD)/fuzz/corpus_$$t; mkdir -p $(BUILD)/fuzz/corpus_$$t; \
	  python3 tools/seed_fuzz_corpus.py $(BUILD)/fuzz/corpus_$$t --target $$t; \
	  $(BUILD)/fuzz/$$n $(BUILD)/fuzz/corpus_$$t \
	    -runs=$(FUZZ_RUNS) -print_final_stats=1 -timeout=25 $(FUZZ_ARGS) || exit 1; \
	done
	@echo ""
	@echo "=== fuzz: PASS -- no crash, no sanitizer finding, no oracle mismatch ==="

.PHONY: docker-fuzz
docker-fuzz: docker-check
	@$(DOCKER_RUN) make BUILD=$(DOCKER_BUILD_DIR) fuzz-run \
	  FUZZ_RUNS=$(FUZZ_RUNS) FUZZ_ARGS="$(FUZZ_ARGS)"

# ---------------------------------------------------------------------------
# Constant-time checking (§8.4)
# ---------------------------------------------------------------------------
#
# valgrind is NOT INSTALLED on this machine and has no working x86-64 macOS port for
# current macOS versions (see `docs/reference/invariants.md`, Build environment). The target is kept, and kept
# failing loudly, rather than dropped — silently losing the CT gate is exactly the
# outcome this reports against.

VALGRIND ?= valgrind

.PHONY: ctgrind
ctgrind:
	@command -v $(VALGRIND) >/dev/null 2>&1 || { \
	  echo "ERROR: valgrind not found."; \
	  echo ""; \
	  echo "  make ctgrind is the constant-time gate (spec §8.4) and CANNOT be"; \
	  echo "  satisfied on this machine: valgrind is not installed and does not"; \
	  echo "  currently support this macOS/x86-64 configuration."; \
	  echo ""; \
	  echo "  This target is intentionally NOT removed. Options, in order:"; \
	  echo "    1. gmake docker-ctgrind — runs it in the Linux CI container."; \
	  echo "       (gmake docker-build once first; gmake docker-probe to verify.)"; \
	  echo "    2. gmake dudect — statistical timing test, Phase 9. Complementary,"; \
	  echo "       not a substitute: it catches microarchitectural leaks ctgrind"; \
	  echo "       misses, and misses the branch/index leaks ctgrind catches."; \
	  echo ""; \
	  echo "  Phase 9 cannot be signed off on this machine alone."; \
	  exit 1; }
	@$(MAKE) ctgrind-run

# The real work, run inside the container by docker-ctgrind. Split out so the host
# target can keep its "valgrind is missing here" diagnosis.
# The CT binaries link a SEPARATE library build with MLKEM_CT_TESTING defined, so the
# declassification points in src/ct_declassify.hpp are live. The shipped libmlkem768.a
# is built without it and contains no trace of them.
CT_BUILD = $(BUILD)/ct
CT_LIB = $(CT_BUILD)/libmlkem768.a

.PHONY: ct-lib
ct-lib:
	@$(MAKE) --no-print-directory BUILD=$(CT_BUILD) \
	  EXTRA_CPPFLAGS=-DMLKEM_CT_TESTING $(CT_LIB)

CT_BIN = $(BUILD)/ct_keccak
CT_SAMPLE_BIN = $(BUILD)/ct_sample
CT_KPKE_BIN = $(BUILD)/ct_kpke
CT_NTT_BIN = $(BUILD)/ct_ntt
CT_KEM_BIN = $(BUILD)/ct_kem

$(CT_BIN): tests/ct/ct_keccak.cpp ct-lib
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $(TEST_CPPFLAGS) -DMLKEM_CT_TESTING \
	  tests/ct/ct_keccak.cpp $(CT_LIB) $(LDFLAGS) -o $@
	@echo "  LINK  $@"

$(CT_KEM_BIN): tests/ct/ct_kem.cpp ct-lib
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $(TEST_CPPFLAGS) -DMLKEM_CT_TESTING \
	  tests/ct/ct_kem.cpp $(CT_LIB) $(LDFLAGS) -o $@
	@echo "  LINK  $@"

$(CT_KPKE_BIN): tests/ct/ct_kpke.cpp ct-lib
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $(TEST_CPPFLAGS) -DMLKEM_CT_TESTING \
	  tests/ct/ct_kpke.cpp $(CT_LIB) $(LDFLAGS) -o $@
	@echo "  LINK  $@"

$(CT_SAMPLE_BIN): tests/ct/ct_sample.cpp ct-lib
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $(TEST_CPPFLAGS) -DMLKEM_CT_TESTING \
	  tests/ct/ct_sample.cpp $(CT_LIB) $(LDFLAGS) -o $@
	@echo "  LINK  $@"

$(CT_NTT_BIN): tests/ct/ct_ntt.cpp ct-lib
	@mkdir -p $(dir $@)
	$(CXX) $(TEST_CXXFLAGS) $(ARCHFLAGS) $(TEST_CPPFLAGS) -DMLKEM_CT_TESTING \
	  tests/ct/ct_ntt.cpp $(CT_LIB) $(LDFLAGS) -o $@
	@echo "  LINK  $@"

VALGRIND_CT = valgrind --tool=memcheck --error-exitcode=99 --track-origins=yes \
              --errors-for-leak-kinds=definite

# A POSITIVE CONTROL must verify the SPECIFIC failure signal, not merely "nonzero".
#
# The earlier form accepted ANY nonzero exit with output discarded, so it printed
# "OK: planted leak detected" if the binary segfaulted, rejected its flag, or valgrind
# failed to launch at all. That is a gate that cannot fail -- precisely what the
# project's positive-control rule exists to prevent (`docs/reference/invariants.md` (testing philosophy)).
#
# $(call ct_expect_findings,<cmd and args>,<egrep pattern>,<description>,<mode name>)
#   Requires ALL THREE:
#     exit status == 99   (valgrind's --error-exitcode: it ran AND found errors)
#     a "CT-MODE: <mode>" banner proving the INTENDED mode ran
#     output matching the expected error KIND
#   Any other status -- 0 (no findings, harness blind), 1 (bad flag), 139 (crash),
#   126/127 (cannot execute) -- FAILS, with the observed status reported.
# $(call ct_expect_clean,<cmd and args>,<mode name>,<description>)
#   Requires BOTH:
#     exit status == 0    (valgrind found nothing)
#     a "CT-MODE: <mode>" banner proving the INTENDED mode ran
#
# The banner is the point. Before it existed, ct_keccak treated any unrecognized
# argument as "run the default path", so a typo'd clean-expected mode ran a DIFFERENT
# clean check and the gate reported success without ever testing what it claimed.
define ct_expect_clean
set +e; out=$$($(VALGRIND_CT) $(1) 2>&1); rc=$$?; set -e; \
if [ "$$rc" -ne 0 ]; then \
  echo "FAIL: '$(3)' expected CLEAN (exit 0) but exited $$rc."; \
  echo "      99 = valgrind found errors; 2 = unknown/missing mode; 139 = crash."; \
  echo "      --- output (tail) ---"; echo "$$out" | tail -20; \
  exit 1; \
fi; \
if ! echo "$$out" | grep -qF "CT-MODE: $(2)"; then \
  echo "FAIL: '$(3)' exited 0 but did not print 'CT-MODE: $(2)'."; \
  echo "      Exit 0 alone is not enough: a typo'd mode name would run a different"; \
  echo "      clean check and pass vacuously. The banner proves WHICH mode ran."; \
  echo "      --- output (tail) ---"; echo "$$out" | tail -20; \
  exit 1; \
fi; \
echo "  OK: $(3) clean (exit 0 + ran mode $(2))"
endef

define ct_expect_findings
set +e; out=$$($(VALGRIND_CT) $(1) 2>&1); rc=$$?; set -e; \
if [ "$$rc" -ne 99 ]; then \
  echo "FAIL: positive control '$(3)' exited $$rc, expected 99."; \
  echo "      99 means valgrind ran AND reported errors. Anything else means the"; \
  echo "      control did not do what it claims: 0 = no findings (harness blind),"; \
  echo "      1 = bad flag, 139 = crash, 126/127 = could not execute."; \
  echo "      --- output (tail) ---"; echo "$$out" | tail -15; \
  exit 1; \
fi; \
if ! echo "$$out" | grep -qF "CT-MODE: $(4)"; then \
  echo "FAIL: positive control '$(3)' did not print 'CT-MODE: $(4)'."; \
  echo "      The binary ran a DIFFERENT mode than intended -- a typo'd mode name"; \
  echo "      would otherwise pass by exercising something else."; \
  echo "      --- output (tail) ---"; echo "$$out" | tail -15; \
  exit 1; \
fi; \
if ! echo "$$out" | grep -qE '$(2)'; then \
  echo "FAIL: positive control '$(3)' exited 99 but nothing matched /$(2)/."; \
  echo "      Exit 99 alone is not enough -- confirm the error KIND is the one this"; \
  echo "      control is meant to demonstrate."; \
  echo "      --- output (tail) ---"; echo "$$out" | tail -15; \
  exit 1; \
fi; \
echo "  OK: $(3) detected (exit 99 + matching diagnostic)"
endef

.PHONY: ctgrind-run
ctgrind-run: $(CT_BIN) $(CT_SAMPLE_BIN) $(CT_NTT_BIN) $(CT_KPKE_BIN) $(CT_KEM_BIN)
	@echo "=== ctgrind SELF-TEST: the harness must DETECT a planted leak ==="
	@$(call ct_expect_findings,$(CT_BIN) --selftest,Conditional jump|uninitialised,planted leak,--selftest)
	@echo ""
	@echo "=== symmetric layer: secret-marked PRF/G/J through the vendored Keccak ==="
	@$(call ct_expect_clean,$(CT_BIN) --secrets,--secrets,PRF/G/J with secret inputs)
	@echo "--- 4-WAY CONTROL: taint must SURVIVE the AVX2 gather/permute/scatter ---"
	@$(call ct_expect_clean,$(CT_BIN) --x4-map,--x4-map,all four PRF_x4 lanes fully tainted (measured))
	@$(call ct_expect_findings,$(CT_BIN) --x4-taint,Conditional jump|uninitialised,PRF_x4 output still tainted through the AVX2 path,--x4-taint)
	@echo ""
	@echo "=== sampling layer (OPPOSITE requirements, both asserted) ==="
	@echo "--- CBD CONTROL FIRST: vpshufb with a SECRET SELECTOR (ADR-025/028) ---"
	@$(call ct_expect_clean,$(CT_SAMPLE_BIN) --cbd-map,--cbd-map,taint reaches all 256 CBD coefficients (measured))
	@$(call ct_expect_findings,$(CT_SAMPLE_BIN) --cbd-taint,Conditional jump|uninitialised,SIMD CBD output still tainted through vpshufb+vpmovsxbw,--cbd-taint)
	@$(call ct_expect_clean,$(CT_SAMPLE_BIN) --cbd,--cbd,CBD with sigma secret)
	@$(call ct_expect_findings,$(CT_SAMPLE_BIN) --ntt-secret,Conditional jump|uninitialised,sample_ntt rejection loop on secret rho,--ntt-secret)
	@out=$$($(VALGRIND_CT) $(CT_SAMPLE_BIN) --ntt-secret 2>&1 || true); \
	  echo "$$out" | grep -q "backend: AVX2 (SIMD rej_uniform)" \
	    && echo "  OK: the control exercised the SIMD sampler, not the scalar fallback" \
	    || { echo "  FAIL: --ntt-secret ran the SCALAR path; the control proves nothing"; \
	         echo "        about the SIMD rej_uniform the library actually dispatches."; exit 1; }
	@$(call ct_expect_clean,$(CT_SAMPLE_BIN) --ntt-public,--ntt-public,sample_ntt with rho public)
	@echo ""
	@echo "=== AVX2 NTT (Phase 8b): the transform itself, on secret coefficients ==="
	@echo "--- CONTROL FIRST: taint must survive vpmullw/vpmulhw/vpsraw + the shuffles"
	@echo "--- (ADR-025: the 8a --x4-taint proof does NOT cover multiplies) ---"
	@$(call ct_expect_clean,$(CT_NTT_BIN) --taint-map,--taint-map,taint reaches all 256 coefficients (measured, not assumed))
	@$(call ct_expect_findings,$(CT_NTT_BIN) --ntt-taint,Conditional jump|uninitialised,ntt/invntt output still tainted through multiply+shuffle,--ntt-taint)
	@echo "--- BASEMUL (8e): 16-bit unpacks + cross-lane permute on secret polys ---"
	@$(call ct_expect_clean,$(CT_NTT_BIN) --basemul-map,--basemul-map,basemul output fully tainted (measured))
	@$(call ct_expect_findings,$(CT_NTT_BIN) --basemul-taint,Conditional jump|uninitialised,basemul output still tainted through the deinterleave permutes,--basemul-taint)
	@$(call ct_expect_clean,$(CT_NTT_BIN) --secret,--secret,ntt/invntt with secret coefficients)
	@echo ""
	@echo "=== K-PKE (Phase 6a + 8c audit): control, taint map, then four clean modes ==="
	@echo "--- CONTROL FIRST: this file had NO positive control until the 8c audit ---"
	@$(call ct_expect_findings,$(CT_KPKE_BIN) --keygen-leak,Conditional jump|uninitialised,dk_PKE still tainted on the real kpke_keygen path,--keygen-leak)
	@$(call ct_expect_clean,$(CT_KPKE_BIN) --taint-map,--taint-map,taint reaches every K-PKE output; rho window exactly 32 bytes)
	@echo "--- Compress_1 / m' gets its OWN control: it is the decrypted message ---"
	@$(call ct_expect_findings,$(CT_KPKE_BIN) --tomsg-leak,Conditional jump|uninitialised,m'' still tainted out of Compress_1 on the real decrypt path,--tomsg-leak)
	@$(call ct_expect_clean,$(CT_KPKE_BIN) --tomsg-map,--tomsg-map,all 32 bytes of m'' tainted (measured))
	@$(call ct_expect_clean,$(CT_KPKE_BIN) --keygen-secret-d,--keygen-secret-d,kpke_keygen with d secret)
	@$(call ct_expect_clean,$(CT_KPKE_BIN) --encrypt-secret-mr,--encrypt-secret-mr,kpke_encrypt with m and r secret)
	@$(call ct_expect_clean,$(CT_KPKE_BIN) --decrypt-secret-dk,--decrypt-secret-dk,kpke_decrypt with dk secret)
	@$(call ct_expect_clean,$(CT_KPKE_BIN) --encrypt-secret-ek,--encrypt-secret-ek,kpke_encrypt with ek secret (rho declassified per ADR-021))
	@echo ""
	@echo "=== ML-KEM (Phase 6b) ==="
	@echo "--- SURVIVAL CHECK: the planted memcmp must still be a real byte compare ---"
	@if $(OBJDUMP) -d $(CT_KEM_BIN) 2>/dev/null \
	   | awk '/decaps_via_memcmp/{f=1} f&&/(repz cmpsb|call.*memcmp|cmpb)/{print; exit}' \
	   | grep -q .; then \
	  echo "  OK: memcmp survived -O3 (a real compare is present)"; \
	else \
	  echo "FAIL: the planted memcmp was optimized away -- the control proves nothing."; \
	  echo "      docs/reference/invariants.md (testing philosophy): confirm a planted artifact SURVIVES before"; \
	  echo "      trusting a clean or dirty result either way."; \
	  exit 1; \
	fi
	@$(call ct_expect_clean,$(CT_KEM_BIN) --keygen-secret-dz,--keygen-secret-dz,keygen_internal with d and z secret)
	@$(call ct_expect_clean,$(CT_KEM_BIN) --encaps-secret-m,--encaps-secret-m,encaps_internal with m secret)
	@$(call ct_expect_clean,$(CT_KEM_BIN) --decaps-secret-dk,--decaps-secret-dk,decaps_internal with dk secret)
	@$(call ct_expect_findings,$(CT_KEM_BIN) --decaps-memcmp,Conditional jump|uninitialised,decaps via memcmp (failure mode #10),--decaps-memcmp)
	@echo ""
	@echo "=== memcheck over the full unit suite ==="
	@$(MAKE) BUILD=$(BUILD) test >/dev/null
	@$(VALGRIND_CT) --leak-check=full $(BUILD)/test_unit >/dev/null
	@echo "  unit suite: 0 errors, 0 leaks"

# ---------------------------------------------------------------------------
# Sanitizers (§10.4)
# ---------------------------------------------------------------------------

.PHONY: asan ubsan msan
#
# HOST LIMITATION (macOS 26.6.2 / Apple clang 16, recorded Phase 0):
#
#   * LeakSanitizer's runtime SIGILLs at exit, so ASAN_OPTIONS=detect_leaks=0 is
#     required for an ASan binary to run at all. Leak detection is unavailable.
#   * Worse, ASan's error-REPORTING path also SIGILLs: a clean program runs fine,
#     but a program with a real heap overflow dies with signal 4 and prints
#     NOTHING, under every ASAN_OPTIONS combination tried (symbolize=0,
#     halt_on_error=0, print_module_map=0).
#
#   Net effect: on this host `make asan` is a crash detector, not a diagnostic.
#   It is kept wired and honest rather than removed or quietly marked green.
#   The real ASan/MSan gate (spec §10.4) must run in Linux CI. UBSan is fully
#   functional here and is the usable sanitizer on this machine.

# Sanitizers slow execution by 3-20x. The differential COUNT is irrelevant to them --
# they look for memory errors and UB, and every code path is exercised thousands of
# times at this level. Statistical depth is `make test-deep`'s job, not theirs.
SANITIZER_DIFF_ITERS ?= 2000

ASAN_OPTIONS_HOST ?= detect_leaks=0

# Preflight: ASan is non-functional on this host for any C++ program that touches the
# standard library (verified Phase 0: a bare std::string program SIGILLs). Detect that
# and say so, rather than handing the user "Illegal instruction: 4" with no context.
.PHONY: asan-preflight
asan-preflight:
	@printf '#include <string>\n#include <cstdio>\nint main(){std::string s="heap allocated string";printf("%%zu\\n",s.size());return 0;}\n' > $(BUILD)/.asan_probe.cpp 2>/dev/null || { mkdir -p $(BUILD); printf '#include <string>\n#include <cstdio>\nint main(){std::string s="heap allocated string";printf("%%zu\\n",s.size());return 0;}\n' > $(BUILD)/.asan_probe.cpp; }
	@$(CXX) $(CXXSTD) -O1 -g -fsanitize=address $(BUILD)/.asan_probe.cpp -o $(BUILD)/.asan_probe 2>/dev/null
	@ASAN_OPTIONS=$(ASAN_OPTIONS_HOST) $(BUILD)/.asan_probe >/dev/null 2>&1 || { \
	  echo "ERROR: AddressSanitizer is non-functional on this host."; \
	  echo ""; \
	  echo "  A minimal C++ program using std::string, built with -fsanitize=address,"; \
	  echo "  terminates with SIGILL. Verified in Phase 0 on macOS 26.6.2 with Apple"; \
	  echo "  clang 16. Both the LeakSanitizer exit path and the ASan error-REPORTING"; \
	  echo "  path crash; no ASAN_OPTIONS combination recovers them."; \
	  echo ""; \
	  echo "  Consequence: ASan cannot be used as a gate on this machine. A crash"; \
	  echo "  here means 'ASan is broken', not 'your code is broken', which is the"; \
	  echo "  worst possible signal to build a correctness gate on."; \
	  echo ""; \
	  echo "  Run the ASan gate (spec §10.4) in the Linux container instead:"; \
	  echo "    gmake docker-asan    — verified to report real heap overflows"; \
	  echo "    gmake docker-all     — every Linux gate at once"; \
	  echo "  On this machine, locally:"; \
	  echo "    gmake ubsan    — fully functional, verified to catch real UB"; \
	  echo "    gmake test     — the correctness gate"; \
	  echo ""; \
	  echo "  Target kept wired, not dropped."; \
	  exit 1; }
	@echo "asan preflight: ASan runtime works on this host."

asan: asan-preflight
	@ASAN_OPTIONS=$(ASAN_OPTIONS_HOST) MLKEM_DIFF_ITERS=$(SANITIZER_DIFF_ITERS) $(MAKE) BUILD=$(BUILD)/asan \
	  CXXFLAGS="$(CXXSTD) -O1 -g $(WARN) -fno-rtti -fvisibility=hidden -fsanitize=address -fno-omit-frame-pointer" \
	  SANITIZE_FLAGS="-g -fsanitize=address -fno-omit-frame-pointer" \
	  test

# UBSan flag set. Two of these are named explicitly so a later edit cannot quietly
# drop them.
#
# IMPORTANT, and NOT what you would assume (verified Phase 1, see ADR-012):
#   int16_t overflow is NOT undefined behaviour. `int16_t * int16_t` promotes both
#   operands to `int`, and narrowing the result back to int16_t is well-defined
#   modular wrapping in C++20. So -fsanitize=signed-integer-overflow does NOT catch
#   docs/reference/kat-failure-checklist.md #8. Measured: 300*200 -> -5536, silently, exit 0.
#
#   -fsanitize=implicit-integer-truncation DOES catch it, exactly and with no false
#   positive on an in-range narrowing. That is the flag that guards the NTT.
#   Caveat for Phase 8: it only sees IMPLICIT conversions. An explicit
#   static_cast<int16_t> is invisible to it, so reduction helpers that deliberately
#   wrap must either keep the conversion implicit or be covered by the
#   -DMLKEM_TRACK_BOUNDS instrumented build in docs/bounds.md instead.
#   It is also clang-only: GCC rejects the flag outright. Probed rather than
#   assumed, so `make ubsan` works under either compiler and simply loses that one
#   check under GCC (which the banner says).
#
#   Use the SIGNED variant only. -fsanitize=implicit-integer-truncation also covers
#   UNSIGNED truncation, which is not UB and is the entire point of byte extraction:
#   the vendored Keccak's store64 does `x[i] = u >> 8*i` and tripped it on every
#   hash. Narrowing to implicit-signed-integer-truncation keeps the int16_t guard
#   ADR-012 needs and drops the false positive -- verified both ways in the
#   container, rather than suppressing or (worse) patching vendored code.
UBSAN_TRUNC = $(shell echo 'int main(){return 0;}' | \
    $(CXX) -xc++ -fsanitize=implicit-signed-integer-truncation - -o /dev/null 2>/dev/null \
    && echo -fsanitize=implicit-signed-integer-truncation)

UBSAN_FLAGS = -fsanitize=undefined -fsanitize=signed-integer-overflow \
              $(UBSAN_TRUNC) \
              -fsanitize=integer-divide-by-zero -fsanitize=shift \
              -fno-sanitize-recover=all -fno-omit-frame-pointer

ubsan:
	@if [ -z "$(UBSAN_TRUNC)" ]; then \
	  echo "WARNING: $(CXX) does not support -fsanitize=implicit-signed-integer-truncation."; \
	  echo "         That is the ONLY sanitizer that catches int16_t overflow"; \
	  echo "         (docs/reference/kat-failure-checklist.md #8) — it is not UB, so"; \
	  echo "         -fsanitize=signed-integer-overflow does not see it."; \
	  echo "         Use clang for a full-strength UBSan run."; \
	fi
	@MLKEM_DIFF_ITERS=$(SANITIZER_DIFF_ITERS) $(MAKE) BUILD=$(BUILD)/ubsan \
	  CXXFLAGS="$(CXXSTD) -O1 -g $(WARN) -fno-rtti -fvisibility=hidden $(UBSAN_FLAGS)" \
	  SANITIZE_FLAGS="-g $(UBSAN_FLAGS)" \
	  test
	@$(MAKE) BUILD=$(BUILD)/ubsan \
	  CXXFLAGS="$(CXXSTD) -O1 -g $(WARN) -fno-rtti -fvisibility=hidden $(UBSAN_FLAGS)" \
	  SANITIZE_FLAGS="-g $(UBSAN_FLAGS)" \
	  kat-model

# MSan needs an MSan-instrumented libc++. Apple clang does not ship one, so this
# target is a hard stop on Darwin and a real run on Linux. Verified in the container:
# it reports use-of-uninitialized-value, and is clean against std::vector/std::array
# under libstdc++ at -O0.
UNAME_S := $(shell uname -s)

msan:
ifeq ($(UNAME_S),Darwin)
	@echo "ERROR: MSan requires clang with an MSan-instrumented libc++. Apple clang"
	@echo "       on macOS does not ship one, so this target CANNOT run on this host."
	@echo "       Run 'gmake docker-msan' instead — verified working in the Linux"
	@echo "       container. Target kept, not dropped."
	@exit 1
else
ifeq ($(strip $(MSAN_LIBCXX)),)
	@echo "ERROR: MSan needs an MSan-instrumented libc++ and MSAN_LIBCXX is unset."
	@echo ""
	@echo "  Against stock libstdc++, MSan reports use-of-uninitialized-value for"
	@echo "  every read of memory written by uninstrumented library code — e.g."
	@echo "  inside std::_Rb_tree as soon as doctest registers a test case. That"
	@echo "  is noise, not signal, and a gate built on it is worthless."
	@echo ""
	@echo "  Use the purpose-built image:  gmake docker-msan"
	@echo "  (built from ci/Dockerfile.msan, which compiles libc++ with MSan)."
	@exit 1
else
	@MLKEM_DIFF_ITERS=$(SANITIZER_DIFF_ITERS) $(MAKE) BUILD=$(BUILD)/msan \
	  CXX=clang++ CC=clang \
	  SANITIZE_FLAGS="-g -fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer" \
	  CXXFLAGS="$(CXXSTD) -O1 -g $(WARN) -fno-rtti -fvisibility=hidden -fsanitize=memory -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -nostdinc++ -isystem $(MSAN_LIBCXX)/include/c++/v1" \
	  LDFLAGS="-stdlib=libc++ -L$(MSAN_LIBCXX)/lib -Wl,-rpath,$(MSAN_LIBCXX)/lib -lc++ -lc++abi -Wno-unused-command-line-argument" \
	  test
endif
endif

# ---------------------------------------------------------------------------
# Linux CI in Docker (DECISIONS.md ADR-008, ADR-011)
# ---------------------------------------------------------------------------
#
# Three gates cannot run on the macOS host: ctgrind (no valgrind), asan (SIGILLs for
# any C++ program, on both Apple clang and Homebrew LLVM), msan (no instrumented
# libc++). They run here instead. Built at Phase 1, not Phase 9, deliberately.
#
# Linux objects must not collide with macOS objects, so container builds use
# BUILD=build/linux. `make test` on the host and `make docker-test` can both be
# resident at once.

DOCKER_IMAGE    ?= mlkem768-ci:bookworm
DOCKER_PLATFORM ?= linux/amd64
DOCKER_BUILD_DIR = build/linux
DOCKER_CXX ?= clang++
DOCKER_RUN = docker run --rm --platform $(DOCKER_PLATFORM) \
             -e CXX=$(DOCKER_CXX) -e MLKEM_DIFF_ITERS \
             -v "$(CURDIR)":/work -w /work $(DOCKER_IMAGE)

.PHONY: docker-check
docker-check:
	@command -v docker >/dev/null 2>&1 || { \
	  echo "ERROR: docker not found. The Linux gates (ctgrind/asan/msan) need it."; exit 1; }
	@docker info >/dev/null 2>&1 || { \
	  echo "ERROR: the Docker daemon is not running. Start Docker Desktop, then retry."; exit 1; }
	@docker image inspect $(DOCKER_IMAGE) >/dev/null 2>&1 || { \
	  echo "Image $(DOCKER_IMAGE) not built yet. Run: gmake docker-build"; exit 1; }

.PHONY: docker-build
docker-build:
	docker build --platform $(DOCKER_PLATFORM) -t $(DOCKER_IMAGE) -f ci/Dockerfile ci/

# Verifies the container can actually DO what later phases need — AVX2/BMI2/FMA are
# compiled AND executed, and each sanitizer must produce a real report. A container
# that compiles AVX2 but cannot run it is exactly the failure this catches.
.PHONY: docker-probe
docker-probe: docker-check
	@$(DOCKER_RUN) sh ci/probe.sh

.PHONY: docker-test
docker-test: docker-check
	@$(DOCKER_RUN) make BUILD=$(DOCKER_BUILD_DIR) test

.PHONY: docker-kat-model
docker-kat-model: docker-check
	@$(DOCKER_RUN) make BUILD=$(DOCKER_BUILD_DIR) kat-model

# From Phase 7 on, `kat` is THE correctness gate (`docs/reference/invariants.md` (testing philosophy): KATs must pass at
# the end of every phase from 7 onward), so it runs in docker-all alongside the rest.
.PHONY: docker-kat
docker-kat: docker-check
	@$(DOCKER_RUN) make BUILD=$(DOCKER_BUILD_DIR) kat

.PHONY: docker-asan
docker-asan: docker-check
	@$(DOCKER_RUN) make BUILD=$(DOCKER_BUILD_DIR)/asan-outer asan

.PHONY: docker-ubsan
docker-ubsan: docker-check
	@$(DOCKER_RUN) make BUILD=$(DOCKER_BUILD_DIR)/ubsan-outer ubsan

# Uses the dedicated MSan image (ci/Dockerfile.msan), which carries an
# MSan-instrumented libc++. See the msan target above for why stock libstdc++
# cannot be used.
DOCKER_MSAN_IMAGE ?= mlkem768-ci:msan

.PHONY: docker-msan-build
docker-msan-build: docker-build
	docker build --platform $(DOCKER_PLATFORM) -t $(DOCKER_MSAN_IMAGE) -f ci/Dockerfile.msan ci/

.PHONY: docker-msan
docker-msan:
	@docker image inspect $(DOCKER_MSAN_IMAGE) >/dev/null 2>&1 || { \
	  echo "Image $(DOCKER_MSAN_IMAGE) not built. Run: gmake docker-msan-build"; exit 1; }
	@docker run --rm --platform $(DOCKER_PLATFORM) -v "$(CURDIR)":/work -w /work \
	  $(DOCKER_MSAN_IMAGE) make BUILD=$(DOCKER_BUILD_DIR)/msan-outer msan

# The constant-time gate. Secret-marking client requests arrived in PHASE 3, not Phase 9
# as originally planned: tests/ct/ct_keccak.cpp marks sigma/r/d/z through the vendored
# Keccak, and tests/ct/ct_sample.cpp asserts the CBD / sample_ntt timing asymmetry.
# Every required-clean check is paired with a POSITIVE CONTROL that must produce
# findings, verified by exit-99-plus-diagnostic rather than merely "nonzero".
.PHONY: docker-ctgrind
docker-ctgrind: docker-check
	@$(DOCKER_RUN) make BUILD=$(DOCKER_BUILD_DIR) ctgrind-run

.PHONY: docker-shell
docker-shell: docker-check
	@docker run --rm -it --platform $(DOCKER_PLATFORM) \
	  -v "$(CURDIR)":/work -w /work $(DOCKER_IMAGE) bash

# Every gate that must be green before a phase is signed off.
.PHONY: docker-audit-refs
docker-audit-refs: docker-check
	@$(DOCKER_RUN) make audit-refs

.PHONY: docker-audit-zeroize
docker-audit-zeroize: docker-check
	@$(DOCKER_RUN) make audit-zeroize

.PHONY: docker-audit-div
docker-audit-div: docker-check
	@$(DOCKER_RUN) make BUILD=$(DOCKER_BUILD_DIR) audit-div

.PHONY: docker-audit-zeroize-sites
docker-audit-zeroize-sites: docker-check
	@$(DOCKER_RUN) make audit-zeroize-sites

.PHONY: docker-all
docker-all: docker-probe docker-test docker-kat docker-audit-div docker-audit-refs \
            docker-audit-zeroize \
            docker-audit-zeroize-sites docker-ubsan \
            docker-asan docker-msan docker-ctgrind
	@echo ""
	@echo "=== all Linux gates passed ==="

# ---------------------------------------------------------------------------
# Vectors (§10.1)
# ---------------------------------------------------------------------------
#
# Vectors are COMMITTED to the repo (DECISIONS.md ADR-006). This target re-verifies
# them, and only downloads when they are absent. It must fail loudly on a checksum
# mismatch rather than silently overwrite a good copy (PROVENANCE.md).

VECTOR_DIR = tests/kat/vectors

.PHONY: fetch-vectors verify-vectors
verify-vectors:
	@test -f $(VECTOR_DIR)/SHA256SUMS || { echo "ERROR: $(VECTOR_DIR)/SHA256SUMS missing"; exit 1; }
	@cd $(VECTOR_DIR) && shasum -a 256 -c SHA256SUMS

fetch-vectors:
	@if [ -f $(VECTOR_DIR)/SHA256SUMS ] && ls $(VECTOR_DIR)/*.json >/dev/null 2>&1; then \
	  echo "Vectors present; verifying against SHA256SUMS (not re-downloading)."; \
	  cd $(VECTOR_DIR) && shasum -a 256 -c SHA256SUMS; \
	else \
	  echo "Vectors missing. Re-download per tests/kat/PROVENANCE.md, which records the"; \
	  echo "pinned commit and the exact raw URLs, then re-run 'make verify-vectors'."; \
	  exit 1; \
	fi

# ---------------------------------------------------------------------------
# Packaging and install (§13)
# ---------------------------------------------------------------------------

# PACKAGE CONTENTS ARE A DELIBERATE DECISION, not a convenience (ADR-037).
#
# A BINARY package: the compiled static library, the public header, and the documents a
# recipient legally and practically needs. NO sources, NO tests, NO third_party/ tree.
#
# That choice decides which third-party notices are required, so it is made explicitly:
# libmlkem768.a contains vendored Keccak objects (verified with `ar t`, not assumed), so
# the pq-crystals, Keccak Teams and Brian Gladman notices all apply -- and Gladman's
# condition 2 requires its notice to accompany a BINARY distribution. doctest and
# nlohmann/json are test-only, contribute zero symbols to the archive (verified with
# `nm`), and are not shipped, so their notices are not required here. Shipping sources
# would change that, which is exactly why the package contents are pinned down.
#
# The version comes from src/version.cpp so the tarball name and the string the library
# reports cannot drift apart.
PKG_VERSION = $(shell sed -n 's/.*kVersion\[\] = "\(.*\)";.*/\1/p' src/version.cpp)
PKG_NAME    = mlkem768-$(PKG_VERSION)
PKG_STAGE   = $(BUILD)/pkg/$(PKG_NAME)
PKG_TARBALL = $(BUILD)/$(PKG_NAME).tar.gz

.PHONY: package
package: $(LIB)
	@test -n "$(PKG_VERSION)" || { echo "ERROR: could not read version from src/version.cpp"; exit 1; }
	@rm -rf $(BUILD)/pkg $(PKG_TARBALL)
	@mkdir -p $(PKG_STAGE)/lib $(PKG_STAGE)/include/mlkem
	@cp $(LIB) $(PKG_STAGE)/lib/
	@cp include/mlkem/*.hpp $(PKG_STAGE)/include/mlkem/
	@cp LICENSE THIRD_PARTY_NOTICES.txt README.md $(PKG_STAGE)/
	@mkdir -p $(PKG_STAGE)/docs
	@cp docs/SUMMARY.md $(PKG_STAGE)/docs/
	@printf 'ML-KEM-768 %s\n\nBuilt: %s\nHost:  %s\n\nContents:\n  include/mlkem/  public headers -- include <mlkem/mlkem768.hpp>\n  lib/            static library, link libmlkem768.a\n  LICENSE         this project MIT, Copyright (c) 2026 Bryan Samuels\n  THIRD_PARTY_NOTICES.txt  REQUIRED notices for vendored code in the library\n  README.md       build, use, and what is NOT claimed\n  docs/SUMMARY.md the whole project in plain words -- START HERE\n\nThis package ships a COMPILED LIBRARY and no sources. The library contains\nthird-party Keccak code; THIRD_PARTY_NOTICES.txt must accompany it.\n' 	  "$(PKG_VERSION)" "$$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$$(uname -sm)" > $(PKG_STAGE)/MANIFEST.txt
	@cd $(BUILD)/pkg && tar -czf ../$(PKG_NAME).tar.gz $(PKG_NAME)
	@echo "  PACKAGE $(PKG_TARBALL)"
	@echo ""
	@tar -tzf $(PKG_TARBALL) | sort
	@echo ""
	@echo "  size: $$(wc -c < $(PKG_TARBALL)) bytes"
	@shasum -a 256 $(PKG_TARBALL) 2>/dev/null || sha256sum $(PKG_TARBALL)

# THE CONSUMER TEST (Phase 10b). Builds a program the way a real user would: install to a
# temporary prefix, then compile with ONLY -I<prefix>/include and link <prefix>/lib.
# Nothing from src/ is on the include path.
#
# Every other test in this project includes headers straight out of src/, so none of them
# could tell whether `make install` ships a usable API. It did not: include/mlkem/ held only
# version.hpp while the declarations lived in src/kem.hpp, which is not installed. This
# target is the check that catches that, and it was proven able to fail before being
# trusted to pass.
CONSUMER_PREFIX = $(BUILD)/consumer-prefix
.PHONY: consumer-test
consumer-test:
	@rm -rf $(CONSUMER_PREFIX)
	@$(MAKE) install PREFIX=$(abspath $(CONSUMER_PREFIX)) >/dev/null
	@echo "=== installed tree ==="
	@find $(CONSUMER_PREFIX) -type f | sed "s|$(CONSUMER_PREFIX)|  <prefix>|"
	@echo ""
	@mkdir -p $(BUILD)/consumer
	@echo "  COMPILE tests/consumer/consumer.cpp  (only -I<prefix>/include)"
	@$(CXX) $(CXXSTD) -O2 $(WARN) \
	  -I$(CONSUMER_PREFIX)/include \
	  tests/consumer/consumer.cpp \
	  $(CONSUMER_PREFIX)/lib/libmlkem768.a $(LDFLAGS) -o $(BUILD)/consumer/consumer
	@echo ""
	@$(BUILD)/consumer/consumer

# Same test, against an UNPACKED TARBALL rather than an install tree -- so what is verified
# is what actually ships. PKG_TEST_DIR is a scratch directory, wiped each run.
.PHONY: package-test
package-test: package
	@rm -rf $(BUILD)/pkgtest && mkdir -p $(BUILD)/pkgtest
	@tar -xzf $(PKG_TARBALL) -C $(BUILD)/pkgtest
	@echo "=== unpacked $(notdir $(PKG_TARBALL)) ==="
	@find $(BUILD)/pkgtest -type f | sed "s|$(BUILD)/pkgtest/||" | sort | head -40
	@echo ""
	@mkdir -p $(BUILD)/consumer
	@echo "  COMPILE against the UNPACKED package"
	@$(CXX) $(CXXSTD) -O2 $(WARN) \
	  -I$(BUILD)/pkgtest/$(PKG_NAME)/include \
	  tests/consumer/consumer.cpp \
	  $(BUILD)/pkgtest/$(PKG_NAME)/lib/libmlkem768.a $(LDFLAGS) -o $(BUILD)/consumer/consumer_pkg
	@echo ""
	@$(BUILD)/consumer/consumer_pkg

.PHONY: install
install: $(LIB)
	install -d $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/include/mlkem
	install -m 644 $(LIB) $(DESTDIR)$(PREFIX)/lib/
	install -m 644 include/mlkem/*.hpp $(DESTDIR)$(PREFIX)/include/mlkem/

# ---------------------------------------------------------------------------
# Housekeeping
# ---------------------------------------------------------------------------

.PHONY: format
format:
	@command -v clang-format >/dev/null 2>&1 || { echo "clang-format not found"; exit 1; }
	@# third_party/ is excluded deliberately: never reformat vendored files (§13).
	@find src include tests bench tools -name '*.cpp' -o -name '*.hpp' -o -name '*.h' \
	  | xargs clang-format -i
	@echo "formatted (third_party/ excluded by design)"

.PHONY: env
env:
	@echo "make            = $(MAKE) $(MAKE_VERSION)  (>= 4.0 required)"
	@echo "CXX             = $(CXX) ($$($(CXX) --version 2>/dev/null | head -1))"
	@echo "CC              = $(CC)"
	@echo "CPU             = $(CPU)"
	@echo "                  ^ selects -march only. The AVX2 backend is ALWAYS built"
	@echo "                    and chosen at RUNTIME by cpuid (src/arch/dispatch.cpp),"
	@echo "                    independent of this. Override: MLKEM_FORCE_ARCH=portable|avx2"
	@echo "AVX2_FLAGS      = $(AVX2_FLAGS)   (applied to src/arch/avx2/ and fips202x4 only)"
	@echo "DEBUG           = $(DEBUG)"
	@echo "BUILD           = $(BUILD)"
	@echo ""
	@echo "CXXFLAGS        = $(CXXFLAGS)"
	@echo "TEST_CXXFLAGS   = $(TEST_CXXFLAGS)"
	@echo "THIRDPARTY_CFLAGS = $(THIRDPARTY_CFLAGS)"
	@echo "CPPFLAGS        = $(CPPFLAGS)"
	@echo "TEST_CPPFLAGS   = $(TEST_CPPFLAGS)"
	@echo "EXTRA_CPPFLAGS  = $(EXTRA_CPPFLAGS)"
	@echo "LDFLAGS         = $(LDFLAGS)"
	@echo "ARCHFLAGS       = $(ARCHFLAGS)"
	@echo "SANITIZE_FLAGS  = $(SANITIZE_FLAGS)"
	@echo "UBSAN_FLAGS     = $(UBSAN_FLAGS)"
	@echo ""
	@echo "origins: CXX=$(origin CXX) CC=$(origin CC) CXXFLAGS=$(origin CXXFLAGS)"
	@echo "  (CXXFLAGS must NOT read 'environment' -- see the comment on its definition)"

.PHONY: clean distclean
clean:
	$(RM) -r $(BUILD)

distclean: clean
	@# Deliberately does NOT delete tests/kat/vectors: they are committed
	@# (ADR-006) and re-acquiring them depends on an upstream path that moves.
	$(RM) -r dist *.tar.gz

-include $(DEPS)
