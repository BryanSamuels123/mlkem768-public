# Linux CI image for ML-KEM-768.
#
# Exists because three of the spec's verification gates cannot run on the macOS
# development host (DECISIONS.md ADR-008): valgrind is unavailable, ASan SIGILLs for any
# C++ program, and MSan needs an instrumented libc++ Apple clang does not ship.
#
# Built in Phase 1 rather than Phase 9, for the same reason the ACVP vectors were fetched
# in Phase 0: discovering at the gate that the environment cannot run the gate invalidates
# everything built on top of it.
#
# Pinned to a digest-stable tag. x86-64 explicitly — the AVX2 work in Phase 8 needs it,
# and on an Apple Silicon host `docker build` would otherwise silently produce arm64.

FROM --platform=linux/amd64 debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential \
      clang-16 \
      llvm-16 \
      libclang-rt-16-dev \
      libc++-16-dev \
      libc++abi-16-dev \
      valgrind \
      make \
      python3 \
      ca-certificates \
      git \
    && rm -rf /var/lib/apt/lists/*

# Debian names these clang-16 / clang++-16; give the build the plain names it expects.
RUN update-alternatives --install /usr/bin/clang   clang   /usr/bin/clang-16   100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-16 100 && \
    update-alternatives --install /usr/bin/c++     c++     /usr/bin/clang++-16 100 && \
    update-alternatives --install /usr/bin/cc      cc      /usr/bin/clang-16   100

WORKDIR /work
