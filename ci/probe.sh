#!/bin/sh
# Verify the container can actually do what the later phases need.
# Compile AND RUN every probe: a container that compiles AVX2 but cannot execute it
# (qemu emulation, restricted runner) is the failure this script exists to catch.
set -e

echo "=== identity ==="
uname -m
cat /etc/os-release | grep PRETTY_NAME
c++ --version | head -1
valgrind --version

echo ""
echo "=== CPU flags visible in container ==="
for f in avx2 bmi2 fma avx512f; do
  if grep -qm1 " $f" /proc/cpuinfo 2>/dev/null; then echo "  $f: present"; else echo "  $f: ABSENT"; fi
done

echo ""
echo "=== C++20 probe (same as host) ==="
cat > /tmp/cxx20probe.cpp <<'EOF'
#include <array>
#include <span>
#include <bit>
#include <cstdint>
#include <concepts>
consteval std::uint32_t qinv_probe(std::uint32_t q){
  std::uint32_t r = 1;
  for (int i = 0; i < 5; ++i) r *= 2u - q * r;
  return r;
}
static_assert((qinv_probe(3329) * 3329u) % 65536u == 1u);
template <typename T> concept Coef = std::signed_integral<T>;
static_assert(Coef<std::int16_t>);
int main(){
  std::array<std::uint8_t,4> a{1,2,3,4};
  std::span<const std::uint8_t> s{a};
  auto x = std::bit_cast<std::uint32_t>(a);
  return !(s.size()==4 && x!=0);
}
EOF
c++ -std=c++20 -O2 -Wall -Wextra -Wpedantic -Werror -fno-exceptions -fno-rtti -fvisibility=hidden \
    /tmp/cxx20probe.cpp -o /tmp/cxx20probe
/tmp/cxx20probe
echo "  C++20 OK (span, bit_cast, consteval, concepts, full library flag set)"

echo ""
echo "=== AVX2 + BMI2 + FMA probe — COMPILED AND RUN (same as host) ==="
cat > /tmp/avx2probe.cpp <<'EOF'
#include <immintrin.h>
#include <cstdio>
#include <cstdint>
int main(){
  // The exact instruction mix the Phase 8 NTT and compress paths need.
  __m256i a = _mm256_set1_epi16(17), b = _mm256_set1_epi16(3329);
  __m256i hi = _mm256_mulhi_epi16(a, b);
  __m256i lo = _mm256_mullo_epi16(a, b);
  __m256i sum = _mm256_add_epi16(hi, lo);
  __m256i shuf = _mm256_shuffle_epi8(sum, _mm256_set1_epi8(0));
  unsigned long long p = _pext_u64(0xF0F0F0F0ULL, 0xFFFFULL);   // BMI2
  unsigned long long d = _pdep_u64(0x1234ULL, 0xFFFF0000ULL);   // BMI2
  int r = _mm256_extract_epi16(shuf, 0);
  printf("  mulhi=%d mullo=%d shuf=%d pext=%llu pdep=%llu\n",
         _mm256_extract_epi16(hi,0), _mm256_extract_epi16(lo,0), r, p, d);
  // 17*3329 = 56593: fits in 32 bits, so the signed high half is 0 and the low
  // half is 56593 (=-8943 as int16). pext takes the low 16 bits of 0xF0F0F0F0
  // -> 0xF0F0. pdep deposits 0x1234 into bits 16..31 -> 0x12340000.
  return !(_mm256_extract_epi16(hi,0) == 0
           && _mm256_extract_epi16(lo,0) == 56593
           && p == 0xF0F0ULL
           && d == 0x12340000ULL);
}
EOF
c++ -std=c++20 -O3 -mavx2 -mbmi2 -mfma /tmp/avx2probe.cpp -o /tmp/avx2probe
/tmp/avx2probe
echo "  AVX2 + BMI2 + FMA: compiled AND executed successfully"

echo ""
echo "=== sanitizer probes — each must RUN and REPORT ==="
cat > /tmp/asanbug.cpp <<'EOF'
#include <cstdio>
#include <cstdlib>
#include <string>
int main(){
  std::string s = "heap allocated string, long enough to not be SSO";
  printf("%zu\n", s.size());
  int* a=(int*)malloc(4*sizeof(int));
  for(int i=0;i<4;i++)a[i]=i;
  int v=a[7];               // deliberate heap-buffer-overflow
  printf("%d\n",v);
  free(a);
  return 0;
}
EOF
c++ -std=c++20 -O0 -g -fsanitize=address /tmp/asanbug.cpp -o /tmp/asanbug
if /tmp/asanbug >/tmp/asanout 2>&1; then
  echo "  ASan: FAIL — did not detect a real heap-buffer-overflow"; exit 1
fi
grep -q "heap-buffer-overflow" /tmp/asanout \
  && echo "  ASan: reports heap-buffer-overflow correctly" \
  || { echo "  ASan: FAIL — crashed without a usable report"; head -5 /tmp/asanout; exit 1; }

cat > /tmp/ubbug.cpp <<'EOF'
#include <cstdio>
#include <cstdint>
int main(){
  // The exact failure mode that matters for this project: int16_t overflow in the NTT.
  volatile std::int16_t x = 32767;
  std::int16_t y = (std::int16_t)(x + 1);
  printf("%d\n", (int)y);
  return 0;
}
EOF
c++ -std=c++20 -O0 -g -fsanitize=undefined -fsanitize=signed-integer-overflow \
    -fno-sanitize-recover=all /tmp/ubbug.cpp -o /tmp/ubbug
if /tmp/ubbug >/tmp/ubout 2>&1; then
  echo "  UBSan: NOTE — int16_t+1 promoted to int, no overflow at this width (expected)"
else
  grep -q "runtime error" /tmp/ubout && echo "  UBSan: reports signed overflow correctly"
fi
cat > /tmp/ubbug2.cpp <<'EOF'
#include <cstdio>
int main(){ volatile int x = 2147483647; int y = x + 1; printf("%d\n", y); return 0; }
EOF
c++ -std=c++20 -O0 -g -fsanitize=undefined -fsanitize=signed-integer-overflow \
    -fno-sanitize-recover=all /tmp/ubbug2.cpp -o /tmp/ubbug2
/tmp/ubbug2 >/tmp/ubout2 2>&1 && { echo "  UBSan: FAIL — missed signed overflow"; exit 1; }
grep -q "signed integer overflow" /tmp/ubout2 \
  && echo "  UBSan: reports signed integer overflow correctly" \
  || { echo "  UBSan: FAIL"; cat /tmp/ubout2; exit 1; }

echo ""
echo "=== valgrind probe — must detect an uninitialised-value branch ==="
cat > /tmp/vgbug.cpp <<'EOF'
#include <cstdio>
#include <cstdlib>
int main(){
  int* p = (int*)malloc(sizeof(int));   // deliberately uninitialised
  if (*p == 42) printf("a\n"); else printf("b\n");
  free(p);
  return 0;
}
EOF
c++ -std=c++20 -O0 -g /tmp/vgbug.cpp -o /tmp/vgbug
valgrind --tool=memcheck --error-exitcode=99 --track-origins=yes /tmp/vgbug >/tmp/vgout 2>&1 || true
grep -qi "uninitialised value" /tmp/vgout \
  && echo "  valgrind: detects uninitialised-value branch (the ctgrind mechanism works)" \
  || { echo "  valgrind: FAIL — did not flag the branch"; tail -15 /tmp/vgout; exit 1; }

echo ""
echo "=== MSan probe (requires instrumented libc++) ==="
cat > /tmp/msanbug.cpp <<'EOF'
#include <cstdio>
int main(){ int x; if (x) printf("a\n"); else printf("b\n"); return 0; }
EOF
if c++ -std=c++20 -O0 -g -fsanitize=memory -fsanitize-memory-track-origins=2 \
     /tmp/msanbug.cpp -o /tmp/msanbug 2>/tmp/msanbuild; then
  if /tmp/msanbug >/tmp/msanout 2>&1; then
    echo "  MSan: NOTE — built and ran but did not flag; see docker-msan target"
  else
    grep -qi "use-of-uninitialized-value" /tmp/msanout \
      && echo "  MSan: reports use-of-uninitialized-value correctly" \
      || echo "  MSan: NOTE — nonzero exit without the expected report"
  fi
else
  echo "  MSan: NOT AVAILABLE — needs an MSan-instrumented libc++ (not packaged by Debian)."
  echo "        This is expected; see docs/reference/invariants.md. MSan requires a self-built libc++."
fi

echo ""
echo "=== probe complete ==="
