// Head-to-head: ours vs pq-crystals AVX2, BOTH LINKED INTO ONE PROCESS and measured
// interleaved. Comparing two projects' own speed-test binaries would compare harnesses,
// not implementations.
//
// Deterministic entry points on both sides -- our *_internal, their *_derand -- so the
// OS CSPRNG cost skews neither. pq-crystals is used for BENCHMARKING ONLY; it is built
// outside this repo and nothing is vendored or copied (ADR-003 / ADR-015).
#include "kem.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>
#include <x86intrin.h>
extern "C" {
int pqcrystals_kyber768_avx2_keypair_derand(uint8_t*, uint8_t*, const uint8_t*);
int pqcrystals_kyber768_avx2_enc_derand(uint8_t*, uint8_t*, const uint8_t*, const uint8_t*);
int pqcrystals_kyber768_avx2_dec(uint8_t*, const uint8_t*, const uint8_t*);
}
using namespace mlkem768;
static volatile int sink=0;
template<typename F> double med(F&&f,int r_,int in){std::vector<double> s;
 for(int r=0;r<r_;++r){auto a=__rdtsc();for(int i=0;i<in;++i)f();auto b=__rdtsc();
 s.push_back(double(b-a)/in);} std::sort(s.begin(),s.end()); return s[s.size()/2];}
int main(){
  std::uint8_t d[32],z[32],m[32],coins64[64];
  for(int i=0;i<32;i++){d[i]=(std::uint8_t)i;z[i]=(std::uint8_t)(i+64);m[i]=(std::uint8_t)(i*3+1);}
  std::memcpy(coins64,d,32); std::memcpy(coins64+32,z,32);
  std::vector<std::uint8_t> ek(EK_BYTES),dk(DK_BYTES),ct(CT_BYTES),ss(SS_BYTES);
  keygen_internal(d,z,ek.data(),dk.data()); encaps_internal(ek.data(),m,ct.data(),ss.data());
  std::vector<std::uint8_t> pk(1184),sk(2400),kct(1088),kss(32);
  pqcrystals_kyber768_avx2_keypair_derand(pk.data(),sk.data(),coins64);
  pqcrystals_kyber768_avx2_enc_derand(kct.data(),kss.data(),pk.data(),m);

  double okg=med([&]{std::uint8_t e[EK_BYTES],k[DK_BYTES];keygen_internal(d,z,e,k);sink^=e[0];},41,200);
  double kkg=med([&]{std::uint8_t p[1184],s[2400];pqcrystals_kyber768_avx2_keypair_derand(p,s,coins64);sink^=p[0];},41,200);
  double oen=med([&]{std::uint8_t c[CT_BYTES],s[SS_BYTES];encaps_internal(ek.data(),m,c,s);sink^=s[0];},41,200);
  double ken=med([&]{std::uint8_t c[1088],s[32];pqcrystals_kyber768_avx2_enc_derand(c,s,pk.data(),m);sink^=s[0];},41,200);
  double ode=med([&]{std::uint8_t s[SS_BYTES];decaps_internal(dk.data(),ct.data(),s);sink^=s[0];},41,200);
  double kde=med([&]{std::uint8_t s[32];pqcrystals_kyber768_avx2_dec(s,kct.data(),sk.data());sink^=s[0];},41,200);
  std::printf("H %.1f %.1f %.1f %.1f %.1f %.1f\n",okg,kkg,oen,ken,ode,kde);
  return 0;}
