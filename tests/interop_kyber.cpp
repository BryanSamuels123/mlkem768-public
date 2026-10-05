// Cross-implementation interop (spec 10.5), never done in Phase 7.
//
// KATs make a failure unlikely, but this is the one test that catches a SERIALIZATION
// bug two self-consistent implementations could share -- or, more usefully, one that
// only ours has and the ACVP vectors happen not to exercise.
#include "kem.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
extern "C" {
int pqcrystals_kyber768_avx2_keypair_derand(uint8_t*, uint8_t*, const uint8_t*);
int pqcrystals_kyber768_avx2_enc_derand(uint8_t*, uint8_t*, const uint8_t*, const uint8_t*);
int pqcrystals_kyber768_avx2_dec(uint8_t*, const uint8_t*, const uint8_t*);
}
using namespace mlkem768;
int main(){
  std::uint32_t st=20260928u; auto rnd=[&]{st^=st<<13;st^=st>>17;st^=st<<5;return st;};
  const int N=10000;
  long badA=0,badB=0,badKey=0,badCt=0;

  // Direction A: OUR keygen + OUR encaps  ->  THEIR decaps
  for(int t=0;t<N;++t){
    std::uint8_t d[32],z[32],m[32],coins[64];
    for(int i=0;i<32;i++){d[i]=(std::uint8_t)rnd();z[i]=(std::uint8_t)rnd();m[i]=(std::uint8_t)rnd();}
    std::memcpy(coins,d,32); std::memcpy(coins+32,z,32);
    std::vector<std::uint8_t> ek(EK_BYTES),dk(DK_BYTES),ct(CT_BYTES),ss(SS_BYTES),ss2(32);
    keygen_internal(d,z,ek.data(),dk.data());
    // Bonus cross-check: same seeds must give the SAME keypair on both sides.
    std::vector<std::uint8_t> pk(1184),sk(2400);
    pqcrystals_kyber768_avx2_keypair_derand(pk.data(),sk.data(),coins);
    if(std::memcmp(ek.data(),pk.data(),1184)!=0 || std::memcmp(dk.data(),sk.data(),2400)!=0) ++badKey;
    encaps_internal(ek.data(),m,ct.data(),ss.data());
    pqcrystals_kyber768_avx2_dec(ss2.data(),ct.data(),dk.data());
    if(std::memcmp(ss.data(),ss2.data(),32)!=0) ++badA;
  }
  // Direction B: THEIR keygen + THEIR enc  ->  OUR decaps
  for(int t=0;t<N;++t){
    std::uint8_t m[32],coins[64];
    for(int i=0;i<64;i++) coins[i]=(std::uint8_t)rnd();
    for(int i=0;i<32;i++) m[i]=(std::uint8_t)rnd();
    std::vector<std::uint8_t> pk(1184),sk(2400),kct(1088),kss(32),ss2(SS_BYTES);
    pqcrystals_kyber768_avx2_keypair_derand(pk.data(),sk.data(),coins);
    pqcrystals_kyber768_avx2_enc_derand(kct.data(),kss.data(),pk.data(),m);
    // Bonus: our encaps on THEIR public key must produce the same ciphertext.
    std::vector<std::uint8_t> oct(CT_BYTES),oss(SS_BYTES);
    encaps_internal(pk.data(),m,oct.data(),oss.data());
    if(std::memcmp(oct.data(),kct.data(),1088)!=0) ++badCt;
    decaps_internal(sk.data(),kct.data(),ss2.data());
    if(std::memcmp(kss.data(),ss2.data(),32)!=0) ++badB;
  }
  std::printf("  A  ours encaps -> pq-crystals decaps : %d/%d shared secrets match%s\n", N-(int)badA,N,badA?"  *** FAIL ***":"");
  std::printf("  B  pq-crystals enc -> ours decaps    : %d/%d shared secrets match%s\n", N-(int)badB,N,badB?"  *** FAIL ***":"");
  std::printf("  bonus: identical keypair from identical seeds : %d/%d%s\n", N-(int)badKey,N,badKey?"  *** FAIL ***":"");
  std::printf("  bonus: identical ciphertext from identical m  : %d/%d%s\n", N-(int)badCt,N,badCt?"  *** FAIL ***":"");
  return (badA||badB||badKey||badCt)?1:0;
}
