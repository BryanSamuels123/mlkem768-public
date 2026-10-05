#pragma once
// ML-KEM-768 — the complete public interface. NIST FIPS 203.
//
// This is the only header a consumer of this library includes, and it deliberately depends
// on nothing but the C++ standard library: no header from the implementation's src/ tree is
// reachable from here. `gmake consumer-test` enforces that by compiling a program against
// the INSTALLED tree with src/ absent from the include path.
//
// ---------------------------------------------------------------------------------------
// WHAT THIS LIBRARY IS FOR, in plain terms
//
// ML-KEM is a *key encapsulation mechanism*. It lets two parties end up holding the same
// 32-byte secret without that secret ever crossing the wire, and it is designed to stay
// secure against an attacker holding a large quantum computer, which is what distinguishes
// it from the elliptic-curve key exchanges in use today.
//
// The shape of it is three operations:
//
//   1. The receiver calls `keygen`, keeping a private DECAPSULATION key and publishing a
//      public ENCAPSULATION key.
//   2. The sender calls `encaps` with that public key. It returns a CIPHERTEXT to send
//      back, and a 32-byte SHARED SECRET to keep.
//   3. The receiver calls `decaps` with the ciphertext and its private key, and obtains
//      the same 32-byte shared secret.
//
// The shared secret is a uniformly random key, suitable for feeding to a symmetric cipher
// or a key-derivation function. It is NOT a message channel: you cannot choose what it is.
//
// ---------------------------------------------------------------------------------------
// WHICH VALUES ARE SECRET
//
// Marked on each declaration below, and worth stating once up front:
//
//   SECRET  the decapsulation key, in full, and any seed it was derived from; every shared
//           secret. Leaking any of these breaks the exchange it belongs to, and leaking a
//           decapsulation key breaks every exchange made with it, past and future.
//   PUBLIC  the encapsulation key and the ciphertext. Both are designed to be sent in the
//           clear and observed.
//
// This implementation runs in constant time with respect to every secret above: its timing
// and memory-access pattern do not depend on their values. It also overwrites secret
// intermediate values before they go out of scope. See the project README for what that
// does and does not cover.
//
// ---------------------------------------------------------------------------------------
// THREAD SAFETY
//
// Every function here is reentrant and holds no mutable global state, with one exception:
// `set_rng` installs a process-wide hook. Call it once, before any thread that uses this
// library exists. Concurrent calls to keygen/encaps/decaps from different threads are safe.
//
// ---------------------------------------------------------------------------------------
// NOT PROVIDED, so you do not go looking:
//
//   * No batch interface. Excluded by decision: a single operation takes microseconds, so
//     spreading one across cores costs more than it saves. Call it from several threads if
//     you need throughput.
//   * No seed-expanded key interface. FIPS 203 permits storing a 64-byte seed instead of
//     the 2400-byte decapsulation key, and this library does not currently expose that.
//   * Only ML-KEM-768. Not the 512 or 1024 parameter sets.

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace mlkem768 {

// --------------------------------------------------------------------------------------
// Sizes. Every one of these is fixed by FIPS 203 for ML-KEM-768; none is configurable.
// --------------------------------------------------------------------------------------

inline constexpr std::size_t EK_BYTES = 1184;   // encapsulation key  (public)
inline constexpr std::size_t DK_BYTES = 2400;   // decapsulation key  (SECRET)
inline constexpr std::size_t CT_BYTES = 1088;   // ciphertext         (public)
inline constexpr std::size_t SS_BYTES = 32;     // shared secret      (SECRET)

using EncapsKey    = std::array<std::uint8_t, EK_BYTES>;   // public
using DecapsKey    = std::array<std::uint8_t, DK_BYTES>;   // SECRET
using Ciphertext   = std::array<std::uint8_t, CT_BYTES>;   // public
using SharedSecret = std::array<std::uint8_t, SS_BYTES>;   // SECRET

// --------------------------------------------------------------------------------------
// Result status. Every entry point reports failure this way; none throws, and the library
// is built without exceptions.
// --------------------------------------------------------------------------------------
enum class Status {
  Ok,                 // succeeded
  RngFailure,         // the random number generator failed; NO output was produced
  InvalidEncapsKey,   // encapsulation key rejected: wrong size, or malformed contents
  InvalidDecapsKey,   // decapsulation key rejected: wrong size, or internally inconsistent
  InvalidCiphertext,  // ciphertext rejected: WRONG SIZE ONLY -- see the note on `decaps`
};

// --------------------------------------------------------------------------------------
// The ABI. These take pointers and lengths, which is what the compiled library exports.
// Prefer the typed overloads further down; these exist for callers holding raw buffers.
// --------------------------------------------------------------------------------------

// Generate a key pair, drawing randomness from the configured generator.
//   ek  OUT, EK_BYTES, public
//   dk  OUT, DK_BYTES, SECRET
// Returns RngFailure if randomness could not be obtained, in which case neither output is
// usable. There is no other failure mode.
[[nodiscard]] Status keygen(std::uint8_t ek[EK_BYTES], std::uint8_t dk[DK_BYTES]) noexcept;

// Encapsulate against someone's public key.
//   ek/ek_len  IN,  the recipient's encapsulation key. Checked: wrong length or malformed
//                   contents give InvalidEncapsKey and produce no output.
//   ct         OUT, CT_BYTES, public -- send this to the recipient
//   ss         OUT, SS_BYTES, SECRET -- keep this
// Draws fresh randomness on every call: calling it twice with the same key correctly gives
// two different ciphertexts and two different shared secrets.
[[nodiscard]] Status encaps(const std::uint8_t* ek, std::size_t ek_len,
                            std::uint8_t ct[CT_BYTES],
                            std::uint8_t ss[SS_BYTES]) noexcept;

// Decapsulate a ciphertext with your private key.
//   dk/dk_len  IN,  SECRET. Wrong length or internal inconsistency gives InvalidDecapsKey.
//   ct/ct_len  IN,  public. Wrong length gives InvalidCiphertext.
//   ss         OUT, SS_BYTES, SECRET
//
// READ THIS BEFORE HANDLING THE RESULT. A ciphertext that is the right SIZE but otherwise
// wrong -- corrupted in transit, or forged -- does NOT produce an error. It returns Ok and
// a shared secret that is deterministic, unpredictable, and different from the sender's.
// This is required by FIPS 203 and is called implicit rejection: reporting "invalid
// ciphertext" would hand an attacker a decryption oracle, which is a practical attack
// against this family of schemes.
//
// The consequence for you: **do not treat Ok as proof that the exchange succeeded.** Both
// sides must confirm they hold the same secret before relying on it -- normally by using it
// in an authenticated protocol, where a mismatch simply makes authentication fail. If you
// need an explicit check, compare a MAC computed under the shared secret; never compare the
// secrets themselves over the wire.
[[nodiscard]] Status decaps(const std::uint8_t* dk, std::size_t dk_len,
                            const std::uint8_t* ct, std::size_t ct_len,
                            std::uint8_t ss[SS_BYTES]) noexcept;

// Validate an encapsulation key without using it (FIPS 203 §7.2): correct length, and every
// packed coefficient within range. Returns true if the key is acceptable. `encaps` performs
// this check itself, so calling it first is optional.
[[nodiscard]] bool check_encaps_key(const std::uint8_t* ek, std::size_t len) noexcept;

// Validate a decapsulation key without using it (FIPS 203 §7.3): correct length, and the
// embedded hash consistent with the embedded public key. Returns true if acceptable.
// `decaps` performs this check itself. Input is SECRET.
[[nodiscard]] bool check_decaps_key(const std::uint8_t* dk, std::size_t len) noexcept;

// --------------------------------------------------------------------------------------
// Random number generator injection.
//
// By default the library uses the operating system's generator -- `getentropy` on macOS,
// `getrandom` on Linux -- which is appropriate for general use. Replace it only if you need
// a specific validated generator, or determinism for testing.
//
// `fn` must fill the whole span and return false on failure; returning true without filling
// it is a silent, catastrophic security bug. `ctx` is passed back to `fn` untouched.
// Passing nullptr restores the default.
//
// THE INJECTED GENERATOR MUST BE THREAD-SAFE OR PER-THREAD. A generator that is neither,
// shared across threads, can repeat its output with no visible sign, and repeated
// randomness in keygen or encaps breaks the scheme outright.
//
// `set_rng` itself is not synchronised: install the hook before starting threads.
// --------------------------------------------------------------------------------------
using RngFn = bool (*)(std::span<std::uint8_t> out, void* ctx) noexcept;
void set_rng(RngFn fn, void* ctx) noexcept;

// --------------------------------------------------------------------------------------
// Typed overloads. These are the ones to use: the sizes come from the types, so a
// wrong-sized buffer is a compile error rather than a runtime status. They are thin inline
// forwarders and add no cost.
// --------------------------------------------------------------------------------------

// See `keygen` above. dk is SECRET.
[[nodiscard]] inline Status keygen(EncapsKey& ek, DecapsKey& dk) noexcept {
  return keygen(ek.data(), dk.data());
}

// See `encaps` above. ss is SECRET; ct is public.
[[nodiscard]] inline Status encaps(const EncapsKey& ek, Ciphertext& ct,
                                   SharedSecret& ss) noexcept {
  return encaps(ek.data(), ek.size(), ct.data(), ss.data());
}

// See `decaps` above, INCLUDING the note on implicit rejection -- Ok does not mean the
// ciphertext was genuine. dk and ss are SECRET.
[[nodiscard]] inline Status decaps(const DecapsKey& dk, const Ciphertext& ct,
                                   SharedSecret& ss) noexcept {
  return decaps(dk.data(), dk.size(), ct.data(), ct.size(), ss.data());
}

[[nodiscard]] inline bool check_encaps_key(std::span<const std::uint8_t> ek) noexcept {
  return check_encaps_key(ek.data(), ek.size());
}

[[nodiscard]] inline bool check_decaps_key(std::span<const std::uint8_t> dk) noexcept {
  return check_decaps_key(dk.data(), dk.size());
}

}  // namespace mlkem768
