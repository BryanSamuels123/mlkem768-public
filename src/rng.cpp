#include "rng.hpp"

#include <cstring>
#include <mutex>

#if defined(__APPLE__)
#include <sys/random.h>        // getentropy
#elif defined(__linux__)
#include <sys/random.h>        // getrandom
#include <errno.h>
#endif

namespace mlkem768 {
namespace {

// Dispatch state. A plain pair guarded by a mutex only on WRITE: reads are a relaxed
// load of two pointers, so the hot path takes no lock. set_rng is expected to be called
// once at startup, before any concurrent use.
std::mutex g_rng_mutex;
RngFn g_rng_fn = nullptr;
void* g_rng_ctx = nullptr;

// OS CSPRNG. getentropy/getrandom are thread-safe by contract.
bool os_random(std::span<std::uint8_t> out) noexcept {
#if defined(__APPLE__)
  // getentropy caps at 256 bytes per call; loop for larger requests.
  std::size_t off = 0;
  while (off < out.size()) {
    const std::size_t n = (out.size() - off > 256) ? 256 : out.size() - off;
    if (getentropy(out.data() + off, n) != 0) return false;
    off += n;
  }
  return true;
#elif defined(__linux__)
  std::size_t off = 0;
  while (off < out.size()) {
    const ssize_t n = getrandom(out.data() + off, out.size() - off, 0);
    if (n < 0) {
      if (errno == EINTR) continue;     // retry: not a failure
      return false;
    }
    off += static_cast<std::size_t>(n);
  }
  return true;
#else
#error "No OS CSPRNG available for this platform; inject one with set_rng()."
#endif
}

}  // namespace

void set_rng(RngFn fn, void* ctx) noexcept {
  std::lock_guard<std::mutex> lock(g_rng_mutex);
  g_rng_fn = fn;
  g_rng_ctx = ctx;
}

bool randombytes(std::span<std::uint8_t> out) noexcept {
  if (out.empty()) return true;
  RngFn fn;
  void* ctx;
  {
    std::lock_guard<std::mutex> lock(g_rng_mutex);
    fn = g_rng_fn;
    ctx = g_rng_ctx;
  }
  if (fn != nullptr) return fn(out, ctx);
  return os_random(out);
}

}  // namespace mlkem768
