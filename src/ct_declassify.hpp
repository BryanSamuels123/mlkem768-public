#pragma once
// Declassification points for constant-time testing.
//
// ############################################################################
// # DECLASSIFICATION IS DANGEROUS. Each use asserts "this value is PUBLIC     #
// # OUTPUT, so timing dependence on it is not a leak." A wrong assertion      #
// # silences a REAL leak and makes ctgrind agree with you.                    #
// #                                                                           #
// # Every call site must justify itself in a comment AND have an ADR entry.   #
// # Never add one to make a test pass.                                        #
// ############################################################################
//
// Compiles to NOTHING unless MLKEM_CT_TESTING is defined, which only the ctgrind
// binaries' library build sets. The shipped library contains no trace of it.
//
// Why it is needed at all: memcheck propagates "secret" through every derivation. It
// cannot know that a value derived from a secret is subsequently PUBLISHED. rho is the
// canonical case -- it is G(d || k)[0:32], so it inherits d's marking, yet it is copied
// verbatim into ek and handed to the world.

#include <cstddef>

#if defined(MLKEM_CT_TESTING) && __has_include(<valgrind/memcheck.h>)
#include <valgrind/memcheck.h>
#define MLKEM_CT_DECLASSIFY(p, n) VALGRIND_MAKE_MEM_DEFINED((p), (n))
#else
#define MLKEM_CT_DECLASSIFY(p, n) ((void)(p), (void)(n))
#endif
