# ML-KEM-768 — what this is, how it was built, and what was measured

*Version 0.1.0. Written for an experienced C++ engineer with no background in cryptography
and no knowledge of this project. Nothing here should require looking anything up; if it
does, that is a defect in this document. Every term is explained where it first appears.*

**The machine every number in this document came from**, since none of them mean anything
without it: an Intel Core i7-9750H, 6 cores at a 2.6 GHz base clock, compiled with Apple
clang 16 for macOS on x86-64, optimization level 3, targeting this processor's own
instruction set. One laptop. Figures are ratios measured on that machine against itself;
they are not portable absolute numbers.

**A note on units, because two different ones appear below.** Timing is reported in
*processor time ticks*, read from the processor's timestamp counter. On this machine that
counter runs at a fixed rate and is *not* the same as counting instruction cycles — it does
not speed up when the processor does. So a tick is a unit of elapsed time — on this
part the counter happens to run at the 2.6 GHz base clock, making one tick 0.385 nanoseconds —
and ratios of ticks are meaningful while absolute tick counts should not be read as counts of
work done, because the processor may have been running faster or slower than its base clock at
the time.

**Two phrases used throughout, defined here.** *Through the public interface* means measured
from outside, by timing a whole call to one of the three public operations — which is what an
attacker can actually do. *Inside a routine* means timing one internal function directly,
which requires being inside the process and is far more sensitive. A timing effect can be real
inside a routine and invisible through the interface; section 9 turns on exactly that
distinction. A *side channel* is any way information leaks other than through the intended
output — how long something took, how much power it drew, what sounds it made.

**This document uses "ticks" for every measured duration.** The word "cycles" appears only
where it genuinely means processor clock cycles — twice: in section 4 about how long a division
takes, and in section 9 about instruction latencies — and never as a synonym for ticks.

---

## The one-page version

**The problem.** When two computers that have never met want to talk privately, they must
first agree on a secret key. They do that over a network anyone can watch, so the agreement
procedure has to be one an eavesdropper can observe in full and still not learn the key. The
methods in use today rest on mathematics that a large quantum computer would break. Such a
machine does not exist yet, but recordings made today can be decrypted the day it does — so
anything meant to stay private for years has to switch now. **ML-KEM is the replacement the
United States standards body selected**, published in 2024 as a federal standard. This
project is a from-scratch implementation of it in C++20.

**What it does.** Three operations, and the names used throughout this document:

1. **Key generation** — one side produces a *public key* it publishes and a *private key* it
   keeps.
2. **Encapsulation** — the other side takes that public key and produces two things: a
   32-byte secret it keeps, and a block of bytes called a *ciphertext* to send back.
3. **Decapsulation** — the first side feeds that ciphertext and its private key in, and gets
   the identical 32-byte secret out.

An observer who saw the public key and the ciphertext cannot work out the secret. That 32-byte
value then becomes the key for ordinary fast encryption. "Encapsulation" is the standard's
word; you can read it as "seal a fresh random secret so only the key-holder can unseal it".

**How it was built, and why in that order.** First a deliberately slow, obviously-correct
version was written — a direct transcription of the standard's own pseudocode, with no
cleverness anywhere. This document calls it **the slow model**. It was checked against the
official test vectors published by the standards body: fixed inputs with known correct
outputs. Only once it reproduced all 80 of them was a fast version written, and every piece of
the fast version was then checked against the slow model. This ordering is the single most
important decision in the project. The slow model is an *independent* answer to "what should
this compute?", so a disagreement localizes the bug to one function immediately, instead of
surfacing as a wall of wrong bytes at the end.

**The results.**

| | |
|---|---|
| Correctness | All 80 official test vectors pass, against both the fast version and the slow model |
| Speed gained | **3.3× to 3.8× faster** than the version that first passed those vectors |
| Versus the algorithm designers' own implementation | this one takes **about 41% more time** — section 5 explains what does and does not account for that |
| Energy | about **294–350 millionths of a joule** per operation |
| Timing safety | no dependence on *secret* values found through the public interface, down to a measured floor of **about 100 ticks** — see the caveat below |

**One caveat on that last row, stated here so the one-page version is not misleading.** A
very small timing effect *was* found deep inside one routine — about 0.07 ticks per call
typically, and never more than about 0.2 in any run; section 9 uses the larger figure as the
bound. It
turned out to appear *more strongly* in an independent implementation of the same algorithm on
the same processor, so whatever causes it is not something this code introduced. It is also
more than a thousand times smaller than anything detectable through the public interface.
Section 9 gives the evidence and states what remains unknown about it.

**The idea that runs through all the testing.** A test that passes tells you nothing unless
you already know it *can* fail. So before trusting any check, a bug it was supposed to catch
was deliberately introduced, and the check had to catch it. This sounds like extra work and it
repeatedly turned out to be the only thing standing between a green result and a false one.
**Four separate checks in this project were discovered to be incapable of failing**, and every
one of them was found this way rather than by inspection.

**What it is not.** This is not validated or certified software, it has had no independent
security audit, and it should not be used to protect anything real. It is a complete,
carefully measured implementation, and that is a different claim.

---

## 1. Why quantum computers force a change

Today's key agreement rests on problems that are easy in one direction and believed hard in
reverse — given two large primes, multiplying them is trivial; given the product, recovering
the primes is not. The security of most of the internet reduces to that asymmetry, or to a
close relative of it.

In 1994 Peter Shor showed that a sufficiently large quantum computer could run an algorithm
that reverses exactly those problems efficiently. Not faster by a constant factor —
fundamentally faster, turning a computation that would outlast the universe into one that
finishes. No machine anywhere near large enough exists today, and it is genuinely unclear
whether one will.

The reason to act anyway is **recording**. An adversary can capture encrypted traffic now,
store it, and decrypt it years later when the machine arrives. Any secret that must stay
secret for a decade is therefore already exposed if it was agreed using today's methods. This
is usually called *harvest now, decrypt later*, and it is why standards bodies moved before
the threat was real.

After an eight-year public competition, the US National Institute of Standards and Technology
selected a submission whose authors named it **CRYSTALS-Kyber**, and published a standardized
version of it in August 2024 as **ML-KEM** — *Module-Lattice-based Key Encapsulation
Mechanism*. "Module-lattice" names the mathematical structure it rests on, explained in the
next section. The **768** identifies one of three sizes the standard defines; this one aims at
a security level comparable to a 192-bit key in a conventional cipher, meaning an attacker's
best option should be searching roughly 2^192 possibilities. The other two sizes trade
security against key and message size.

> **A trap worth knowing about, because it wastes days.** ML-KEM and the Kyber submission it
> came from are *not the same algorithm*. Standardization changed three small details, and
> most material written before mid-2024 — including the designers' own code and papers from
> that era — describes the older version. Each difference produces an implementation that is
> entirely self-consistent: it agrees with itself, round-trips correctly, and passes every
> test you write yourself, while disagreeing with the official vectors. That failure mode is
> nearly opaque without knowing to look for it. So, concretely, the three changes are:
>
> 1. ML-KEM mixes one extra byte into the very first hash of key generation, identifying which
>    of the three sizes is in use. Kyber does not. Omit it and every key you generate is wrong
>    but perfectly self-consistent.
> 2. Kyber hashed the 32 random bytes before using them as the message. ML-KEM does not.
> 3. Kyber ran the final shared secret through one more hashing step. ML-KEM does not — the
>    secret comes straight out of the hash that also produces the encryption randomness.
>
> All three are one-line differences, and each on its own produces an implementation that
> passes every test you write yourself and fails the official vectors.
>
> This also explains something in section 6 that otherwise looks anachronistic: a timing bug
> found in the designers' reference code in 2023, a year before ML-KEM was published. That
> code implemented Kyber, the predecessor. The bug is in a step both versions share.

## 2. How ML-KEM works, at the level of intuition

You do not need this section to use the library, but it explains why the code looks the way it
does — and in particular why a *deliberately imperfect* computation is the correct one.

**The hard problem is about lattices.** Take a grid of points stretching off in many
directions — not a neat square grid, but a skewed one. The grid is described by a handful of
*basis vectors*: arrows from the origin whose whole-number combinations generate every point in
it. Different sets of basis vectors can describe the very same grid while making it look easy
or hopeless to work with, which is the hinge the whole scheme turns on. In
two or three dimensions, finding the grid point nearest to some arbitrary position is easy. In
several hundred dimensions, with a badly-chosen basis, it becomes intractable, and no quantum
algorithm is known that helps. ML-KEM's security rests on a problem of that shape. "Module"
in the name refers to the particular algebraic structure used to build it.

**The concrete version is arithmetic with deliberate errors.** Instead of geometry, think of a
system of linear equations. Given a matrix **A** and a vector **b** where **b = A·s**, you can
recover the secret **s** by ordinary linear algebra — schoolchild material. Now add a small
random error to each equation, so **b = A·s + e** where every entry of **e** is a small
number. Recovering **s** now appears to be extremely hard, in high dimension, even though each
individual equation is *nearly* right. That is the whole trick: **the noise is what makes it
secure.**

**Where the numbers come from, and why polynomials.** The entries above are not single
integers but *polynomials* — lists of 256 coefficients, each an integer modulo the prime
3329. A polynomial is used rather than a plain number because multiplying two of them mixes
all 256 coefficients together in one operation, which buys a large problem dimension for a
small amount of arithmetic, and because it admits a fast multiplication algorithm (section 3).
So **A** is a 3×3 matrix of such polynomials and **s** is a 3-element vector of them — that
"3" is what the *module* structure means concretely, and it is where the 768 in the name comes
from (3 × 256 = 768 coefficients of secret).

**The public key carries a seed instead of the matrix.** A 3×3 matrix of 256-coefficient
polynomials would be about 3.5 kilobytes, so the public key ships a 32-byte seed instead and
both sides
regenerate **A** from it by hashing. That regeneration is called *expanding* the matrix, and it
is the largest single consumer of time in the scheme — it is almost entirely hashing.

That accounts for the sizes quoted in section 8. The 1184-byte public key is that 32-byte
seed plus 1152 bytes holding the noisy product **b** — three polynomials of 256 coefficients
packed at 12 bits each, which is 1152 exactly. The 2400-byte private key holds the secret
vector **s** in the same packed form, a copy of the public key, a hash of it, and 32 further
random bytes used for the rejection behaviour in section 8. The 64-byte seed mentioned in
section 9 is the pair of 32-byte random values that key generation starts from — one seeding
the secret and noise, one being those 32 rejection bytes — from which the whole 2400-byte
private key can be recomputed.

**Where the secret being agreed actually enters.** Encapsulation picks 32 random bytes, and
those bytes *are* the message. They are turned into a polynomial by mapping each bit to one of
two widely separated values: bit 0 becomes 0, and bit 1 becomes roughly half of 3329. That
polynomial is added to another noisy product of the public key, and the result — plus one more
noisy term — is the ciphertext. So the ciphertext is "the message, buried in noise, in a way
only the private key can dig out". The 32-byte shared secret is then derived by hashing that
message together with a hash of the public key.

**Why decryption tolerates errors, which is the part that surprises people.** The receiver's
computation does not recover the sender's polynomial exactly. It recovers something *close to
it*, because both sides deliberately added noise. The final step looks at each coefficient and
asks which of the two values above — 0, or half of 3329 — it is nearer, and reads off the
corresponding bit. Because the accumulated noise is far smaller than the gap between those two
values, every coefficient lands on the right side and both sides end up with identical bits.

The ciphertext is also **compressed** before transmission: each coefficient is rounded to
fewer bits than it strictly needs — two widths are used, 10 bits for the bulk of it and 4 bits
for the part carrying the message — which shrinks the message and adds yet more noise that the
same margin absorbs. Decapsulation therefore begins by *decompressing* — expanding those
rounded values back to full-width coefficients. That step matters below.

This all has a consequence that shaped a large part of the testing. **The rounding absorbs
small mistakes.** An implementation bug that perturbs an intermediate value slightly still
produces the right answer, because the rounding corrects it. All the standard tests pass. But
every such bug spends part of the noise margin that makes decryption reliable, and that margin
is what holds the **failure rate — the chance that one decapsulation returns the wrong secret
despite everything being implemented correctly — at about 1 in 2^165**. That is a number so
small it will never be observed in practice. Worse, decapsulation failures are themselves a
known avenue of attack against this family of schemes, so quietly eating that margin is a
genuine security regression that no functional test reports.

The practical upshot: **for every function on the decapsulation path, the official test
vectors are not a meaningful check.** Only comparing against the slow model, value by value,
catches these. This was verified rather than assumed: a deliberate error was introduced into
the decompression step described above, flipping the lowest bit of each coefficient, and all
80 official vectors still passed. Only when the error was moved to a much higher bit — worth
1024 instead of 1, so a perturbation comparable to the noise margin itself — did 5 of the 80
fail. **Those same 5 are the only vectors that exercise a successful decapsulation at all**;
the other 75 cover key generation, encapsulation, deliberately invalid inputs, and the
rejection path described in section 8.

## 3. How the project was built

**Phase one: the slow model.** A literal transcription of the standard's pseudocode.
Polynomial multiplication done the obvious way — every term against every term, 256 × 256
products — rather than by the fast method the real implementation uses. Exact integer
arithmetic throughout, no representation tricks. The goal was code whose correctness you can
check by reading it against the standard line by line.

**Phase two: prove the slow model against the official vectors.** This is the step that makes
everything after it work. Had the model merely been self-consistent, it could have shared a
misreading of the standard with the fast version, and the two would have agreed all the way to
a failing final test. Because it reproduces the official vectors exactly, every later
comparison against it is *equivalent to* an official-vector test, but localized to a single
function.

**Phase three: the fast version, checked against the model at every step.** In order: the hash
functions, the arithmetic core, data packing, random sampling — the step that turns hash output
into the small error values **e** described in section 2, and into the matrix **A** — then the
scheme itself. Each
piece was compared against its slow counterpart on random inputs — and where the input space
was small enough, on *every possible input* rather than a sample.

Two examples of that, both in the modular-arithmetic core. One routine reduces an arbitrary
16-bit value into range; it takes a single 16-bit input, so it was checked on all 65,536
possible values. The other converts values out of the scaled internal representation
described below. Its correctness argument holds only for inputs bounded by 3329 × 65,536, and
**every one of the 218,169,343 distinct values in that legal range was tested** — the whole
range, not a sample. Exhaustive verification, where affordable, removes the question of whether
the sample was lucky.

**The scaled internal representation, since section 3 and section 9 both refer to it.** Every
value is held multiplied by a fixed constant — a technique called *Montgomery form* — because
in that form the expensive part of multiplying two numbers modulo 3329 becomes a shift instead
of a division. The cost is bookkeeping: each operation changes how many factors of that
constant a value carries, so the rules for which functions add one and which remove one must be
exactly right. Get the direction backwards and results come out wrong by a constant factor,
which still round-trips correctly and passes a great many tests. Section 9 records what happened
when this project's own notes described that convention wrongly.

**What "arithmetic reduction" means, since it recurs below.** All the arithmetic happens modulo
3329, but taking a remainder with a division instruction is slow and — as section 6 explains —
unsafe here. Instead, values are allowed to drift outside the range 0–3328 and are pulled back
periodically by a short sequence of multiplies and shifts that computes the remainder without
dividing. Each such pull-back is a *reduction*. They cost time, so the optimization work
included proving that some of them were unnecessary because the values could not have drifted
far enough to overflow a 16-bit integer.

**Phase four: make it fast.** The single largest win was noticing that most of the time was
spent hashing, and that the scheme calls the hash function on several independent inputs at
once. The processor's vector registers hold four 64-bit lanes side by side, so **four** hash
computations were restructured to run simultaneously in one set of registers — four because
that is the register width, not because the algorithm asks for four. After that came a
hand-written vectorized version of the fast polynomial multiplication, removal of the
provably-unnecessary reductions, and vectorized data packing. After every single change the
official vectors had to still pass; a change that broke them was reverted rather than debugged.

**About that fast multiplication.** Multiplying two 256-coefficient polynomials directly costs
256 × 256 products. There is a standard technique — the *number-theoretic transform* — that
converts each polynomial into a different representation in which multiplication becomes
merely coefficient-by-coefficient, 256 products instead of 65,536, with a transform costing about 256 × 7 operations at
each end — seven passes over the coefficients, not eight, because of how 3329 factorizes. It is the same idea as the Fast Fourier Transform, done
in modular integer arithmetic instead of with complex numbers. This document calls it **the
fast transform**. It is the most performance-critical piece of *arithmetic* in the
library — hashing costs more overall — and the subject of the open question in section 9.

**The library contains two versions of the hot routines**, one using the processor's vector
instructions and one in plain portable C++, and picks between them when it first runs by
asking the processor what it supports. Both are required to produce bit-identical output, and
a test enforces that — which is what makes it safe to have the official vectors exercise only
whichever one the test machine selects.

**Phase five: verify the security properties**, then package it. Verification is sections 6
and 7; using the packaged result is section 8.

## 4. The testing philosophy, and four times it caught something real

The rule: **prove a check can fail before trusting that it passes.** Concretely — introduce
the exact bug the check exists to catch, confirm it is caught, then remove it.

This is more than diligence. A check that cannot fail is *worse* than no check, because it
produces the reassuring output of a check that works. Four were found here.

**A test that was asserting nothing.** A test intended to confirm correct behaviour at an exact
arithmetic tie — where a value falls precisely halfway between two outputs and the rounding
direction matters — was passing. Investigation showed the range of inputs it searched
contained **no ties at all**. It had never tested anything. As it turns out, the compression
step can never produce a tie, and the decompression step produces exactly one tie at each of the
two widths; that asymmetry is worth knowing and was discovered
only because the test was interrogated rather than believed.

**A search that reported success because its pattern was wrong.** One requirement is that the
compiled library contain no division instructions, because division takes a variable number of
cycles depending on its operands — which can leak secret values through timing (section 6).
The check searched the compiled output and reported zero divisions. It also reported zero in a
version where a division had been *deliberately inserted*. The search pattern was subtly
wrong. Once fixed, it immediately found a real division the compiler had inserted on its own,
in code where the source contained no division at all.

**A memory-error detector that was not watching the library.** Late in the project a fuzzing
setup was built — software that hammers the code with machine-generated input looking for
crashes — with a memory-error detector attached. A deliberate read past the end of an array
was planted, and nothing found it through 400,000 attempts. Then a hand-crafted input
*guaranteed* to trigger it also found nothing. That distinguished "the generator cannot reach
it" from "the detector cannot see it": only the test harness had been compiled with the
detector, while the library itself was an ordinary optimized build, and a memory-error
detector cannot report a fault in code it did not instrument. The whole arrangement had been a
crash detector for the test harness. Once the library was instrumented too, the fault was
found unaided in about 18,000 attempts.

That fix also changed what the coverage figures meant, and **this document contains two
different branch counts** which must not be confused:

- **Branches reached across the whole test program** — harness, slow model and library
  together. This went from **163 to 412** after the library was instrumented, two and a half
  times more, because the earlier figure had not been counting the library at all.
- **Branches reached in the library alone** — **202 of its 744**, the figure reported in
  section 9. That is the one that says anything about how much of *the library* was
  exercised. The library is therefore about half of the larger figure — 202 of 412, with the
  other 210 in the harness and the model — so the 412 is not a library coverage number.

Both are branch counts. They differ because they count different programs.

**A guarantee that quietly became vacuous.** Secret values are overwritten before going out of
scope, and a check confirmed the overwriting survives optimization. Separately, one value was
reclassified as non-secret — the 32-byte seed from which the public matrix is expanded, which
the standard publishes inside the public key anyway, so treating it as secret was simply
wrong. But an existing test had depended on that value being treated as secret. It did not
start failing — it became *vacuous*, still passing while testing nothing. That is strictly
worse than a failure, and it was caught only because the test demanded a specific error code
rather than merely "something went wrong".

Two refinements came out of these, both now standing rules. First: **a planted bug must survive
compilation.** Twice, a deliberate fault was optimized away before the check ran, so the clean
result meant nothing. Second: **a planted bug must be large enough to see.** The one-bit
decompression error described in section 2 was neither removed nor undetectable — the
algorithm simply absorbed it. The right question is not "did the check pass?" but "what size
of fault could this check actually detect?"

## 5. Performance

Two separate comparisons follow, and **they were measured with two different harnesses, which
is why the same build appears with slightly different numbers in each.** That is stated up
front because the discrepancy is visible and would otherwise look like an error:

- The first compares this project against *its own past*, using this project's benchmark
  program built once per version.
- The second compares against *another project*, which requires linking both libraries into
  one program and alternating between them — a different harness, with different surrounding
  code and therefore slightly different cache and branch-prediction behaviour.

The same build measures about 3–8% faster in the first than in the second. Neither is more
correct; each is internally consistent, and **only ratios within a single table should be
compared.** Reading a number out of one table and into the other is not valid.

### Against its own past

Once the implementation first passed the official vectors, that commit was marked as the
correctness baseline and all optimization measured against it:

| operation | baseline | v0.1.0 | speedup |
|---|---|---|---|
| Key generation | 117,788 | 35,701 | **3.30×** |
| Encapsulation | 128,717 | 37,343 | **3.45×** |
| Decapsulation | 155,440 | 40,540 | **3.83×** |

Ticks per operation, as defined at the top. Measured by running both versions **alternately in
one session** rather than one after the other, because a machine warms up, changes clock speed
and gets interrupted, and measuring one version fully before the other attributes all of that
drift to whichever went second. 24 alternating pairs; medians.

**How much of that is measurement error, stated rather than hoped.** The same run also timed a
function that is *byte-identical* in both versions — third-party hashing code included
unmodified from elsewhere. It should show a ratio of exactly 1.00. It showed **1.013**. So this
comparison carries about **1.3% systematic bias, and in a known direction**: the identical
function measured *slower* in the old build, so the harness slightly flatters the new one and
the true speedups are marginally *lower* than printed. On a 3.30× ratio, 1.3% is about 0.04 —
so read these as 3.26×, 3.41× and 3.78× at worst. **The uncertainty sits in the second decimal
place**, which is why nothing here is quoted to three.

Only that systematic component is quantified. Random scatter is suppressed by taking medians
of 24 alternating pairs rather than reported as an interval — a real limitation: these figures
are good to a couple of percent, not better.

### Against the algorithm designers' own implementation

The team that designed the algorithm publishes a heavily optimized implementation. Comparing
against it is the meaningful external benchmark. It was built from its own repository at a
fixed, recorded commit, entirely outside this project, and never becomes part of anything this
project ships.

| operation | this project | the designers' | ratio |
|---|---|---|---|
| Key generation | 36,924 | 26,123 | **1.41×** |
| Encapsulation | 38,755 | 27,372 | **1.42×** |
| Decapsulation | 43,629 | 31,089 | **1.40×** |

Ticks per operation again, 41 alternating repetitions of 200 operations each, medians.
**This table has no equivalent of the byte-identical control used above**, and cannot: there is
no code common to both projects to time as a reference. So its systematic error is unquantified
— the cross-harness spread of 3–8% noted above is the best available indication of its size,
which means 1.41× should be read as "roughly 1.4×" and not to two decimals. That is a real
weakness in the number this document quotes most often.

Higher is worse: this implementation takes about **1.41× as long** — 41% more time per
operation, equivalently about 29% fewer operations per second. This document uses the time
framing throughout.

**Some of that gap is real extra work, and some of it is not — the honest split.** This
implementation **erases every secret it writes to the stack**; theirs erases nothing. There
are 27 such values per operation. But that erasure was made nearly free late in the project
(below), and doing so is exactly what moved this ratio from 1.53× down to 1.41×. So the honest split is: **erasure used to cost about 0.12× and now costs
essentially nothing, which is why the ratio moved from 1.53× to 1.41×. It therefore explains
none of the 0.41× still outstanding.**
The remaining gap is elsewhere: chiefly that the designers' version has hand-written assembly
for the fast transform and related routines where this one has C++ with vector intrinsics.
Citing secret erasure as the explanation for the whole 41% would be wrong, and earlier drafts
of this document did exactly that.

**What erasing secrets costs, and a mistake worth recording.** The standard requires that
intermediate secret values be destroyed once no longer needed. The obvious way to write that —
a loop writing zero over each byte, marked `volatile` so the compiler cannot delete it — cost
about 8% of key generation, running roughly 27 times slower than a plain bulk memory clear.
(Unrelated to the 27 values above; the coincidence is accidental.)

The first diagnosis was wrong, and measuring is what caught that. The slow loop was written in
a way that also forced the compiler to re-read its own pointer before every single byte, and
that looked like the obvious culprit. Fixing only that recovered almost nothing. The real cost
was `volatile` itself: it forbids combining byte writes into wide ones. The fix was to use a
plain `memset` and stop the compiler discarding it a different way — with an empty inline
assembly statement that declares it clobbers memory, which the optimizer cannot see through
and which emits no instructions. That runs at full memory-clearing speed. Verified not to have
weakened the erasing: removing that barrier makes the erase vanish from the compiled output
entirely, and a standing test now checks exactly that.

## 6. Security validation

### What "constant time" means, and why it is not optional

If code takes longer when a secret bit is 1 than when it is 0, then anyone who can measure how
long it took learns something about the secret. Repeat the measurement enough times and the
whole key comes out. This is not theoretical: it has broken deployed systems repeatedly,
including remotely over a network, and in 2023 a family of these bugs — collectively named
KyberSlash — was found in the designers' own reference implementation of this scheme's
predecessor. The cause there was an integer division whose duration depends on the value being
divided.

So the requirement is that **execution time must not depend on secret data at all.** In
practice that forbids, on any secret value: branching on it, using it as an array index
(because which memory addresses you touch is visible through the processor's caches), and
using instructions whose duration varies with their operands — integer division being the main
one. It also forbids floating-point arithmetic outright, which the standard itself requires.

Three independent checks were used, because each is blind to something the others catch.

**Does the code ever branch on a secret, or use one as an address?** The program runs under a
memory-checking tool of the kind normally used to find uses of uninitialized memory. Such a
tool tracks, for every bit in the program, whether that bit is *defined*, and complains when
an undefined bit changes the program's behaviour — because reading uninitialized memory is a
bug. The trick is to deliberately mark the secret values as undefined at the start. Then any
point where the program branches on a secret, or uses one to compute an address, is
*mechanically indistinguishable* from the bug the tool already looks for, and it reports the
exact line. **Zero reports.** This is the cheapest high-confidence check available.

It is blind to timing that varies without a branch — in particular, it cannot see a division
at all, because a division's *result* is perfectly defined; only its duration leaks.

One caveat belongs next to that zero: it is zero *given* the classification of which values
are secret, and section 4 describes one value being reclassified as non-secret partway through.
That reclassification was correct — the standard publishes the value — but it is part of what
"zero reports" is conditional on, and re-verifying the remaining checks after it was a
deliberate step rather than an assumption.

**Does any division survive anywhere in the library?** The compiled machine code is searched
for division instructions. **Zero**, which is the answer that matters, since division is the
instruction behind the 2023 bugs. This check works at the machine level deliberately: it
catches divisions the compiler inserted that appear nowhere in the source, and one such was
found and removed. It cannot tell whether a given division's operands are secret — it simply
insists there are none.

**Does the measured execution time depend on secret inputs?** Each operation is timed over
hundreds of thousands of runs, split into two groups: one where the secret input is held fixed,
one where it is random each time. If runtime is independent of the secret, the two groups'
timing distributions should be indistinguishable. They are compared with Welch's *t*-test — a
standard statistical test for whether two samples have different means when their variances
differ — which reports a value conventionally called *t*. Roughly, *t* counts how many
standard errors apart the two means are: below about 3 the difference is indistinguishable from
noise, and it climbs without limit as evidence accumulates. The threshold used here is
|*t*| < 10, proposed by the authors of the published timing-test method this one follows (named
in the closing section); a stricter convention in the side-channel literature is 4.5, and any
result between the two is reported rather than passed silently. This catches effects the other
two checks are structurally incapable of seeing.

### What "clean" means here — the resolution matters more than the verdict

A timing test cannot prove a difference is zero; it can only fail to find one down to some
size. Reporting "no leak found" without that size is close to meaningless, so it was measured
directly: **a delay of known, adjustable length was planted inside decapsulation, on a path
that depends on a secret, and shortened until the test stopped noticing it.**

> **Detection is reliable down to about 100 ticks and fails at about 50.** Between those two
> the result is erratic — sometimes found, sometimes not — which is itself the useful finding:
> that band is where this measurement runs out of resolution.

So "no timing dependence on secrets" means *none larger than roughly 100 ticks*. Against
decapsulation's 40,540 ticks that is about 0.25% of the operation; against key generation's
35,701, about 0.28%. It does not mean none at all.

An earlier draft of this work claimed a one-tick resolution. That figure was real but came from
timing a short, quiet loop, and it does not carry over to an operation forty thousand ticks
long with much larger natural variation. **A sensitivity is a property of the thing being
measured, not of the measuring tool** — a correction worth making explicitly, because the wrong
number was a hundredfold too flattering.

### Secret erasure

All 27 secret values written to the stack per operation are overwritten before going out of
scope. This is verified two separate ways, because neither covers the other: one check confirms
the erasing routine itself is not deleted by the optimizer *and* that it covers the whole
buffer rather than part of it — an earlier version of that check counted instructions, which
could not distinguish a complete erase from one that cleared three quarters of the bytes. The
other confirms an erase is actually emitted at each of the 27 sites. Both had to be proven able
to fail first, and the second was deliberately written *before* the erasing routine was
rewritten for speed, so that the rewrite could be shown not to have broken anything.

**What this does not cover, and cannot.** The erasure clears the named variable. It does not
reach copies the compiler made of that value in processor registers or in stack scratch space,
and no C++ mechanism can reach them — the language provides no way to enumerate them. **This is
a known, unclosed limitation of secret erasure in C++, not an oversight here.** The honest
statement of the guarantee is "each named secret is overwritten before its scope ends", not
"this secret no longer exists anywhere in memory".

### Robustness

The code was also driven with large volumes of machine-generated input looking for crashes and
memory faults, with two kinds of instrumentation compiled in: the memory-error detector
described in section 4, which catches reads and writes outside an object's bounds, and a second
detector for operations the C++ standard leaves undefined. More usefully, every result was also
compared against the slow model. Almost every malformed input takes the rejection path described
in section 8, and its result has to match the model exactly. That turns the exercise into a
correctness check on precisely the path the official vectors cannot see. The inputs that do
*not* take that path are the ones that fail an explicit size or consistency check and are
rejected outright with an error; those are covered by ordinary unit tests instead.

## 7. Energy per operation

Energy was measured because a later comparison against different hardware — a
field-programmable gate array or a custom chip, for instance — needs it.

**And this section ends by explaining why these figures serve that purpose poorly.** That is
not a contradiction, it is the point of measuring now: the numbers are a floor to build on, and
the caveats below are the specification for what a serious cross-device comparison would have
to do differently. Recording them without the caveats would be worse than not recording them. Power draw was sampled once per second through a fixed 280-second
schedule: 30 seconds idle, then each of the six measured runs — this project's three operations,
then the designers' three — for 30 seconds apiece with a 10-second idle between consecutive
runs, and 30 seconds idle at the end. That is **seven idle periods** in total, whose mean is the
baseline subtracted below. The harness also counted how many operations completed in each 30-second window,
which is what converts watts into energy per operation.

**A microjoule (µJ) is a millionth of a joule.** At roughly 300 µJ per operation, a million key
generations costs about 300 joules — around 0.08 watt-hours, or what a laptop draws in a few
seconds. These are small quantities; the reason to measure is comparison.

The arithmetic, so it can be checked: key generation ran at 71,216 operations per second while
the processor drew 25.01 W, against an idle draw of 4.08 W. So (25.01 − 4.08) ÷ 71,216 =
294 µJ per operation.

Operations per second are given for both sides so every energy figure can be recomputed the
same way; the designers' code drew slightly more power, 27.2–27.3 W against this project's
25.0–25.9 W.

| operation | ops/s, this project | ops/s, theirs | this project | the designers' | energy ratio | *time* ratio |
|---|---|---|---|---|---|---|
| Key generation | 71,216 | 98,900 | ~294 µJ | ~235 µJ | 1.25× | 1.39× |
| Encapsulation | 67,872 | 99,687 | ~321 µJ | ~233 µJ | 1.38× | 1.47× |
| Decapsulation | 62,315 | 87,218 | ~350 µJ | ~265 µJ | 1.32× | 1.40× |

Higher is worse in both ratio columns. **The time ratios here differ slightly from section 5's
(1.39/1.47/1.40 against 1.41/1.42/1.40) because they come from this run's throughput counts
rather than from the timing benchmark** — a third harness, measuring the same thing a different
way. The encapsulation figure differs most, by about 3%.

**The interesting result: the energy penalty is smaller than the time penalty**, in all three
operations. This implementation draws *less* power while running — about 25 W against 27 —
which partly offsets taking longer. Nothing here was designed for low power; it is simply what
was measured, and it is recorded because energy would otherwise be assumed to track speed
exactly, and it does not. Section 5 warns against reading numbers across harnesses, so doing it here is deliberate and
worth flagging: substituting section 5's time ratios for this run's, the effect still holds for
key generation and decapsulation and shrinks to almost nothing for encapsulation. **It survives
the cross-check in two operations of three, which makes it a modest finding rather than a
strong one.** That is the reason for stating it at all — an effect that only appears under one
harness's numbers would not be worth reporting.

### Which of these numbers survive a comparison against other hardware

This matters more than the numbers themselves, because getting it wrong produces a comparison
that looks rigorous and is not.

**The ratios are trustworthy; the absolute figures are indicative.** The idle draw that gets
subtracted is the mean of the seven idle periods, 4.08 W, and the individual periods ranged
from 2.7 to 5.1 W. Recomputing against those extremes rather
than the mean moves the absolute figures by about **+7% / −5%** — written as "±6%" for brevity,
though it is not symmetric — which is why they appear as "~294 µJ" and should be spoken as
"about 290" rather than "293.9". The ratios move by **under 1%**, because both
implementations are measured against the same idle baseline and the error largely cancels.

**A cross-device comparison needs the absolute figures — the uncertain ones.** Two
implementations on one machine share a baseline. Two different devices do not, so the
comparison rests on the ±6% numbers, and that uncertainty becomes the floor of the comparison
rather than a footnote.

**And the power boundary must match on both sides.** These figures are *processor package*
power minus idle. That excludes everything else on the board: memory, voltage regulators and
their losses, storage, input/output. A figure quoted for a gate array or custom chip is often
*whole-board* power, which includes all of that. Comparing the two directly would flatter
whichever side was measured at the narrower boundary — normally the processor. **Any such
comparison must either bring both sides to the same boundary or state the mismatch next to the
numbers.**

Finally: one run, on one laptop, and the power figure comes from a model the processor computes
internally from its own activity counters, not from a physical meter on the power rail. Enough
to say this implementation costs noticeably more energy than the reference and roughly how
much. Not enough to support a claim about a few percent.

## 8. Using it safely

The whole interface is one header. Sizes are fixed: the public key is 1184 bytes, the private
key 2400, the ciphertext 1088, and the shared secret 32.

Every operation returns a status rather than throwing — the library is compiled with exceptions
disabled — and the status is an enumeration whose values are success, a failure of the random
number generator, and one rejection code each for a malformed public key, private key, or
ciphertext. The example below shows those checks; what it omits, for brevity, is what
to *do* on failure. Each return value must be tested, and the compiler enforces it — the
functions are marked so their results cannot be discarded.

**What the rejection codes are for, given that the types are fixed-size.** If you use the typed
interface below, a wrong-size input is impossible: the size is part of the type. The library
also offers a pointer-and-length form for callers holding raw buffers — typically bytes just
read off a network — and that is where a length can be wrong. The key rejection codes also
cover inputs of the *right* length that are malformed: a public key whose packed coefficients
decode out of range, or a private key whose embedded hash does not match the public key stored
inside it. A *ciphertext* of the right length is never rejected — see immediately below.

```cpp
#include <mlkem/mlkem768.hpp>

mlkem768::EncapsKey ek;          // public  — publish this
mlkem768::DecapsKey dk;          // SECRET  — keep it
mlkem768::Ciphertext ct;         // public  — send this back
mlkem768::SharedSecret ss_send;  // SECRET
mlkem768::SharedSecret ss_recv;  // SECRET

if (mlkem768::keygen(ek, dk) != mlkem768::Status::Ok)            { /* handle */ }
if (mlkem768::encaps(ek, ct, ss_send) != mlkem768::Status::Ok)   { /* handle */ }
if (mlkem768::decaps(dk, ct, ss_recv) != mlkem768::Status::Ok)   { /* handle */ }
// ss_send and ss_recv are now identical
```

### The one thing that will catch you out

**Decapsulation does not report a tampered ciphertext.** Hand it a ciphertext that is the right
*size* but corrupted or forged, and it returns success and a shared secret — one that is
deterministic, unpredictable, and different from the sender's.

This is deliberate and required by the standard. Reporting "invalid ciphertext" would give an
attacker a *decryption oracle* — a service that answers questions about the private key. The
attack is: send a deliberately modified ciphertext, observe whether it was accepted or
rejected, and that single bit of feedback reveals something about the key. Repeat with
different modifications and the key can be reconstructed. Attacks of exactly this shape have
broken real deployed systems.

The scheme's defence is to make rejection *indistinguishable from success*. On a bad ciphertext
it returns a different secret, derived by hashing a value stored inside the private key
together with the ciphertext itself — so the result is unpredictable to the attacker but
perfectly reproducible for the key-holder, and the caller sees an ordinary success. This is
called **implicit rejection**. This implementation computes both the real and the fallback
answer on every call and selects between them without branching, so the timing does not reveal
which happened either.

**What that means for you: success does not mean the exchange worked.** The two sides must
confirm they hold the same secret before relying on it. Normally this comes for free. Use the
shared secret as the key for an authenticated encryption scheme — one that attaches a short
*authentication tag*, computed from the message and the key, which the receiver recomputes and
compares. If the two sides hold different secrets, the tags will not match and the connection
fails closed, which is the behaviour you want. If you need an explicit check instead, have each
side send a tag computed over some agreed fixed value using the shared secret as the key, and
compare those. **Never send the secrets themselves in order to compare them.**

### Two more things

**Randomness.** By default the operating system's random generator is used, which is
appropriate for general use. If you supply your own, it **must** be safe to call from several
threads at once, or be per-thread. Here is why that matters more than usual: encapsulation's
entire security rests on the 32 random bytes it picks being unpredictable and never reused. If
two threads share a generator that is not thread-safe, they can be handed the *same* bytes —
and two ciphertexts built from the same message under the same public key let an attacker
recover that message. There is no visible symptom; everything appears to work.

**Threads.** Every operation is safe to call concurrently. There is no batch interface: one
operation takes about 15 microseconds on this machine (decapsulation's 40,540 ticks at
0.385 ns each), which is comparable to the cost of coordinating threads, so spreading a single operation across
cores would lose. Call it from several threads if you need throughput.

## 9. What didn't work, what was left out, and what is still unknown

The most useful part of any write-up, and the part most often missing.

### Deliberately excluded

**A batch interface.** The standard's surrounding guidance suggests one for processing many
operations at once. Excluded: the target use is a single real-time stream, where one operation
is about 15 microseconds (section 8) — comparable to the cost of coordinating threads — so
cross-core parallelism would lose. Revisitable if the workload changes.

**Caching the expanded public matrix.** Expanding the matrix from its seed is the most
expensive single step, and the standard explicitly permits caching the result. It is a large
win *if* one public key is reused across many exchanges. The target workload uses a fresh key
each time, so the cache would never be hit and the memory would be spent for nothing.
Revisitable.

**Storing a 64-byte seed instead of the 2400-byte private key.** The standard permits
re-deriving the private key from the seed it was generated from — a 37× storage saving for
anything holding many keys at rest. Not needed here, and not implemented; adding it at the end
would have meant new untested code or exposing internals. Revisitable.

**A faster internal data layout.** The fast transform can leave its output in a permuted
coefficient order that the following multiplication step consumes directly, saving a
rearrangement — worth an estimated few percent. Excluded by decision rather than overlooked. The
invariant it would break is that the transform leaves its 256 coefficients in the standard
order, the same order the slow model and the standard's own pseudocode use. Four checks rest
on that: the comparison of the vectorized against the portable version for bit-identical
output, the comparison of both against the slow model, the arithmetic range table that says
how far each coefficient may drift, and the test that checks the transform's constant tables
against the standard's appendix. Trading four checks for a few percent was judged the wrong
way round.

### Tried and abandoned

**Removing some arithmetic reductions.** Seven sites were listed as candidates, one of which
turned out on inspection not to be a reduction at all, leaving **six** real ones. **Three** were proven
unnecessary and removed. Of the other three: **one** would have overflowed a 16-bit integer —
silently, producing wrong-but-plausible results — for as long as one of the three accepted
removals stood, so the two were mutually exclusive: the removal that had already been proven safe was kept,
and this one was left in place; **two** were
removed experimentally, measured, and found to make the code about 3% *slower*, so they were
put back. Recorded because "we tried it and it didn't help" is information.

**Vectorizing one of the sampling routines — kept, but it did not earn its keep.** This is the
one that converts hash output into the small error values the scheme adds as noise. Filed here rather
than under exclusions because the *expected benefit* failed to materialize. The function itself
became about 3.9× faster and the whole operation did not measurably change: the routine is too
small a share of the total. It was kept on the argument that the speedup is real and verified,
but the honest label is that its end-to-end benefit is inside the noise.

### Genuinely unknown

**A very small timing effect in the fast transform.** The statistical timing test found a
reproducible dependence on input *values* in the vectorized fast transform, at roughly **0.07
ticks per call**.

*How a fraction of a tick is measured:* the timer cannot resolve less than one tick, but each
measurement times a batch of 32 calls and hundreds of thousands of batches are taken, so a
consistent sub-tick difference in the mean emerges from averaging even though no single
measurement could show it. That is also why such a small number can be statistically solid and
practically irrelevant at the same time.

*Whether it came from this code* was tested by running three implementations through an
identical harness: this project's vectorized transform, this project's plain portable
transform, and **the designers' own vectorized transform**. Ranked by *t*, the only measure
comparable across them:

| implementation | *t* | reading |
|---|---|---|
| the designers' vectorized transform | 7.3 – 22.7 | clearly present, strongest of the three |
| this project's vectorized transform | 2.4 – 10.0 | present, weaker |
| this project's portable transform | 1.7 – 4.8 | **not significant — says nothing either way** |

**These numbers do not gate anything, and that needs saying explicitly**, because they touch and
exceed the |*t*| < 10 threshold section 6 set out. Three points reconcile them:

- **The gate applies to whole-operation measurements through the public interface**, which is
  what an attacker can time. Those are the ones reported in section 6, and they are clean down
  to the ~100-tick floor. The rows above time one internal routine directly, from inside the
  process, which is far more sensitive — that is why they can show something the gated
  measurements cannot.
- **So these rows are diagnostics for locating an effect, not pass/fail results.** They exist
  to answer "where is it and is it ours?", and their answer is "in the transform, and not
  specific to our code".
- **"Not significant" in the portable row means something narrower than section 6's 4.5.** It
  means the gap is indistinguishable from *that arm's own* noise, which is much larger because
  that version runs about 30× slower. It is not a claim that the row cleared a threshold.

Nothing in this table was passed silently: it is all reported here, which is what section 6
promised for results in that band.

The portable arm looked at first like corroboration, because its raw timing gap in ticks was by
far the largest. It is not: that version runs about 30× slower, so a bigger gap sitting inside
proportionally bigger noise is evidence in neither direction, and its *t* confirms that. **So
the conclusion rests on one comparison — against the designers' independent code — not on all
three arms**, and an earlier draft of this document wrongly cited the portable arm as support.

**What that comparison does and does not establish.** It rules out a cause specific to *this*
implementation, since independent code on the same machine shows more of the effect. It does
**not** rule out a cause shared by both — they compute the same transform, so the same
data-dependent behaviour in a similar instruction sequence could in principle affect both. What
can be said is that it is not a defect this project introduced.

**What is settled: the effect is not something this implementation introduced.** **What remains
unknown: what causes it.** There is no known mechanism — the code has no branches and no
divisions on secret data, and the vector instructions it uses take a fixed number of processor
clock cycles — genuinely cycles, not ticks — regardless of their operands. Settling *that* would need a different instrument: a processor
with a fixed clock, or hardware performance counters instead of a general-purpose timer.

The largest per-call gap observed for this effect in any run was about **0.2 ticks** — that is
where the bound comes from: the biggest difference actually measured, not a confidence limit.
Against the roughly 100-tick floor at which anything is detectable through the public
interface, that is some five hundred times smaller.

**A separate timing question, also inconclusive.** A different test was built for a different
routine — the final rounding step that turns the recovered polynomial back into 32 bytes — to
determine whether its timing responds to how *similar* successive inputs are — whether calling
it twice on nearly-identical values runs faster than on unrelated ones, as processors sometimes
do.

Why that would matter: this routine's input is the recovered polynomial, which depends on both
the private key and the ciphertext. An attacker who submits many ciphertexts and times each
decapsulation chooses the ciphertexts but *not* that polynomial. So if the timing varied with
how much the polynomial changed from one call to the next, the attacker would be reading out
something about a key-dependent value they do not control — a real leak, even though no single
value is ever revealed. Hence the test. The
test could not answer it: its own control condition, where the two groups are constructed so
that nothing can possibly differ but the values themselves, registered as strongly as the real
measurement. That means the instrument's noise floor was as large as the difference being
looked for. **It is not evidence of a leak and not evidence of its absence.**

**On the number that can still be quoted despite the test being inconclusive**, since that
reads as a contradiction: the test could not decide *whether* timing responds to similarity,
but it did record how large the mean gap was in each condition, and the largest was about
0.2 ticks per call. So the honest statement is "if there is an effect here, it is no bigger
than 0.2 ticks per call — and we could not establish that there is one." That this is the same
0.2 as the transform effect above is a coincidence of this machine's resolution, not a sign the
two are the same phenomenon; they were measured independently, on different routines.

*("The project's own plan" below, and the decision records referred to elsewhere in this
section, are the specification and decision log named in the closing section — the one place
this document names files.)*

**The random-input testing fell far short of the plan.** Two *targets* were built — separate
fuzzing programs, one driving decapsulation and one driving the two input-validation checks.
The project's own plan called for 100 million executions of each; **300,000 of each** were
run. Each execution of the decapsulation target does a
full key generation, encapsulation and decapsulation, *plus* a decapsulation through the slow
model for comparison; the validation target does a key generation and then exercises the two
checks. Both carry two layers of instrumentation. The measured rates were 181 and 237
executions per second respectively — close enough that the figures below use 180–240 for
both. At that rate the 300,000 that *were* run took about
25 minutes per target, and 100 million would take about six days each. Six days of machine
time is not obviously unaffordable, so the honest position is not "it was impractical" but
**"it was not done"** — a decision about effort, recorded rather than dressed up. The alternative of dropping the model comparison or the
instrumentation to reach a bigger number would have removed the parts that make the exercise
worth anything.

(The earlier figure of 400,000 attempts in section 4 was from the *broken* setup, before the
library was instrumented. Those attempts were faster because less was being checked, and they
tested the wrong binary. The two numbers are not comparable.)

Coverage was measured instead: **50 of 81 library functions reached**, and **202 of 744
branches**. The 31 unreached functions are individually accounted for — the portable code path,
parameter combinations impossible at this size, and small helpers the compiler inlines away
entirely. On the portable path specifically: **these coverage numbers are from the random-input
testing only**, and that testing runs whichever path the processor selects, which here is the
vectorized one. The portable path is covered instead by the ordinary test suite, which runs
both and requires them to agree bit for bit — so it is tested, just not by this measurement.

**Secrets in compiler-generated copies**, as described in section 6 — unclosed, and not
closable in this language.

**The lower-level entry points are undeclared but not unreachable.** Below the three public
operations sit deterministic versions of them that take their randomness as an explicit
argument instead of drawing it — the form the official test vectors are written against, since
reproducing a fixed expected output requires fixing the randomness. The standard says these
*should not* be exposed to applications, because an application that supplies its own
randomness can get it wrong. The public header does not declare them. But they remain present
as symbols in the compiled library, so a caller who writes the declaration themselves can call
them. They are undocumented and cannot be reached by accident. Hiding them properly would mean
altering the shipped library after every check had already run against it, so the claim was
downgraded to match the truth instead: **undeclared, not inaccessible.**

### One process failure worth admitting

The project's rolling status document was supposed to be rewritten at each stage rather than
appended to, precisely so a later reader would not trust stale text. That rule failed
repeatedly. The worst instance: the status file came to describe the project's **number
representation convention incorrectly**. That convention is the Montgomery form described in
section 3 — every value held multiplied by a fixed constant, with rules about which operations
add or remove a factor of it, and results wrong by a constant factor if those rules are
inverted. That
is the single most dangerous thing in the project to have documented wrongly.

A mechanical check was added afterwards, and it catches only a stale *date*, not stale prose.
The decision log entry recording that check says so explicitly, and concludes that this is not
a case for adding another check — it is the discipline not being followed. It is recorded here because a summary that
omitted it would be less useful.

Two things this does *not* mean. The convention was only ever described wrongly in the status
notes — **the code implemented it correctly throughout**, which the official test vectors would
have caught within minutes otherwise. And it recurred once more while this document was being
written: the same status file's narrative sections were again describing finished work as
upcoming. They were deleted and rewritten rather than edited, which is what the rule asked for
in the first place.

---

## Where to look

The main text above avoids naming files and tools so it reads as prose, with two deliberate
exceptions: the code example in section 8 names the header you include, and section 9 refers to
"the plan" and "the decision log", which are the specification and `DECISIONS.md` in the table
below. Everything else is here.

| To find | Look in |
|---|---|
| Build, install, use, and what is not claimed | `README.md` |
| Every decision, with its reasoning and the evidence | `DECISIONS.md` — numbered entries, one per decision |
| Invariants to respect before changing the code | `docs/reference/invariants.md` |
| What is still open or unresolved | section 9 above; reasoning in `DECISIONS.md` |
| The standard's algorithms, extracted once | `docs/algorithms/` |
| Per-stage write-ups: what was measured and what it meant | `docs/notes/` |
| Timing verification in detail, including the ~100-tick floor | `docs/notes/09-dudect.md` |
| Energy method, full results and limits | `docs/notes/09-energy.md` |
| Random-input testing, coverage, and the harness defects | `docs/notes/10-fuzzing.md` |
| Arithmetic range invariants — what may drift how far | `docs/bounds.md` |
| What each timing tool can and cannot detect | `docs/reference/ct-tooling.md` |
| Every build command | `docs/reference/commands.md` |
| Licences: this project's, and the third-party code's | `LICENSE`, `THIRD_PARTY_NOTICES.txt` |

**Tools, by their real names.** The branch-and-address check is valgrind's memory checker,
driven in the style of the ctgrind technique. The statistical timing test implements the method
of dudect, using Welch's *t*-test. The random-input testing uses libFuzzer with
AddressSanitizer (the memory-error detector) and UndefinedBehaviorSanitizer (the second
detector). The division search, the erasure checks and several document-consistency checks are
project-specific scripts. The comparison implementation is `pq-crystals/kyber`, built outside
this repository at a pinned commit and never included in anything shipped. Third-party code
included in this repository — the hashing routines — is listed with its licences in the notices
file; *vendored* is the term used for that practice, meaning a copy of someone else's source
kept in-tree at a recorded version rather than fetched at build time.

**Commands.** `gmake test` for the test suite, `gmake kat` for the official vectors,
`gmake docker-all` for every check that needs Linux, `gmake package` to build a release
archive. It is `gmake`, not `make`, because macOS ships a version of Make old enough to
compare file timestamps only to the nearest second, which silently reuses stale object files;
the build refuses to run under it.
