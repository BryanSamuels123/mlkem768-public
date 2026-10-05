# Energy per operation — measured 2026-09-29

*Run once, on final Phase 9 code, as the deferred procedure required. Raw data and the
parser are in the repo so every number here can be re-derived:
`docs/notes/energy-2026-09-29/powermetrics-raw.txt` (the capture),
`harness-phases.txt` (the harness's own phase log), and `tools/parse_energy.py`.*

```
python3 tools/parse_energy.py docs/notes/energy-2026-09-29/powermetrics-raw.txt \
                              docs/notes/energy-2026-09-29/harness-phases.txt
```

---

## 1. What was measured, and what a microjoule per operation means

`powermetrics --samplers cpu_power` was captured at 1-second intervals while
`bench/bench_energy.cpp` ran a fixed 280-second schedule: 30 s idle, then each of our three
operations for 30 s, then each of pq-crystals' three, with 10 s idles between and 30 s idle
at the end. The harness prints a wall-clock timestamp at every boundary, which is the only
thing joining the two recordings.

**A microjoule (µJ) is a millionth of a joule — the energy the whole CPU package draws to
complete one operation.** At ~300 µJ per key generation, a million key generations costs
about 300 joules, roughly the energy in a AA battery's last few percent, or about 0.08 watt-
hours. It is a small quantity; the reason to measure it is the *comparison*, not the absolute
size.

Two figures are reported for each operation:

- **Gross** — average package power during the phase, divided by operations per second. This
  includes everything the machine was doing, the operating system included.
- **Net** — the same, after subtracting the idle baseline. This is the closer estimate of
  what the cryptography itself costs, and it is the figure to quote.

The capture (390 samples, 19:20:30 → 19:27:01) fully brackets the harness run
(19:21:37 → 19:26:27), so no phase is partially covered. **The first and last sample of each
phase are dropped**: a 1-second sample straddling a boundary is part idle and part compute,
so keeping it would pull every compute phase toward idle and every idle phase toward
compute — biasing the net figure in the one direction that matters. 28 of 30 samples survive
in each long phase, 8 of 10 in each short one.

## 2. Results

Package power by phase, and the resulting per-operation energy:

| phase | ops/s | gross W | net W | gross µJ/op | **net µJ/op** | throughput drift |
|---|---|---|---|---|---|---|
| `ours_keygen` | 71 216 | 25.01 | 20.93 | 351.2 | **293.9** | −0.4 % |
| `ours_encaps` | 67 872 | 25.84 | 21.76 | 380.8 | **320.6** | +1.3 % |
| `ours_decaps` | 62 315 | 25.88 | 21.80 | 415.3 | **349.8** | −0.1 % |
| `kyber_keygen` | 98 900 | 27.32 | 23.24 | 276.2 | **235.0** | −0.5 % |
| `kyber_encaps` | 99 687 | 27.26 | 23.18 | 273.5 | **232.5** | +2.5 % |
| `kyber_decaps` | 87 218 | 27.20 | 23.12 | 311.9 | **265.0** | −0.3 % |

Idle baseline: 4.08 W, the mean of all seven idle phases (individually 4.31, 4.26, 4.32,
4.39, 5.13, 2.67, 3.50 W).

**Throughput did not drift meaningfully inside any phase** — the largest first-half versus
second-half change is +2.5 %, so this run was not thermally throttled and the averages are
not hiding a slowdown.

## 3. Ours versus pq-crystals — and the one result worth noticing

| operation | ours | pq-crystals | energy ratio | **time ratio** |
|---|---|---|---|---|
| KeyGen | 293.9 µJ | 235.0 µJ | **1.25×** | 1.39× |
| Encaps | 320.6 µJ | 232.5 µJ | **1.38×** | 1.47× |
| Decaps | 349.8 µJ | 265.0 µJ | **1.32×** | 1.40× |

In plain words: **each of our operations costs about a quarter to two-fifths more energy
than the reference implementation's.** That is the same story the cycle counts tell — we are
slower, so we hold the CPU busy for longer, and energy is power multiplied by time.

**But the energy penalty is consistently smaller than the time penalty**, in all three
operations. We draw *less* power while running (25.0–25.9 W against their 27.2–27.3 W), and
that partly offsets being slower. So the gap in energy is narrower than the gap in speed —
1.25× versus 1.39× for key generation, for instance.

This is a measurement, not a design achievement: nothing in this project targeted power
draw, and the likely cause is simply that their code keeps more execution units busy per
cycle. It is recorded because it is the kind of thing that would otherwise be assumed to
track speed exactly, and it does not.

Note also that **we pay this while doing strictly more work**: every operation erases all 27
wrapped stack secrets, and pq-crystals erases nothing.

## 4. Limits — these are real and none of them is small print

**Package power is the whole CPU, not this code.** The `cpu_power` sampler reports what the
processor package draws — cores, graphics and system agent together — so the operating
system, background daemons and anything else running land in the same number. Subtracting
the idle baseline removes the *steady* part of that, not any of it that varied during the
run.

**The idle baseline is the dominant uncertainty, and it moved.** The seven idle phases span
2.67 W to 5.13 W. Recomputing the net figures against the lowest and the highest instead of
the mean:

| operation | net µJ at lowest baseline | at mean | at highest | spread |
|---|---|---|---|---|
| KeyGen | 313.7 | 293.9 | 279.2 | ±6 % |
| Encaps | 341.4 | 320.6 | 305.1 | ±6 % |
| Decaps | 372.5 | 349.8 | 333.0 | ±6 % |

So **the absolute per-operation figures are good to roughly ±6 %, no better.** Quote them as
"about 290 µJ", not as 293.9.

**The ratios, however, are robust**, because both implementations are measured against the
same baseline and the error largely cancels:

| operation | ratio at lowest baseline | at mean | at highest |
|---|---|---|---|
| KeyGen | 1.259 | 1.251 | 1.244 |
| Encaps | 1.384 | 1.379 | 1.375 |
| Decaps | 1.324 | 1.320 | 1.316 |

The comparison moves by under 1 % across the full range of plausible baselines. **The ratios
are the trustworthy part of this measurement; the absolute microjoules are indicative.**

**This is a rough figure, not a laboratory measurement.** One run, on a laptop, with an
energy *model* rather than a power meter — `powermetrics` reports "Intel energy model
derived package power", which is an estimate the processor computes, not a physical
measurement. There is no repetition, so there is no error bar beyond the baseline
sensitivity above. It is enough to say our operations cost noticeably more energy than the
reference's and to quantify roughly how much; it is not enough to support a claim about a
few per cent.

**It describes this machine only.** A different processor, a different thermal envelope, or
a plugged-in versus battery state would all change the absolute numbers, and could change
the ratios.

### If these figures are ever used for a cross-device comparison

A comparison against different hardware — an FPGA or a microcontroller, say — is exactly the
case this measurement is *least* suited to, and for two reasons that both need stating
out loud rather than discovered later.

**It needs the absolute figures, which are the uncertain ones.** The ratios above are robust
to ±1 % because both implementations share an idle baseline that cancels. A different device
has no such shared baseline, so a cross-device comparison rests on the ~290 µJ numbers, whose
±6 % baseline sensitivity then becomes the floor of the comparison rather than a footnote.

**The power boundary must be the same on both sides, and here it is the CPU package net of
idle.** That is not comparable to whole-board power without saying so. Package power excludes
the board: DRAM, voltage regulators and their losses, I/O, storage, anything on the board that
is not the processor. An FPGA figure quoted as board power therefore includes cost categories
these numbers exclude, and comparing the two directly would flatter whichever side was
measured at the narrower boundary — usually the CPU.

So any such comparison must either bring both sides to the same boundary, or state the
mismatch explicitly alongside the numbers. Quoting a bare "290 µJ per operation" against a
board-power figure would be wrong in a way the reader cannot detect.

## 5. When this must be re-run

If Phase 10's fuzzing forces a change to library code, this measurement is **repeated** —
and so is the criterion-4 head-to-head, which holds by only about 0.09×.
