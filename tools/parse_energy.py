#!/usr/bin/env python3
"""Split a powermetrics capture into the energy harness's phases and report per-operation
energy. See docs/notes/09-energy.md for the results and their limits.

  python3 tools/parse_energy.py <capture.txt> <phases.txt>

The harness (bench/bench_energy.cpp) prints a wall-clock timestamp at every phase
boundary; powermetrics timestamps every sample. That is the only thing joining the two.

THE FIRST AND LAST SAMPLE OF EACH PHASE ARE DROPPED. A 1-second sample that straddles a
phase boundary is part idle and part compute, so it belongs to neither -- keeping them
would pull every compute phase toward idle and every idle phase toward compute, which
biases the net figure in the one direction that matters.
"""

import re
import sys
from datetime import datetime

SAMPLE = re.compile(r"^\*\*\* Sampled system activity \((?P<ts>.+?)\)")
POWER = re.compile(r"package power \(CPUs\+GT\+SA\):\s*(?P<w>[0-9.]+)W")
PHASE = re.compile(r"^PHASE\s+(?P<tag>\S+)\s+(?P<t>\d\d:\d\d:\d\d\.\d+)")
COUNT = re.compile(r"^COUNT\s+(?P<tag>\S+)\s+ops=(?P<ops>\d+)\s+elapsed=(?P<el>[0-9.]+)s"
                   r"\s+ops/s=(?P<ops_s>[0-9.]+)\s+firsthalf=(?P<fh>[0-9.]+)"
                   r"\s+secondhalf=(?P<sh>[0-9.]+)\s+drift=(?P<dr>\S+)")


def sod_from_sample(ts):
    # "Tue Sep 29 19:20:30 2026 -0500" -> seconds of day
    m = re.search(r"(\d\d):(\d\d):(\d\d)", ts)
    h, mi, s = (int(x) for x in m.groups())
    return h * 3600 + mi * 60 + s


def sod_from_phase(t):
    hh, mm, rest = t.split(":")
    return int(hh) * 3600 + int(mm) * 60 + float(rest)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    cap, phases_file = sys.argv[1], sys.argv[2]

    # --- samples: (seconds-of-day, watts) ---
    samples = []
    cur_ts = None
    with open(cap, errors="replace") as f:
        for line in f:
            m = SAMPLE.match(line)
            if m:
                cur_ts = sod_from_sample(m.group("ts"))
                continue
            m = POWER.search(line)
            if m and cur_ts is not None:
                samples.append((cur_ts, float(m.group("w"))))
                cur_ts = None
    if not samples:
        print("FAIL: no power samples parsed -- is this a cpu_power capture?")
        return 1

    # --- phases and counts ---
    bounds, counts = [], {}
    for line in open(phases_file, errors="replace"):
        m = PHASE.match(line)
        if m:
            bounds.append((m.group("tag"), sod_from_phase(m.group("t"))))
            continue
        m = COUNT.match(line)
        if m:
            counts[m.group("tag")] = {
                "ops": int(m.group("ops")), "elapsed": float(m.group("el")),
                "ops_s": float(m.group("ops_s")), "fh": float(m.group("fh")),
                "sh": float(m.group("sh")), "drift": m.group("dr")}

    # --- assign samples, dropping boundary-straddling ones ---
    phases = []
    for i, (tag, start) in enumerate(bounds):
        if tag == "done":
            continue
        end = bounds[i + 1][1]
        inside = [w for (t, w) in samples if start <= t < end]
        kept = inside[1:-1] if len(inside) > 2 else []
        phases.append({"tag": tag, "start": start, "end": end, "dur": end - start,
                       "n_raw": len(inside), "n": len(kept),
                       "mean": (sum(kept) / len(kept)) if kept else float("nan")})

    # --- coverage check: the capture must bracket the whole run ---
    first_s, last_s = samples[0][0], samples[-1][0]
    run_start, run_end = bounds[0][1], bounds[-1][1]
    print("=== coverage ===")
    print(f"  capture : {first_s/3600:.4f}h .. {last_s/3600:.4f}h  ({len(samples)} samples)")
    print(f"  harness : {run_start/3600:.4f}h .. {run_end/3600:.4f}h")
    if first_s > run_start or last_s < run_end:
        print("  WARNING: the capture does NOT fully bracket the run. Phases at the")
        print("           uncovered end are incomplete and their figures are not usable.")
    else:
        print("  OK: capture brackets the whole run.")
    print()

    by_tag = {p["tag"]: p for p in phases}
    idles = [p for p in phases if p["tag"].startswith("idle")]
    idle_mean = sum(p["mean"] for p in idles) / len(idles)

    print("=== phases (package power, W) ===")
    print(f"  {'phase':<14} {'dur':>5} {'smp':>5} {'kept':>5} {'mean W':>8}")
    for p in phases:
        print(f"  {p['tag']:<14} {p['dur']:>5.0f} {p['n_raw']:>5} {p['n']:>5} {p['mean']:>8.2f}")
    print()
    print("=== idle baseline ===")
    for p in idles:
        print(f"  {p['tag']:<14} {p['mean']:>8.2f} W")
    print(f"  {'MEAN of all':<14} {idle_mean:>8.2f} W   <- baseline for net power")
    print(f"  start vs end : {by_tag['idle_start']['mean']:.2f} -> "
          f"{by_tag['idle_end']['mean']:.2f} W  "
          f"(drift {by_tag['idle_end']['mean'] - by_tag['idle_start']['mean']:+.2f} W)")
    print()

    print("=== energy per operation ===")
    print(f"  {'phase':<14} {'ops/s':>10} {'gross W':>8} {'net W':>7} "
          f"{'gross uJ':>9} {'net uJ':>8}  drift")
    rows = {}
    for tag in ("ours_keygen", "ours_encaps", "ours_decaps",
                "kyber_keygen", "kyber_encaps", "kyber_decaps"):
        if tag not in by_tag or tag not in counts:
            continue
        p, c = by_tag[tag], counts[tag]
        gross_w = p["mean"]
        net_w = gross_w - idle_mean
        gross_uj = gross_w / c["ops_s"] * 1e6
        net_uj = net_w / c["ops_s"] * 1e6
        rows[tag] = {"gross_w": gross_w, "net_w": net_w,
                     "gross_uj": gross_uj, "net_uj": net_uj, **c}
        print(f"  {tag:<14} {c['ops_s']:>10.0f} {gross_w:>8.2f} {net_w:>7.2f} "
              f"{gross_uj:>9.3f} {net_uj:>8.3f}  {c['drift']}")
    print()

    print("=== ours vs pq-crystals (net energy per operation) ===")
    for op in ("keygen", "encaps", "decaps"):
        a, b = rows.get("ours_" + op), rows.get("kyber_" + op)
        if not a or not b:
            continue
        print(f"  {op:<8} ours {a['net_uj']:.3f} uJ   pq-crystals {b['net_uj']:.3f} uJ   "
              f"ratio {a['net_uj']/b['net_uj']:.2f}x")
    return 0


if __name__ == "__main__":
    sys.exit(main())
