#!/usr/bin/env python3
"""Seed the fuzz corpus from the NIST ACVP vectors.

  python3 tools/seed_fuzz_corpus.py <corpus-dir> [--target decaps|keycheck]

WHY SEED AT ALL. libFuzzer starting from nothing has to discover the input layout by
mutation, and the layouts here begin with a 32-byte seed pair that feeds key generation --
bytes with no structure a fuzzer can hill-climb toward. Seeding with real NIST `d`/`z`
values and real messages starts it on inputs that already reach the deep code, so the
budget goes on the parts that matter instead of on finding the doorway.

Never reads the vector JSON into the conversation: prints counts only.
"""

import glob
import json
import os
import sys


def find_vectors():
    pats = ["tests/kat/vectors/*keyGen*.json", "tests/kat/vectors/*encapDecap*.json"]
    out = []
    for p in pats:
        out += sorted(glob.glob(p))
    return out


def collect(files):
    """Pull (d, z) seed pairs and m messages out of whatever ACVP files are present."""
    seeds, msgs = [], []
    for path in files:
        try:
            doc = json.load(open(path))
        except Exception as e:
            print(f"  skip {os.path.basename(path)}: {e}")
            continue
        for grp in doc.get("testGroups", []):
            for t in grp.get("tests", []):
                d, z, m = t.get("d"), t.get("z"), t.get("m")
                if d and z:
                    try:
                        seeds.append((bytes.fromhex(d), bytes.fromhex(z)))
                    except ValueError:
                        pass
                if m:
                    try:
                        msgs.append(bytes.fromhex(m))
                    except ValueError:
                        pass
    return seeds, msgs


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    out_dir = sys.argv[1]
    target = "decaps"
    if "--target" in sys.argv:
        target = sys.argv[sys.argv.index("--target") + 1]
    os.makedirs(out_dir, exist_ok=True)

    files = find_vectors()
    if not files:
        print("no ACVP vector files found under tests/kat/vectors/ -- corpus not seeded.")
        print("the fuzzer still runs, it just starts cold. gmake fetch-vectors first.")
        return 0

    seeds, msgs = collect(files)
    print(f"  parsed {len(files)} vector file(s): {len(seeds)} (d,z) seed pairs, "
          f"{len(msgs)} messages")
    if not seeds:
        print("  no seed pairs found; corpus not seeded")
        return 0

    n = 0
    if target == "decaps":
        # layout: d(32) || z(32) || m(32) || mode(1) || mutation payload
        for i, (d, z) in enumerate(seeds):
            m = msgs[i % len(msgs)] if msgs else bytes(32)
            if len(m) != 32:
                m = (m + bytes(32))[:32]
            # one seed with no mutations (a VALID ciphertext: exercises the accept path,
            # which random mutation would essentially never reach), and one with a few.
            # mode byte 0 = PATCH with no payload -> a VALID ciphertext, which is the
            # accept path; random mutation would essentially never reach it.
            open(os.path.join(out_dir, f"acvp{i:03d}_clean"), "wb").write(d + z + m + b"\x00")
            mut = bytes([0x11, 0x00, 0x01, 0x22, 0x01, 0x80])
            open(os.path.join(out_dir, f"acvp{i:03d}_patch"), "wb").write(
                d + z + m + b"\x00" + mut)
            # mode 1 = OVERLAY, seeded with a real ciphertext prefix so the fuzzer starts
            # with direct byte control from a structurally plausible point.
            open(os.path.join(out_dir, f"acvp{i:03d}_overlay"), "wb").write(
                d + z + m + b"\x01" + bytes(64))
            n += 3
    else:
        # layout: mode(1) || d(32) || z(32) || tail
        for i, (d, z) in enumerate(seeds):
            for mode in (0, 1, 2, 3):
                open(os.path.join(out_dir, f"acvp{i:03d}_m{mode}"), "wb").write(
                    bytes([mode]) + d + z + bytes([0x00, 0x00, 0x01]))
                n += 1

    print(f"  wrote {n} corpus file(s) to {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
