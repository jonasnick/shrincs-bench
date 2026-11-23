"""Tabulate a run of run_bench.sh against the verification density limit.

    python3 verifier/table.py RESULTS.jsonl MICRO.json

RESULTS.jsonl is the output of run_bench.sh, MICRO.json the output of
`model/measure_constants.py microbench` on the same machine. For every
parameter set, the table gives the verification time in BIP340 verifications
of four variants and, in parentheses, the allowed time divided by it (at
least 1 meets the limit). The allowed time is the spend's weight divided by
the weight of a Schnorr key-path spend (model/shrincs_block_cost.py), minus
the compressions that open the P2MR commitment, which the verifier benchmark
does not time, at the portable-C kappa of MICRO.json.
"""

import json
import os
import statistics
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "model"))
import shrincs_block_cost as m  # noqa: E402

COLUMNS = [
    ("portable C", "g++ -O2", "one at a time, portable C"),
    ("Core's SSE4", "g++ -O2", "one at a time, best"),
    ("4 lanes, gcc `-O2`", "g++ -O2", "4 lanes, rest portable C"),
    ("8 lanes, clang `-O2 -march=native`", "clang++ -O2 -march=native", "8 lanes, rest portable C"),
]


def kind_params(name):
    """Model kind and parameters of a set name such as sl-45-5-10-13-16 (h, d,
    k, a, w) or sf-w32 (first leaf, w)."""
    if name.startswith("sf-w"):
        return "stateful", (1, int(name[4:]))
    return "stateless", tuple(int(x) for x in name[3:].split("-"))


def portable_kappa(micro):
    rounds = json.load(open(micro))["rounds"]
    return statistics.median(r["verify"] / r["sha256"]["standard"]["call"] for r in rounds)


def main():
    results, micro = sys.argv[1:3]
    kappa = portable_kappa(micro)
    rows = {}
    for line in open(results):
        r = json.loads(line)
        rows[(r["set"], r["compiler"], r["variant"])] = r
    sets = list(dict.fromkeys(r[0] for r in rows))
    w_s = m.schnorr_weight()
    print(f"portable-C kappa {kappa:.0f}, Schnorr key-path spend {w_s:.1f} WU\n")
    print("| Parameter set | Size | Allowed | " + " | ".join(c[0] for c in COLUMNS) + " |")
    print("|---|---:|---:|" + "---:|" * len(COLUMNS))
    for name in sets:
        kind, params = kind_params(name)
        size = m.signature(kind, params)[0]
        allowed = m.input_costs(kind, params, "p2mr", kappa)[0] / w_s - m.opening("p2mr", kappa) / kappa
        cells = []
        for _, compiler, variant in COLUMNS:
            r = rows[(name, compiler, variant)]
            assert r["bytes"] == size, (name, r["bytes"], size)
            t = r["bip340_per_verification"]
            cells.append(f"{t:.1f} ({allowed / t:.2f})")
        label = f"stateful, $w = {params[1]}$" if kind == "stateful" else str(params)
        print(f"| {label} | {size:,} B | {allowed:.1f} | " + " | ".join(cells) + " |")


if __name__ == "__main__":
    main()
