#!/usr/bin/env python3
"""Signature vectors for other parameter sets, from a modified copy of the
BIP's reference implementation.

  gen_param_vectors.py SHRINCS_PY OUTDIR [JOBS]

For every parameter set in SETS, the constants of SHRINCS_PY (impl/shrincs.py)
are replaced, and the assertion that stateful signatures are shorter than
stateless ones is dropped (some sets violate it; it is a design constraint,
not part of verification). Each set gets a key from a fixed seed, and
NSTATELESS stateless and NSTATEFUL stateful signatures (first leaf of an
unbalanced FXMSS tree of depth 6, i.e. depth 1) on random 32-byte messages,
each checked with the modified reference's shrincs_verify. Writes
OUTDIR/<name>.csv (pubkey, message, ctx, signature in hex) and runs JOBS
processes in parallel.
"""

import csv
import importlib.util
import multiprocessing
import os
import random
import re
import sys
import tempfile
from binascii import hexlify

# name: (stateless chain bits, layers, XMSS height, FORS height, FORS count, stateful chain bits)
SETS = {
    "sl-45-5-10-13-16": (4, 5, 9, 13, 10, 4),
    "sl-40-5-10-15-32": (5, 5, 8, 15, 10, 4),
    "sl-42-6-9-15-64": (6, 6, 7, 15, 9, 4),
    "sl-40-5-9-16-64": (6, 5, 8, 16, 9, 4),
    "sl-40-4-9-16-64": (6, 4, 10, 16, 9, 4),
    "sl-44-4-8-16-64": (6, 4, 11, 16, 8, 4),
    "sl-42-3-7-19-64": (6, 3, 14, 19, 7, 4),
    "sf-w16": (4, 5, 9, 13, 10, 4),
    "sf-w32": (4, 5, 9, 13, 10, 5),
    "sf-w64": (4, 5, 9, 13, 10, 6),
}
NSTATELESS = 64
NSTATEFUL = 64
NAMES = ["WOTS_TW_CHAIN_BITS", "SPHX_LAYER_COUNT", "SPHX_XMSS_HEIGHT", "SPHX_FORS_HEIGHT",
         "SPHX_FORS_COUNT", "WOTS_C_CHAIN_BITS"]

_modules = {}


def module(source, name):
    """The reference implementation with the constants of set `name`."""
    if name not in _modules:
        text = open(source).read()
        for const, value in zip(NAMES, SETS[name]):
            text, n = re.subn(rf"^({const}\s*=\s*)\d+", rf"\g<1>{value}", text, flags=re.M)
            assert n == 1, const
        text, n = re.subn(r"^assert SHRINCS_SF_SIGNATURE_SIZE_MAX < SHRINCS_SL_SIGNATURE_SIZE\n", "", text, flags=re.M)
        assert n == 1
        path = os.path.join(tempfile.mkdtemp(), f"shrincs_{name.replace('-', '_')}.py")
        open(path, "w").write(text)
        spec = importlib.util.spec_from_file_location(os.path.basename(path)[:-3], path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _modules[name] = mod
    return _modules[name]


def keygen(args):
    source, name = args
    m = module(source, name)
    seed = m.sha256(name.encode() + b"1") + m.sha256(name.encode() + b"2")
    seckey, _ = m.shrincs_keygen(seed[:48], bytes([m.FXMSS_SHAPE_UNBALANCED, 6]))
    return name, seckey


def sign(args):
    source, name, seckey, stateless, i = args
    m = module(source, name)
    rng = random.Random(f"{name}-{stateless}-{i}")
    msg = bytes(rng.randrange(256) for _ in range(32))
    sig = m.shrincs_sign(msg, b"", seckey, None if stateless else 0, None)
    pub = m.shrincs_extract_pubkey(seckey)
    assert m.shrincs_verify(msg, sig, b"", pub)
    return name, pub, msg, sig


def main():
    source, out = sys.argv[1], sys.argv[2]
    jobs = int(sys.argv[3]) if len(sys.argv) > 3 else os.cpu_count()
    os.makedirs(out, exist_ok=True)
    with multiprocessing.Pool(jobs) as pool:
        keys = dict(pool.map(keygen, [(source, n) for n in SETS]))
        print("keys generated", flush=True)
        tasks = []
        for name, seckey in keys.items():
            n = NSTATELESS if name.startswith("sl-") else 0
            tasks += [(source, name, seckey, True, i) for i in range(n)]
            n = NSTATEFUL if name.startswith("sf-") else 0
            tasks += [(source, name, seckey, False, i) for i in range(n)]
        tasks.sort(key=lambda t: -SETS[t[1]][2])  # tallest XMSS trees first
        rows = {}
        for name, pub, msg, sig in pool.imap_unordered(sign, tasks):
            rows.setdefault(name, []).append((pub, msg, b"", sig))
    for name, data in rows.items():
        data.sort(key=lambda row: row[1])
        with open(os.path.join(out, f"{name}.csv"), "w", newline="") as fh:
            w = csv.writer(fh)
            for row in data:
                w.writerow([hexlify(x).decode() for x in row])
        print(f"{name}: {len(data)} signatures of {len(data[0][3])} bytes")


if __name__ == "__main__":
    main()
