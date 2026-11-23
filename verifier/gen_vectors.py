#!/usr/bin/env python3
"""Signature vectors for the C verifier, from the BIP's reference implementation.

  gen_vectors.py SHRINCS_BIP_DIR OUTDIR

Writes OUTDIR/signatures_valid.csv, regenerated exactly as
gen_test_vectors.py does and checked against the committed fingerprint, and
OUTDIR/bench.csv: signatures with the key of the official vectors on random
32-byte messages, NSTATELESS stateless ones and NSTATEFUL stateful ones at
the first leaf (depth 1). Both files have the columns pubkey, message, ctx,
signature (hex). Does not write into the BIP repository.
"""

import csv
import hashlib
import os
import random
import sys
from binascii import hexlify, unhexlify

NSTATELESS = 16
NSTATEFUL = 64


def main():
    bip, out = sys.argv[1], sys.argv[2]
    sys.path.insert(0, bip)
    import gen_test_vectors as g
    from impl import shrincs

    os.makedirs(out, exist_ok=True)
    # The official signature vectors, written as gen_test_vectors.py writes them.
    path = os.path.join(out, "signatures_valid.csv")
    rows = []
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["seckey", "pubkey", "message", "ctx", "opt_rand", "state_ctr", "signature"])
        for inp in g.SIGNATURES_VALID_TEST_VEC_INPUTS:
            sig = shrincs.shrincs_sign(inp.message, inp.ctx, inp.seckey, inp.state_ctr, inp.opt_rand)
            pub = shrincs.shrincs_extract_pubkey(inp.seckey)
            assert shrincs.shrincs_verify(inp.message, sig, inp.ctx, pub)
            w.writerow([hexlify(inp.seckey).decode(), hexlify(pub).decode(), hexlify(inp.message).decode(),
                        hexlify(inp.ctx).decode(), "" if inp.opt_rand is None else hexlify(inp.opt_rand).decode(),
                        "" if inp.state_ctr is None else inp.state_ctr, hexlify(sig).decode()])
            rows.append((pub, inp.message, inp.ctx, sig))
    with open(path, "rb") as fh:
        fingerprint = hashlib.sha256(fh.read()).hexdigest()
    with open(os.path.join(bip, "test_vectors", "signatures_valid.csv.fp")) as fh:
        committed = fh.read().strip()
    print(f"signatures_valid.csv fingerprint {'matches' if fingerprint == committed else 'DIFFERS FROM'} the committed one")
    if fingerprint != committed:
        sys.exit(1)

    seckey = g.SIGNATURES_VALID_TEST_VEC_INPUTS[0].seckey
    pub = shrincs.shrincs_extract_pubkey(seckey)
    rng = random.Random(20261120)
    bench = []
    for n, state_ctr in ((NSTATELESS, None), (NSTATEFUL, 0)):
        for _ in range(n):
            msg = bytes(rng.randrange(256) for _ in range(32))
            sig = shrincs.shrincs_sign(msg, b"", seckey, state_ctr, None)
            assert shrincs.shrincs_verify(msg, sig, b"", pub)
            bench.append((pub, msg, b"", sig))
        print(f"{n} {'stateless' if state_ctr is None else 'stateful'} signatures of {len(sig)} bytes", flush=True)
    for name, data in (("official.csv", rows), ("bench.csv", bench)):
        with open(os.path.join(out, name), "w", newline="") as fh:
            w = csv.writer(fh)
            for pub_, msg, ctx, sig in data:
                w.writerow([hexlify(pub_).decode(), hexlify(msg).decode(), hexlify(ctx).decode(), hexlify(sig).decode()])


if __name__ == "__main__":
    main()
