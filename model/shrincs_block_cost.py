#!/usr/bin/env python3
"""Validation cost of full blocks of SHRINCS spends: w = 64 versus w = 16.

A full block (4M WU) of ordinary spends of one type is validated by a node
running Bitcoin Core. Its cost has two parts:

  - Script checks: one signature verification per input, plus its sighash
    and, for script-path spends, the commitment check. The main thread
    prepares the checks and P - 1 worker threads (-par=P) run them while the
    main thread continues.
  - Everything else, on the main thread: loading the block, hashing its
    transactions, fetching and updating coins, writing undo data and the
    chainstate. This scales with the number of inputs, outputs and bytes.

All costs are in units of one BIP340 verification (V). Bitcoin Core's
SHA-256 work is counted from the serialization and the SHRINCS parameter
sets: txids, wtxids, Merkle roots, BIP341 precomputation, sighashes,
signature-cache and script-execution-cache keys, TapLeaf/TapTweak/TapBranch
hashes and SHRINCS verification. The count is an approximate ledger (padding
is averaged where sizes are averages, Merkle trees have one node per
transaction), priced at 1/KAPPA V per compression, the cost of one short
hash call. Changing KAPPA therefore changes all of this hashing, not only
SHRINCS. BIP340 verification itself does not depend on SHA extensions,
because libsecp256k1 uses its own portable SHA-256. SHRINCS verification is
modelled as scalar hashing; no SHRINCS verifier was timed, and a verifier
could hash independent chains in parallel with SIMD.

The constants below are the only measured inputs; measure_constants.py
measures them with an unmodified Bitcoin Core on real mainnet blocks and
prints this block. They are machine-specific: expressing them in V assumes
that the costs of coins, memory and disk scale with the cost of a
verification from one machine to another. Applying them to blocks of SHRINCS
spends extrapolates from today's blocks, which have many more, smaller
inputs.

With P threads the block takes

    other + prep + max(0, checks - (P - 1) * (loop + prep)) / P,

where loop is the part of `other` spent in the main thread's transaction
loop, prep is the main thread's script preparation and checks is the work of
the queued script checks: script work is free while the workers keep up with
the main thread and costs 1/P beyond that. All costs are elapsed time; P = 1
means one script thread (Bitcoin Core still prefetches coins on separate
threads).

Run with any Python 3.9+; no dependencies.
"""

from math import ceil

# ---------------------------------------------------------------------------
# Measured constants (measure_constants.py): AMD Ryzen 9 7950X3D, pinned to
# the CCD with the 32 MB L3; Bitcoin Core 32.1; mainnet blocks 972944-973943
# reconnected with dbcache=1024 and 125 GB RAM. Reconnecting skips work that a
# new block needs (undo data and block writes, contextual checks), and the
# coins database was in the OS page cache, so the non-script costs are likely
# low. Limiting bitcoind to 4 GB including the page cache and evicting its
# files before each run (NVMe disks) raised them to PER_BYTE = 1.35e-04,
# PER_INPUT = 0.032, LOOP_PER_INPUT = 0.0126 and PREP_PER_INPUT = 0.00998,
# which changes the costs relative to the Schnorr block by up to 11% with one
# script thread and up to 32% with eight (most with SHA-NI, where the scripts
# are cheap).
# ---------------------------------------------------------------------------

# SHA-256 compressions per BIP340 verification, per SHA-256 implementation.
KAPPA = {"portable C": 202, "SHA-NI": 696}
# BIP341 script-path commitment check (xonly_pubkey_tweak_add_check), V.
TWEAK_CHECK = 0.73
# Reference transaction shape: inputs and outputs per transaction, averaged
# over the 12 months from 2025-11-17 to 2026-11-16 (mainnet.observer). The
# per-input costs below were measured with the shape of the measured blocks
# (1.71 inputs and 2.28 outputs per transaction, 1.33 outputs per input
# instead of 1.29), and include the input's share of outputs at that shape.
INPUTS_PER_TX = 1.85
OUTPUTS_PER_TX = 2.39
# Non-script cost without SHA-256, V: loading and checking the block per
# byte, everything else (coins, UTXO updates) per input, including the
# input's share of outputs at the shape above.
PER_BYTE = 7.4e-05
PER_INPUT = 0.0298
# The part of the input cost spent in the main thread's transaction loop, V.
LOOP_PER_INPUT = 0.0107
# Main-thread script preparation without SHA-256, V per input.
PREP_PER_INPUT = 0.00831

# ---------------------------------------------------------------------------
# What to compare
# ---------------------------------------------------------------------------

BLOCK_WEIGHT = 4_000_000
THREADS = [1, 4, 8]
# Reference hardware for the criterion: compressions per BIP340 verification
# (mjthatch's benchmark in SHRINCS/shrincs-bip#32, also used in SHRINCS.md).
# This is a choice, not a measurement of the machine above.
KAPPA_REF = 127
# (label, kind, parameters): stateful (leaf depth, w), stateless and slh-dsa
# (h, d, k, a, w).
SPENDS = [
    ("Schnorr key path", "schnorr", None),
    ("stateful w=16", "stateful", (1, 16)),
    ("stateful w=32", "stateful", (1, 32)),
    ("stateful w=64", "stateful", (1, 64)),
    ("stateless (45,5,10,13,16)", "stateless", (45, 5, 10, 13, 16)),
    ("stateless (40,5,10,15,32)", "stateless", (40, 5, 10, 15, 32)),
    ("stateless (42,6,9,15,64)", "stateless", (42, 6, 9, 15, 64)),
    ("stateless (40,5,9,16,64)", "stateless", (40, 5, 9, 16, 64)),
    ("stateless (40,4,9,16,64)", "stateless", (40, 4, 9, 16, 64)),
    ("stateless (44,4,8,16,64)", "stateless", (44, 4, 8, 16, 64)),
    ("stateless (42,3,7,19,64)", "stateless", (42, 3, 7, 19, 64)),
    ("SLH-DSA-128s", "slh-dsa", (63, 7, 14, 12, 16)),
]
# Stateful leaf depths to compare, and blocks that mix stateful and stateless
# spends with the same w for both paths.
STATEFUL_DEPTHS = [1, 8, 32, 128, 255]
STATEFUL_SHARE = 0.9
# Signature sizes (bytes) for the break-even table.
BREAK_EVEN_SIZES = [400, 550, 1000, 2500, 5000, 8000]
MIXED_STATELESS = {16: (45, 5, 10, 13, 16), 64: (42, 6, 9, 15, 64)}
# w = 64 relative to w = 16: (label, numerator, denominator).
PAIRS = [("stateful", "stateful w=64", "stateful w=16"),
         ("(42,6,9,15,64)", "stateless (42,6,9,15,64)", "stateless (45,5,10,13,16)"),
         ("(40,5,9,16,64)", "stateless (40,5,9,16,64)", "stateless (45,5,10,13,16)")]


# ---------------------------------------------------------------------------
# SHRINCS sizes and verification compressions (SHRINCS.md cost model)
# ---------------------------------------------------------------------------

def sha256_compressions(size):
    """Compressions to hash `size` bytes after a cached 64-byte prefix."""
    return size // 64 + (1 if size % 64 < 56 else 2)


def tweak_hash(num_values):
    """Hash of a 22-byte compressed address and num_values 16-byte values."""
    return sha256_compressions(22 + 16 * num_values)


def wots_lengths(w, msg_bits=128):
    """WOTS chain counts (len1, len2) for base w, as in FIPS 205."""
    lg = w.bit_length() - 1
    len1 = ceil(msg_bits / lg)
    len2 = ((len1 * (w - 1)).bit_length() - 1) // lg + 1
    return len1, len2


def wots_verify_chain_work(w, msg_bits=128):
    """(expected, maximum) WOTS chain steps to verify a uniformly random digest.

    The verifier finishes each chain: w - 1 - m_i steps for every message
    digit m_i and the same for every checksum digit. If log2(w) does not
    divide the digest length, base_2b pads the last digit with trailing zero
    bits. The expectation is exact, by convolving integer counts of digests.
    """
    lg = w.bit_length() - 1
    len1, len2 = wots_lengths(w, msg_bits)
    last_bits = msg_bits - lg * (len1 - 1)
    digits = [range(w)] * (len1 - 1)
    digits.append([m << (lg - last_bits) for m in range(2**last_bits)])

    dist = {0: 1}  # dist[s] = number of digests with message chain work s
    for values in digits:
        new = {}
        for s, count in dist.items():
            for m in values:
                t = s + (w - 1 - m)
                new[t] = new.get(t, 0) + count
        dist = new

    def checksum_work(csum):
        work = 0
        for _ in range(len2):
            work += w - 1 - csum % w
            csum //= w
        return work

    expected = sum(count * (s + checksum_work(s)) for s, count in dist.items()) / 2**msg_bits
    maximum = max(s + checksum_work(s) for s in dist)
    return expected, maximum


def stateful(depth, w):
    """(signature bytes, compressions) of a stateful signature at leaf depth."""
    lg = w.bit_length() - 1
    chains = ceil(128 / lg)
    constant_sum = ceil(chains * (w - 1) / 2)
    size = 1 + 16 + ceil(min(depth, 64) / 8) + 2 + 16 * chains + 16 * depth
    cost = (4                                   # H_msg_sf
            + 1                                 # H_grind
            + chains * (w - 1) - constant_sum   # finish the chains (constant)
            + tweak_hash(chains)                # compress the WOTS+C public key
            + depth)                            # one H per Merkle path node
    return size, cost


def stateless(h, d, k, a, w):
    """(signature bytes, expected compressions, worst compressions)."""
    len1, len2 = wots_lengths(w)
    l = len1 + len2
    size = 16 * (1 + h + d * l + k * (a + 1)) + 1   # + algorithm indicator
    chain_avg, chain_max = wots_verify_chain_work(w)
    fixed = (2                    # H_msg
             + k                  # FORS leaf hashes
             + k * a              # FORS authentication paths
             + tweak_hash(k)      # FORS roots
             + h                  # XMSS authentication paths across all layers
             + d * tweak_hash(l)  # WOTS public-key compressions
             + 2)                 # SHRINCS wrapper
    return size, fixed + d * chain_avg, fixed + d * chain_max


def signature(kind, params):
    """(signature bytes, expected verification compressions) of a hash-based
    signature. "slh-dsa" is a stateless set without the SHRINCS algorithm
    indicator and wrapper; "hash" is any scheme, given as (bytes,
    compressions). Every kind is spent like a SHRINCS signature."""
    if kind == "stateful":
        return stateful(*params)
    if kind == "stateless":
        return stateless(*params)[:2]
    if kind == "slh-dsa":
        size, expected, _ = stateless(*params)
        return size - 1, expected - 2
    return params


def check_cost_model():
    """Check the cost model against published numbers: SHRINCS.md, and the
    SPHINCS-Parameters website (worst case, without the SHRINCS wrapper)."""
    assert stateful(1, 16) == (548, 255) and stateful(255, 16) == (4619, 509)
    assert stateless(45, 5, 10, 13, 16)[::2] == (5777, 2792)
    assert stateless(63, 7, 14, 12, 16)[2] - 2 == 3891  # SLH-DSA-128s
    assert signature("slh-dsa", (63, 7, 14, 12, 16))[0] == 7856
    assert stateless(40, 4, 9, 16, 64)[2] - 2 == 6022
    assert stateless(44, 4, 8, 16, 64)[2] - 2 == 6009
    # Expected chain work: 32 uniform base-16 digits; for w = 64, 21 uniform
    # digits and a last digit in {0, 16, 32, 48} (closed form 50211/64).
    assert abs(wots_verify_chain_work(16)[0] - 267.1229045) < 1e-6
    assert wots_verify_chain_work(64)[0] == 50211 / 64


# ---------------------------------------------------------------------------
# Serialization (BIP141, BIP341, BIP342) and Bitcoin Core's SHA-256 work
# ---------------------------------------------------------------------------

TX_NONWIT = 4 + 4 + 1 + 1           # version, locktime, input and output counts
TX_MARKER_FLAG = 2                  # segwit marker and flag (witness bytes)
INPUT_NONWIT = 32 + 4 + 1 + 4       # outpoint, empty scriptSig, sequence
OUTPUT = 8 + 1 + 34                 # value, script length, P2TR or P2MR script
SHRINCS_LEAF = 1 + 49 + 1           # push, flagged 49-byte public key, opcode


def compact_size_len(n):
    return 1 if n < 0xfd else 3 if n <= 0xffff else 5


def witness_len(items):
    return compact_size_len(len(items)) + sum(compact_size_len(n) + n for n in items)


def hash_compressions(size):
    """Compressions of SHA-256 over `size` bytes, or of a tagged hash with its
    tag midstate cached."""
    return ceil((size + 9) / 64)


def average_hash_compressions(size):
    """hash_compressions() for an average size, averaging over the position
    of the padding."""
    return (size + 9) / 64 + 0.5


# One SHA256D64 per Merkle tree node: two compressions for the 64-byte
# input and one for the second hash.
MERKLE_NODE = 3


def block_hashing(txs, stripped, size, segwit_txs, segwit_size, merkle_trees=2):
    """Compressions of the txids, wtxids and Merkle trees of a block.

    stripped is the total size without witness data, segwit_size the total
    size of the segwit transactions; a non-segwit transaction's wtxid is its
    txid. Each txid and wtxid is a SHA256d, with the padding of the first
    hash averaged. A new block needs both Merkle trees (CheckBlock and
    ContextualCheckBlock); reconnecting a block recomputes only the
    transaction tree.
    """
    return (stripped / 64 + (9 / 64 + 1.5) * txs
            + segwit_size / 64 + (9 / 64 + 1.5) * segwit_txs
            + merkle_trees * MERKLE_NODE * txs)


def precompute_hashing(ins_per_tx, outs_per_tx):
    """Main-thread hashing per transaction: the BIP341 hashes of prevouts,
    amounts, scriptPubKeys, sequences and outputs, and the script-execution
    cache key (wtxid and flags)."""
    return (sum(average_hash_compressions(n * ins_per_tx) for n in (36, 8, 35, 4))
            + average_hash_compressions(OUTPUT * outs_per_tx)
            + hash_compressions(32 + 4))


def spend(kind, params, commitment):
    """Witness bytes and script-check work of one spend.

    commitment is "p2tr" (single-leaf P2TR script path: 33-byte control block,
    TapLeaf and TapTweak hashes, tweak check) or "p2mr" (P2MR script at depth
    one: 33-byte control block, TapLeaf and TapBranch hashes; BIP360 skips
    script execution at depth zero). Schnorr uses the P2TR key path.

    Every check hashes its signature-cache entry (sighash, public key and
    signature after a cached 64-byte salt), as Bitcoin Core does for BIP340;
    a SHRINCS implementation is assumed to do the same.
    Returns (witness bytes, BIP340 verifications, tweak checks, compressions).
    """
    sighash = hash_compressions(1 + 174 + (0 if kind == "schnorr" else 37))
    if kind == "schnorr":
        return witness_len([64]), 1, 0, sighash + hash_compressions(32 + 32 + 64)
    sig, verify = signature(kind, params)
    compressions = verify + sighash + hash_compressions(32 + 49 + sig) + commitment_hashes()
    if commitment == "p2tr":
        return witness_len([sig, SHRINCS_LEAF, 33]), 0, 1, compressions
    return witness_len([sig, SHRINCS_LEAF, 1 + 32]), 0, 0, compressions


def commitment_hashes():
    """Compressions of the TapLeaf hash and of the TapBranch (P2MR) or
    TapTweak (P2TR) hash that open a script-path spend's commitment."""
    return hash_compressions(1 + compact_size_len(SHRINCS_LEAF) + SHRINCS_LEAF) + hash_compressions(64)


# ---------------------------------------------------------------------------
# Full blocks
# ---------------------------------------------------------------------------

def input_costs(kind, params, commitment, kappa):
    """Weight (WU) of one input, including its share of the transaction, and
    its costs (V): other, loop, prep and checks (see the module docstring)."""
    witness, schnorr, tweak, compressions = spend(kind, params, commitment)
    i, o = INPUTS_PER_TX, OUTPUTS_PER_TX
    nonwit = INPUT_NONWIT + (TX_NONWIT + OUTPUT * o) / i
    wit = witness + TX_MARKER_FLAG / i
    size = nonwit + wit
    hashing = block_hashing(1 / i, nonwit, size, 1 / i, size)
    other = PER_INPUT + PER_BYTE * size + hashing / kappa
    prep = PREP_PER_INPUT + precompute_hashing(i, o) / i / kappa
    checks = schnorr + tweak * TWEAK_CHECK + compressions / kappa
    return 4 * nonwit + wit, (other, LOOP_PER_INPUT, prep, checks)


def block(parts, commitment, kappa):
    """Cost (V) of a full block for each P in THREADS, the script checks'
    share at P = 1, and the block's number of inputs.

    parts lists (fraction of inputs, kind, parameters) of the spends.
    """
    inputs = [(f, *input_costs(kind, params, commitment, kappa)) for f, kind, params in parts]
    ins = BLOCK_WEIGHT / sum(f * weight for f, weight, _ in inputs)
    other, loop, prep, checks = (ins * sum(f * c[j] for f, _, c in inputs) for j in range(4))
    cost = {p: other + prep + max(0.0, checks - (p - 1) * (loop + prep)) / p for p in THREADS}
    return cost, (prep + checks) / (other + prep + checks), ins


def full_block(kind, params, commitment, kappa):
    """block() with a single spend type."""
    return block([(1.0, kind, params)], commitment, kappa)


def reference_overhead(commitment="p2mr"):
    """X_ref: the weight (WU) that a hash-based spend adds besides its
    signature (for signatures of 253 bytes or more): its outpoint, sequence
    and empty scriptSig, its share of the transaction's overhead and outputs,
    its leaf script and control block, and the length prefixes."""
    weight, _ = input_costs("hash", (1000, 0.0), commitment, KAPPA_REF)
    return weight - 1000


def schnorr_weight():
    """W_S: the weight (WU) of a Schnorr key-path spend, with its share of the
    transaction."""
    return input_costs("schnorr", None, "p2mr", KAPPA_REF)[0]


def compressions_per_wu(kind, params, commitment, kappa):
    """C_spend / W: expected compressions to verify the signature and open the
    output's commitment (a BIP340 verification and the BIP341 tweak check
    count as kappa and TWEAK_CHECK * kappa) per weight unit of the spend."""
    weight = input_costs(kind, params, commitment, kappa)[0]
    if kind == "schnorr":
        return kappa / weight  # key path: no commitment to open
    return (signature(kind, params)[1] + opening(commitment, kappa)) / weight


def opening(commitment, kappa):
    """Compressions to open a script-path spend's commitment, with the BIP341
    tweak check of P2TR counted as TWEAK_CHECK * kappa."""
    return commitment_hashes() + (TWEAK_CHECK * kappa if commitment == "p2tr" else 0.0)


def limit_per_byte(kind, params, commitment, kappa):
    """The limit on expected compressions per signature byte: the C/B at which
    the spend has the verification density of a Schnorr key-path spend, i.e.
    C + opening = kappa * W / W_S."""
    sig = signature(kind, params)[0]
    weight = input_costs(kind, params, commitment, kappa)[0]
    return (kappa * weight / schnorr_weight() - opening(commitment, kappa)) / sig


def break_even_kappa(kind, params, commitment):
    """The kappa at which the spend has the verification density of a Schnorr
    key-path spend. Solves C + opening = kappa * W / W_S for kappa; in P2TR,
    the tweak check's part of the opening scales with kappa."""
    verify = signature(kind, params)[1]
    weight = input_costs(kind, params, commitment, KAPPA_REF)[0]
    tweak = TWEAK_CHECK if commitment == "p2tr" else 0.0
    return (verify + commitment_hashes()) / (weight / schnorr_weight() - tweak)


# BIP342's validation budget allows one BIP340 verification per this many WU.
BUDGET_WU = 50


def verification_density(kind, params, commitment, kappa):
    """Verification density in BIP340-verification equivalents (V) per 50 WU,
    i.e. the share of BIP342's validation budget that the spend uses:
    compressions_per_wu() with a compression counted as 1/kappa V. A Schnorr
    key-path spend has 50 / W_S."""
    return compressions_per_wu(kind, params, commitment, kappa) * BUDGET_WU / kappa


def break_even(sig_bytes, commitment, kappa, p, schnorr_factor=1.0):
    """Expected verification compressions at which a full block of hash-based
    spends with sig_bytes-byte signatures costs as much as a full block of
    Schnorr key-path spends, with p script threads. schnorr_factor scales
    the cost of the Schnorr block (e.g. for batch verification)."""
    target = schnorr_factor * full_block("schnorr", None, commitment, kappa)[0][p]
    lo, hi = 0.0, 1e6
    for _ in range(60):
        mid = (lo + hi) / 2
        if full_block("hash", (sig_bytes, mid), commitment, kappa)[0][p] < target:
            lo = mid
        else:
            hi = mid
    return lo


def main():
    check_cost_model()
    print(f"Full blocks of {BLOCK_WEIGHT:,} WU, {INPUTS_PER_TX} inputs and"
          f" {OUTPUTS_PER_TX} outputs per transaction. Cost in BIP340 verifications (V);"
          " dens. is the verification density in V per 50 WU.")
    kappas = {"reference": KAPPA_REF, **KAPPA}
    summary = []
    for commitment in ("p2tr", "p2mr"):
        for hw, kappa in kappas.items():
            print(f"\nSHRINCS in {commitment.upper()}, SHA-256 {hw} (KAPPA = {kappa})")
            print(f"  {'':27} {'dens.':>5} {'inputs':>6} {'scripts':>7}"
                  + "".join(f"  {'P=' + str(p):>14}" for p in THREADS))
            costs = {}
            for label, kind, params in SPENDS:
                costs[label], share, ins = full_block(kind, params, commitment, kappa)
                base = costs[SPENDS[0][0]]
                print(f"  {label:27} {verification_density(kind, params, commitment, kappa):5.3f}"
                      f" {ins:6,.0f} {share:7.0%}"
                      + "".join(f"  {costs[label][p]:7,.0f} {costs[label][p] / base[p]:5.2f}x"
                                for p in THREADS))
            summary.append((f"{commitment.upper()}, {hw}", costs))

    print("\nw=64 relative to w=16: " + ", ".join(label for label, _, _ in PAIRS))
    print(f"  {'':18}" + "".join(f"  {'P=' + str(p):<14}" for p in THREADS))
    for name, costs in summary:
        print(f"  {name:18}" + "".join(
            "  " + " ".join(f"{costs[a][p] / costs[b][p]:4.2f}" for _, a, b in PAIRS) for p in THREADS))

    print(f"\nReference overhead X_ref = {reference_overhead():.1f} WU, Schnorr spend W_S = {schnorr_weight():.1f} WU,"
          f" density limit 50 / W_S = {BUDGET_WU / schnorr_weight():.4f} V per 50 WU"
          f" (KAPPA_REF / W_S = {KAPPA_REF / schnorr_weight():.4f} compressions per WU)")
    print(f"Expected compressions per signature byte (C/B), the limit on C/B at KAPPA_REF = {KAPPA_REF},"
          " and the KAPPA at which C/B meets the limit")
    print(f"  {'':27} {'bytes':>6} {'C/B':>6} {'limit P2MR':>10} {'limit P2TR':>10}"
          f" {'KAPPA P2MR':>10} {'KAPPA P2TR':>10}")
    for label, kind, params in SPENDS[1:]:
        sig, verify = signature(kind, params)
        print(f"  {label:27} {sig:6,} {verify / sig:6.3f}"
              + "".join(f" {limit_per_byte(kind, params, c, KAPPA_REF):10.3f}" for c in ("p2mr", "p2tr"))
              + "".join(f" {break_even_kappa(kind, params, c):10.0f}" for c in ("p2mr", "p2tr")))
    print("Break-even for any hash-based scheme in P2MR (P = 1): the verification density (V per 50 WU),"
          " and the expected compressions per signature byte, at which a full block costs as much as the Schnorr block")
    print(f"  {'signature bytes':18}" + "".join(f"{s:>14}" for s in BREAK_EVEN_SIZES))
    for hw, kappa in kappas.items():
        limits = []
        for s in BREAK_EVEN_SIZES:
            c = break_even(s, "p2mr", kappa, 1)
            limits.append(f"{verification_density('hash', (s, c), 'p2mr', kappa):7.4f}{c / s:7.3f}")
        print(f"  {hw:18}" + "".join(limits))

    for hw, kappa in kappas.items():
        schnorr = full_block("schnorr", None, "p2mr", kappa)[0]

        def relative(parts):
            cost = block(parts, "p2mr", kappa)[0]
            return " ".join(f"{cost[p] / schnorr[p]:4.2f}" for p in THREADS)

        print(f"\nP2MR, SHA-256 {hw}, relative to the Schnorr block for P = "
              + ", ".join(map(str, THREADS)))
        print("  Stateful spends by leaf depth (w=16 | w=64):")
        for depth in STATEFUL_DEPTHS:
            print(f"    depth {depth:3}:  " + " | ".join(
                relative([(1.0, "stateful", (depth, w))]) for w in (16, 64)))
        print(f"  {STATEFUL_SHARE:.0%} stateful (first leaf) and {1 - STATEFUL_SHARE:.0%}"
              " stateless inputs, same w for both paths:")
        for w, params in MIXED_STATELESS.items():
            print(f"    w={w}: " + relative([(STATEFUL_SHARE, "stateful", (1, w)),
                                            (1 - STATEFUL_SHARE, "stateless", params)]))


if __name__ == "__main__":
    main()
