#!/usr/bin/env python3
"""Measure the constants of shrincs_block_cost.py with Bitcoin Core.

shrincs_block_cost.py computes the validation cost of full blocks of SHRINCS
spends from a few measured constants. This script measures them on one
machine, with an unmodified Bitcoin Core and real mainnet blocks, and prints
them as a block to paste into shrincs_block_cost.py.

Stage `microbench` times, with the libsecp256k1 and SHA-256 code of the
Bitcoin Core source tree:
  - BIP340 verification, including public-key parsing: the unit V;
  - the BIP341 script-path commitment check: TWEAK_CHECK;
  - one SHRINCS hash call (a SHA-256 midstate after the 64-byte PK.seed
    block, then a 22-byte address and a 16-byte value, i.e. one
    compression), for every SHA-256 implementation the CPU supports: KAPPA.
Each round times the verifications again after the hash calls, and KAPPA is
the median over rounds of the ratio within a round, which cancels frequency
changes between rounds; the stage warns about frequency drift within a round,
a large spread between rounds, and a run without --cpu (on CPUs with
performance and efficiency cores, the OS may move the process between them).
Two biases remain, both small and both towards a lower KAPPA, i.e. a stricter
limit: the verifications run back to back, so libsecp256k1's tables stay in
the cache (reading 1 to 8 MB between verifications made them 3% to 6% slower
on an i7-1280P), and a hash call costs more than the raw compression that
the streaming time approximates (the KAPPA it implies is also printed): 3% to
8% more with portable C or SSE4, and about 50% more with SHA-NI, whose
compression is about as fast as the call overhead.

Stage `measure` reconnects a range of mainnet blocks through Bitcoin Core's
normal ConnectTip path (invalidateblock, restart, reconsiderblock), with an
empty signature cache and with -debug=bench timing, once per run:
  - script checks skipped (assumevalid set to the tip): the non-script time
    of each block and the time of its main-thread transaction loop;
  - script checks on one thread (-par=1): the time with one script thread;
  - script checks on P threads (-par=P): the wall clock time.
It confirms from Core's log that script checks were off or on for the whole
range, and collects each block's shape with getblockstats.

Stage `constants` subtracts Bitcoin Core's SHA-256 work (txids, wtxids,
Merkle trees, BIP341 precomputation), counted with shrincs_block_cost.py and
priced at the measured cost of the node's SHA-256 implementation. It
attributes the rest of the non-script time of loading and checking a block
to its bytes, and the remaining non-script time (coins, UTXO updates) to its
inputs, including their share of outputs at the measured transaction shape.
It checks the parallel model of shrincs_block_cost.py against the -par runs,
and reports the script checks' share of the measured blocks' time with one
script thread. All times are elapsed time (Bitcoin Core's -debug=bench timers);
with -par=1, coins are still prefetched on -prevoutfetchthreads threads.

How to run:
  1. Get Bitcoin Core (release binaries and the matching source tree, for the
     microbenchmark), for example on x86_64 Linux:
       V=32.1
       curl -O https://bitcoincore.org/bin/bitcoin-core-$V/SHA256SUMS
       curl -O https://bitcoincore.org/bin/bitcoin-core-$V/bitcoin-$V-x86_64-linux-gnu.tar.gz
       sha256sum --ignore-missing -c SHA256SUMS
       tar xzf bitcoin-$V-x86_64-linux-gnu.tar.gz
       git clone --depth 1 --branch v$V https://github.com/bitcoin/bitcoin.git src-$V
  2. Sync a mainnet node. Pruning is fine if it keeps the measured range plus
     two weeks of blocks (prune=30000 keeps far more):
       bitcoind -datadir=DATA -prune=30000 -blocksonly -dbcache=8000
     Wait until it is synced ("initialblockdownload": false), then stop it.
  3. Run the stages with the node stopped and the machine otherwise idle,
     pinning everything to the same CPUs (here: one CCD of the CPU):
       ./measure_constants.py microbench --src src-$V --out micro.json --cpu 8
       ./measure_constants.py measure --bin bitcoin-$V/bin --datadir DATA --out blocks.json --cpus 8-15,24-31
       ./measure_constants.py constants micro.json blocks.json
     `measure` reconnects the range once per run (seven runs by default),
     which takes one to three hours. It leaves the node synced to its tip.

The script needs Python 3.9+ and, for `microbench`, gcc and g++.
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import shrincs_block_cost as model  # noqa: E402

# ---------------------------------------------------------------------------
# Stage 1: microbenchmark
# ---------------------------------------------------------------------------

SECP_BENCH_C = r"""
/* BIP340 verification and the BIP341 tweak check, timed with the
 * libsecp256k1 of the Bitcoin Core source tree. */
#define ENABLE_MODULE_EXTRAKEYS 1
#define ENABLE_MODULE_SCHNORRSIG 1
#include "src/secp256k1.c"
#include "src/precomputed_ecmult.c"
#include "src/precomputed_ecmult_gen.c"
#include <stdlib.h>
#include <time.h>

static secp256k1_context *ctx;
static int count;
static unsigned char (*pk)[32], (*sig)[64], (*msg)[32], (*tweaked)[32], (*tweak)[32];
static int *parity;

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec * 1e-9;
}

void secp_setup(int n) {
    int i, j;
    count = n;
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    pk = malloc(32 * n); sig = malloc(64 * n); msg = malloc(32 * n);
    tweaked = malloc(32 * n); tweak = malloc(32 * n); parity = malloc(sizeof(int) * n);
    for (i = 0; i < n; i++) {
        unsigned char sk[32];
        secp256k1_keypair kp;
        secp256k1_xonly_pubkey xpk, xq;
        secp256k1_pubkey q;
        for (j = 0; j < 32; j++) {
            sk[j] = (unsigned char)(i * 7 + j + 1);
            msg[i][j] = (unsigned char)(i + 3 * j);
            tweak[i][j] = (unsigned char)(i * 5 + j);
        }
        CHECK(secp256k1_keypair_create(ctx, &kp, sk));
        CHECK(secp256k1_keypair_xonly_pub(ctx, &xpk, NULL, &kp));
        CHECK(secp256k1_xonly_pubkey_serialize(ctx, pk[i], &xpk));
        CHECK(secp256k1_schnorrsig_sign32(ctx, sig[i], msg[i], &kp, NULL));
        CHECK(secp256k1_xonly_pubkey_tweak_add(ctx, &q, &xpk, tweak[i]));
        CHECK(secp256k1_xonly_pubkey_from_pubkey(ctx, &xq, &parity[i], &q));
        CHECK(secp256k1_xonly_pubkey_serialize(ctx, tweaked[i], &xq));
    }
}

/* Seconds per BIP340 verification, including public-key parsing. */
double secp_verify(void) {
    int i;
    double t0 = now();
    for (i = 0; i < count; i++) {
        secp256k1_xonly_pubkey xpk;
        CHECK(secp256k1_xonly_pubkey_parse(ctx, &xpk, pk[i]));
        CHECK(secp256k1_schnorrsig_verify(ctx, sig[i], msg[i], 32, &xpk));
    }
    return (now() - t0) / count;
}

/* Seconds per tweak check, including parsing the internal key. */
double secp_tweak_check(void) {
    int i;
    double t0 = now();
    for (i = 0; i < count; i++) {
        secp256k1_xonly_pubkey xpk;
        CHECK(secp256k1_xonly_pubkey_parse(ctx, &xpk, pk[i]));
        CHECK(secp256k1_xonly_pubkey_tweak_add_check(ctx, tweaked[i], parity[i], &xpk, tweak[i]));
    }
    return (now() - t0) / count;
}
"""

MAIN_BENCH_CPP = r"""
// Rounds of: BIP340 verification, tweak check, one SHRINCS hash call per
// SHA-256 implementation, and BIP340 verification again (to detect frequency
// drift within the round). Prints one JSON object per round.
#include <crypto/sha256.h>

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

extern "C" {
void secp_setup(int n);
double secp_verify(void);
double secp_tweak_check(void);
}

static double Now()
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

// One SHRINCS hash call: copy the midstate after the 64-byte PK.seed block,
// absorb a 22-byte address and a 16-byte value, finalize (one compression).
static double HashCall(int iters)
{
    unsigned char seed[64] = {1};
    unsigned char in[38] = {2};
    unsigned char out[32];
    CSHA256 mid;
    mid.Write(seed, sizeof(seed));
    const double t0 = Now();
    for (int i = 0; i < iters; ++i) {
        CSHA256 h = mid;
        h.Write(in, sizeof(in)).Finalize(out);
        in[0] = out[0];
    }
    return (Now() - t0) / iters;
}

// Seconds per 64-byte block when hashing a long message.
static double Stream(int blocks)
{
    std::vector<unsigned char> data(64 * blocks, 3);
    unsigned char out[32];
    const double t0 = Now();
    CSHA256().Write(data.data(), data.size()).Finalize(out);
    return (Now() - t0) / blocks;
}

int main(int argc, char** argv)
{
    const int rounds = argc > 1 ? std::stoi(argv[1]) : 9;
    const int sigs = 20000;
    const int iters = 2000000;
    const sha256_implementation::UseImplementation impls[] = {
        sha256_implementation::STANDARD,
        sha256_implementation::USE_SSE4,
        sha256_implementation::USE_SSE4_AND_SHANI,
    };
    secp_setup(sigs);
    for (int r = 0; r < rounds; ++r) {
        std::printf("{\"verify\": %.9e, \"tweak\": %.9e, \"sha256\": {", secp_verify(), secp_tweak_check());
        std::string seen;
        bool first = true;
        for (const auto impl : impls) {
            const std::string name = SHA256AutoDetect(impl);
            if (name == seen) continue;  // implementation not supported
            seen = name;
            std::printf("%s\"%s\": {\"call\": %.9e, \"stream\": %.9e}", first ? "" : ", ",
                        name.c_str(), HashCall(iters), Stream(1 << 16));
            first = false;
        }
        std::printf("}, \"verify_after\": %.9e}\n", secp_verify());
        std::fflush(stdout);
    }
}
"""


def run(cmd, **kwargs):
    print("+", " ".join(cmd), file=sys.stderr)
    return subprocess.run(cmd, check=True, **kwargs)


def microbench(args):
    src = os.path.abspath(args.src)
    secp = os.path.join(src, "src", "secp256k1")
    crypto = os.path.join(src, "src", "crypto")
    machine = platform.machine()
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "secp_bench.c"), "w") as f:
            f.write(SECP_BENCH_C)
        with open(os.path.join(tmp, "bench.cpp"), "w") as f:
            f.write(MAIN_BENCH_CPP)
        # Same settings as Bitcoin Core's bundled build: -O2, ecmult window 15,
        # x86_64 assembly on x86_64.
        secp_flags = ["-O2", "-DECMULT_WINDOW_SIZE=15"]
        if machine == "x86_64":
            secp_flags.append("-DUSE_ASM_X86_64=1")
        run(["gcc", *secp_flags, f"-I{secp}", f"-I{secp}/include", f"-I{secp}/src",
             "-c", "secp_bench.c", "-o", "secp_bench.o"], cwd=tmp)
        cxx = ["g++", "-O2", "-std=c++20", f"-I{src}/src"]
        objects = ["secp_bench.o"]
        if machine == "x86_64":
            defines = ["-DENABLE_SSE41", "-DENABLE_AVX2", "-DENABLE_X86_SHANI"]
            units = [("bench.cpp", []), ("sha256.cpp", []), ("sha256_sse4.cpp", []),
                     ("sha256_sse41.cpp", ["-msse4.1"]), ("sha256_avx2.cpp", ["-mavx", "-mavx2"]),
                     ("sha256_x86_shani.cpp", ["-msse4", "-msha"])]
        elif machine in ("aarch64", "arm64"):
            defines = ["-DENABLE_ARM_SHANI"]
            units = [("bench.cpp", []), ("sha256.cpp", []),
                     ("sha256_arm_shani.cpp", ["-march=armv8-a+crypto"])]
        else:
            defines = ["-DDISABLE_OPTIMIZED_SHA256"]
            units = [("bench.cpp", []), ("sha256.cpp", [])]
        for unit, flags in units:
            path = unit if unit == "bench.cpp" else os.path.join(crypto, unit)
            obj = unit.replace(".cpp", ".o")
            run([*cxx, *defines, *flags, "-c", path, "-o", obj], cwd=tmp)
            objects.append(obj)
        run(["g++", *objects, "-o", "bench"], cwd=tmp)
        cmd = [os.path.join(tmp, "bench"), str(args.rounds)]
        if args.cpu is not None:
            cmd = ["taskset", "-c", str(args.cpu), *cmd]
        else:
            print("WARNING: without --cpu, the OS may move the benchmark between cores,"
                  " which skews kappa on CPUs with performance and efficiency cores", file=sys.stderr)
        out = run(cmd, capture_output=True, text=True).stdout
    rounds = [json.loads(line) for line in out.splitlines()]
    result = dict(machine=machine, cpu=cpu_name(), rounds=rounds)
    with open(args.out, "w") as f:
        json.dump(result, f, indent=1)
    print_microbench(result)


def cpu_name():
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor()


def median(xs):
    xs = sorted(xs)
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def round_verify(r):
    """A round's verification time: the mean of its timings before and after
    the hash calls (files from before verify_after have only the first)."""
    return (r["verify"] + r.get("verify_after", r["verify"])) / 2


def micro_summary(micro):
    """Median times and, per SHA-256 implementation, median ratios to one
    verification. Ratios are taken within a round, so they are robust to
    frequency changes between rounds. Also the relative spread of the hash
    call ratios between rounds and the largest change of the verification
    time within a round (None for files without verify_after)."""
    rounds = micro["rounds"]
    impls = list(rounds[0]["sha256"])

    def ratios(key):
        return {i: [r["sha256"][i][key] / round_verify(r) for r in rounds] for i in impls}

    call = ratios("call")
    return dict(
        verify=median([round_verify(r) for r in rounds]),
        tweak=median([r["tweak"] / round_verify(r) for r in rounds]),
        call={i: median(x) for i, x in call.items()},
        stream={i: median(x) for i, x in ratios("stream").items()},
        spread={i: (max(x) - min(x)) / median(x) for i, x in call.items()},
        drift=(max(abs(r["verify_after"] / r["verify"] - 1) for r in rounds)
               if "verify_after" in rounds[0] else None),
    )


# Warn if KAPPA varies more than this between rounds, or the verification
# time more than this within a round.
SPREAD_WARN = 0.10
DRIFT_WARN = 0.05


def print_microbench(micro):
    m = micro_summary(micro)
    print(f"CPU: {micro['cpu']}")
    print(f"BIP340 verification: {m['verify'] * 1e6:.1f} us")
    print(f"BIP341 tweak check: {m['tweak']:.2f} verifications")
    for impl in m["call"]:
        print(f"SHA-256 '{impl}': hash call {m['call'][impl] * m['verify'] * 1e9:.0f} ns"
              f" (kappa = {1 / m['call'][impl]:.0f} calls per verification,"
              f" {m['spread'][impl]:.1%} spread between rounds),"
              f" streaming {m['stream'][impl] * m['verify'] * 1e9:.0f} ns per block"
              f" (kappa = {1 / m['stream'][impl]:.0f})")
    if m["drift"] is not None:
        print(f"Largest change of the verification time within a round: {m['drift']:.1%}")
        if m["drift"] > DRIFT_WARN:
            print("WARNING: the CPU frequency changed within a round; rerun on an idle, pinned CPU")
    for impl, spread in m["spread"].items():
        if spread > SPREAD_WARN:
            print(f"WARNING: kappa for '{impl}' varies by {spread:.0%} between rounds;"
                  " rerun on an idle, pinned CPU")


# ---------------------------------------------------------------------------
# Stage 2: reconnect mainnet blocks with Bitcoin Core
# ---------------------------------------------------------------------------

class Node:
    """A bitcoind process without peers, so that its tip does not move."""

    def __init__(self, bindir, datadir, chain, dbcache, cpus, memory_max):
        self.prefix = ["taskset", "-c", cpus] if cpus else []
        if memory_max:
            # The cgroup limit includes the page cache of the files bitcoind reads.
            self.prefix = ["systemd-run", "--user", "--scope", "--quiet",
                           f"-pMemoryMax={memory_max}", "-pMemorySwapMax=0", *self.prefix]
        self.bitcoind = os.path.join(bindir, "bitcoind")
        self.cli_path = os.path.join(bindir, "bitcoin-cli")
        self.datadir = os.path.abspath(datadir)
        self.base = [f"-datadir={self.datadir}", f"-chain={chain}"]
        self.dbcache = dbcache
        self.proc = None

    def cli(self, *args):
        cmd = [self.cli_path, *self.base, "-rpcclienttimeout=0", *map(str, args)]
        return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout.strip()

    def start(self, logfile, extra=()):
        cmd = [*self.prefix, self.bitcoind, *self.base, "-server=1", "-connect=0",
               "-listen=0", "-dnsseed=0", "-blocksonly=1", "-persistmempool=0",
               f"-dbcache={self.dbcache}", "-debug=bench", "-logtimemicros=1",
               "-printtoconsole=0", f"-debuglogfile={logfile}", *extra]
        print("+", " ".join(cmd), file=sys.stderr)
        self.proc = subprocess.Popen(cmd)
        while True:
            if self.proc.poll() is not None:
                sys.exit(f"bitcoind exited with code {self.proc.returncode}")
            try:
                self.cli("getblockcount")
                return
            except subprocess.CalledProcessError:
                time.sleep(1)

    def stop(self):
        self.cli("stop")
        self.proc.wait()
        self.proc = None

    def blockchaininfo(self):
        return json.loads(self.cli("getblockchaininfo"))

    def evict_page_cache(self):
        """Drop the datadir's files from the OS page cache, so that bitcoind
        reads blocks and coins from disk (needs no privileges)."""
        for root, _, files in os.walk(self.datadir):
            for name in files:
                try:
                    fd = os.open(os.path.join(root, name), os.O_RDONLY)
                except OSError:
                    continue
                try:
                    os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
                finally:
                    os.close(fd)


BLOCK_STATS = ["height", "ins", "outs", "txs", "total_size", "total_weight",
               "swtxs", "swtotal_size", "swtotal_weight"]


def measure(args):
    node = Node(args.bin, args.datadir, args.chain, args.dbcache, args.cpus, args.memory_max)
    logdir = os.path.abspath(args.logdir)
    os.makedirs(logdir, exist_ok=True)

    node.start(os.path.join(logdir, "setup.log"))
    info = node.blockchaininfo()
    if info["initialblockdownload"]:
        sys.exit("the node is not synced")
    tip = info["blocks"]
    tip_hash = info["bestblockhash"]
    # assumevalid skips scripts only for blocks two weeks of work below the
    # best header; leave a margin above the measured range.
    last = tip - args.margin
    first = last - args.blocks + 1
    if info.get("pruned") and info["pruneheight"] >= first - 1:
        sys.exit(f"block {first - 1} is pruned (prune height {info['pruneheight']})")
    first_hash = node.cli("getblockhash", first)
    stats = [json.loads(node.cli("getblockstats", h, json.dumps(BLOCK_STATS)))
             for h in range(first, last + 1)]
    node.stop()

    runs = [("warmup", True, 16), ("noscript", True, 16)]
    runs += [(f"par{p}", False, p) for p in args.par]
    results = dict(tip=tip, first=first, last=last, dbcache=args.dbcache, cpus=args.cpus,
                   prevoutfetchthreads=args.prevoutfetchthreads,
                   memory_max=args.memory_max, evict=args.evict,
                   stats=stats, runs={})
    for name, noscript, par in runs:
        extra = [f"-par={par}", f"-assumevalid={tip_hash if noscript else 0}",
                 f"-prevoutfetchthreads={args.prevoutfetchthreads}"]
        # Disconnect the range, then restart so that the signature cache and
        # the coins cache are empty, and reconnect it.
        node.start(os.path.join(logdir, f"{name}-disconnect.log"), extra)
        node.cli("invalidateblock", first_hash)
        node.stop()
        if args.evict:
            node.evict_page_cache()
        log = os.path.join(logdir, f"{name}.log")
        node.start(log, extra)
        t0 = time.time()
        node.cli("reconsiderblock", first_hash)
        elapsed = time.time() - t0
        if node.blockchaininfo()["bestblockhash"] != tip_hash:
            sys.exit("reconsiderblock did not return to the tip")
        node.stop()
        blocks = parse_bench_log(log)
        skipped = script_check_ranges(log)
        results["runs"][name] = dict(par=par, noscript=noscript, elapsed=elapsed,
                                     skipped=skipped,
                                     blocks={h: blocks[h] for h in range(first, last + 1)})
        print(f"{name}: {elapsed:.0f} s", file=sys.stderr)
        with open(args.out, "w") as f:
            json.dump(results, f)


BENCH_LINES = {
    "load": re.compile(r"- Load block from disk: ([\d.]+)ms"),
    "sanity": re.compile(r"- Sanity checks: ([\d.]+)ms"),
    "loop": re.compile(r"- Connect (\d+) transactions: ([\d.]+)ms"),
    "verify": re.compile(r"- Verify (\d+) txins: ([\d.]+)ms"),
    "undo": re.compile(r"- Write undo data: ([\d.]+)ms"),
    "flush": re.compile(r"  - Flush: ([\d.]+)ms"),
    "chainstate": re.compile(r"- Writing chainstate: ([\d.]+)ms"),
    "total": re.compile(r"\] - Connect block: ([\d.]+)ms"),
}
UPDATE_TIP = re.compile(r"UpdateTip: new best=\w+ height=(\d+)")


def parse_bench_log(path):
    """Per-block timings (ms) from a -debug=bench log, keyed by height."""
    blocks, cur, height = {}, {}, None
    with open(path) as f:
        for line in f:
            if m := UPDATE_TIP.search(line):
                height = int(m.group(1))
                continue
            for key, regex in BENCH_LINES.items():
                if m := regex.search(line):
                    cur[key] = float(m.groups()[-1])
                    if key == "total":
                        if height is not None:
                            blocks[height] = cur
                        cur, height = {}, None
                    break
    return blocks


SCRIPT_CHECKS = re.compile(r"(Enabling|Disabling) script verification at block #(\d+)")


def script_check_ranges(path):
    """Heights at which Core logged that it enabled or disabled script checks."""
    with open(path) as f:
        return [(m.group(1), int(m.group(2))) for line in f if (m := SCRIPT_CHECKS.search(line))]


def check_script_checks(run, first, last):
    """Whether script checks were off (noscript) or on for the whole range."""
    state = None
    for action, height in run["skipped"]:
        if height <= first:
            state = action
        elif height <= last:
            return False
    return state == ("Disabling" if run["noscript"] else "Enabling")


# ---------------------------------------------------------------------------
# Stage 3: constants
# ---------------------------------------------------------------------------

def impl_name(impl):
    """Short name of a SHA-256 implementation reported by SHA256AutoDetect."""
    return "SHA-NI" if "shani" in impl else "SSE4" if "sse4" in impl else "portable C"


def wall(other, loop, script, prep, p):
    """Block time with script checks on p threads (shrincs_block_cost.py)."""
    return other + prep + max(0.0, (script - prep) - (p - 1) * (loop + prep)) / p


def constants(args):
    with open(args.micro) as f:
        micro = json.load(f)
    with open(args.blocks) as f:
        data = json.load(f)
    m = micro_summary(micro)
    t_verify = m["verify"] * 1e3  # ms
    # Bitcoin Core uses the best implementation the CPU supports, the last one.
    node_impl = list(m["call"])[-1]
    t_hash = m["call"][node_impl] * t_verify  # ms per compression

    first, last = data["first"], data["last"]
    runs = data["runs"]
    if args.logdir:
        for name, r in runs.items():
            blocks = parse_bench_log(os.path.join(args.logdir, f"{name}.log"))
            r["blocks"] = {str(h): blocks[h] for h in range(first, last + 1)}
    if any("sanity" not in b for b in runs["noscript"]["blocks"].values()):
        sys.exit("the blocks file lacks per-stage timings; re-parse its logs with --logdir")
    for name, r in runs.items():
        if not check_script_checks(r, first, last):
            sys.exit(f"run {name}: script checks were not {'off' if r['noscript'] else 'on'}"
                     " for the whole range")
    heights = [str(h) for h in range(first, last + 1)]
    n = len(heights)
    stats = {str(s["height"]): s for s in data["stats"]}
    ns = runs["noscript"]["blocks"]
    full1 = runs["par1"]["blocks"]
    par_min = min(r["par"] for r in runs.values() if not r["noscript"] and r["par"] > 1)
    queued = runs[f"par{par_min}"]["blocks"]

    def total(key):
        return sum(stats[h][key] for h in heights)

    ins, outs, txs = total("ins"), total("outs"), total("txs") - n
    # getblockstats counts the coinbase's outputs but not its input.
    ins_per_tx, outs_per_tx = ins / txs, outs / (txs + n)

    def hashing(h):
        """Bitcoin Core's non-script SHA-256 work in block h, compressions."""
        s = stats[h]
        stripped = (s["total_weight"] - s["total_size"]) / 3
        # Reconnecting a block recomputes only the transaction Merkle tree.
        return model.block_hashing(s["txs"], stripped, s["total_size"], s["swtxs"], s["swtotal_size"],
                                   merkle_trees=1)

    def precompute(h):
        """Approximate BIP143/BIP341 precomputation of block h, compressions."""
        s = stats[h]
        k = s["txs"] - 1
        return model.precompute_hashing(s["ins"] / k, s["outs"] / k) * k if k else 0.0

    print_microbench(micro)
    print(f"Bitcoin Core's SHA-256: {node_impl}")
    print(f"\nBlocks {first}-{last} ({n} blocks, tip {data['tip']}, dbcache {data['dbcache']} MiB,"
          f" prevoutfetchthreads {data['prevoutfetchthreads']}, CPUs {data.get('cpus') or 'all'},"
          f" memory {data.get('memory_max') or 'unlimited'},"
          f" page cache {'evicted' if data.get('evict') else 'kept'})")
    print(f"  per block: {total('total_weight') / n:,.0f} WU, {ins / n:,.0f} inputs,"
          f" {outs / n:,.0f} outputs, {txs / n:,.0f} transactions")
    t_ns = sum(ns[h]["total"] for h in heights)
    t_1 = sum(full1[h]["total"] for h in heights)
    hash_ms = sum(hashing(h) for h in heights) * t_hash
    print(f"  time per block with one script thread (-par=1): {t_1 / n:.1f} ms = {t_1 / n / t_verify:,.0f} V")
    print(f"  script checks' share of it: {(t_1 - t_ns) / t_1:.0%}"
          f" ({(t_1 - t_ns) / ins / t_verify:.2f} V per input)")
    print(f"  non-script time per input: {t_ns / ins / t_verify:.2f} V, of which SHA-256"
          f" {hash_ms / ins / t_verify:.2f} V")

    # Attribute the non-script time: loading and checking the block (minus
    # its SHA-256 work) per byte, the rest per input. A regression on inputs,
    # outputs, transactions and bytes cannot separate them: the time hardly
    # varies with the block's shape, and rare long flushes dominate its variance.
    def mean_ms(key):
        return sum(ns[h].get(key, 0.0) for h in heights) / n

    print("  non-script time per block (ms): " + ", ".join(
        f"{k} {mean_ms(k):.2f}" for k in ("load", "sanity", "loop", "undo", "flush", "chainstate", "total")))
    if mean_ms("undo") < 0.01:
        print("  NOTE: no undo data was written (the blocks had been connected before) and"
              " the coins database may have been in the OS page cache: a lower bound")
    per_byte = (sum(ns[h]["load"] + ns[h]["sanity"] for h in heights)
                - hash_ms) / total("total_size") / t_verify
    per_input = sum(ns[h]["total"] - ns[h]["load"] - ns[h]["sanity"] for h in heights) / ins / t_verify
    loop_input = sum(ns[h]["loop"] for h in heights) / ins / t_verify
    # Main-thread script preparation: the loop time of the smallest parallel
    # run minus that without scripts (more threads would add SMT contention).
    prep_ms = [max(0.0, queued[h]["loop"] - ns[h]["loop"]) for h in heights]
    prep = (sum(prep_ms) - sum(precompute(h) for h in heights) * t_hash) / ins / t_verify
    print(f"  main-thread script preparation: {sum(prep_ms) / ins / t_verify:.3f} V per input,"
          f" {prep:.3f} V without SHA-256 (approximate)")

    print("\n  Parallel model on the measured blocks (ms per block):")
    print("  -par  measured  model")
    for r in runs.values():
        if r["noscript"]:
            continue
        measured = sum(r["blocks"][h]["total"] for h in heights) / n
        predicted = sum(wall(ns[h]["total"], ns[h]["loop"], full1[h]["total"] - ns[h]["total"],
                             p_ms, r["par"]) for h, p_ms in zip(heights, prep_ms)) / n
        print(f"  {r['par']:4}  {measured:8.1f}  {predicted:5.1f}")

    kappa = ", ".join(f'"{impl_name(impl)}": {1 / c:.0f}' for impl, c in m["call"].items())
    print(f"""
# ---- constants for shrincs_block_cost.py ({micro['cpu']}, blocks {first}-{last}) ----
KAPPA = {{{kappa}}}
TWEAK_CHECK = {m['tweak']:.2f}
INPUTS_PER_TX = {ins_per_tx:.2f}
OUTPUTS_PER_TX = {outs_per_tx:.2f}
PER_BYTE = {per_byte:.3g}
PER_INPUT = {per_input:.3g}
LOOP_PER_INPUT = {loop_input:.3g}
PREP_PER_INPUT = {max(prep, 0.0):.3g}""")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="stage", required=True)

    p = sub.add_parser("microbench", help="time verification and hashing")
    p.add_argument("--src", required=True, help="Bitcoin Core source tree")
    p.add_argument("--out", default="micro.json")
    p.add_argument("--rounds", type=int, default=9)
    p.add_argument("--cpu", type=int, help="pin to this CPU")
    p.set_defaults(func=microbench)

    p = sub.add_parser("measure", help="reconnect mainnet blocks with Bitcoin Core")
    p.add_argument("--bin", required=True, help="directory with bitcoind and bitcoin-cli")
    p.add_argument("--datadir", required=True)
    p.add_argument("--chain", default="main", help="for testing the script on regtest")
    p.add_argument("--out", default="blocks.json")
    p.add_argument("--logdir", default="logs")
    p.add_argument("--blocks", type=int, default=1000, help="number of blocks to measure")
    p.add_argument("--margin", type=int, default=2200,
                   help="blocks between the measured range and the tip (more than two weeks)")
    p.add_argument("--par", type=lambda s: [int(x) for x in s.split(",")], default=[1, 2, 4, 8, 16])
    p.add_argument("--dbcache", type=int, default=1024, help="MiB (Bitcoin Core's default)")
    p.add_argument("--prevoutfetchthreads", type=int, default=8, help="Bitcoin Core's default")
    p.add_argument("--cpus", help="run bitcoind on these CPUs (taskset list), e.g. those of"
                   " the CPU the microbenchmark ran on")
    p.add_argument("--memory-max", help="limit bitcoind's memory, including the page cache of"
                   " its files, with a systemd user scope (e.g. 4G)")
    p.add_argument("--evict", action="store_true",
                   help="evict the datadir's files from the page cache before each reconnect")
    p.set_defaults(func=measure)

    p = sub.add_parser("constants", help="derive the constants of shrincs_block_cost.py")
    p.add_argument("micro")
    p.add_argument("blocks")
    p.add_argument("--logdir", help="re-parse the bench logs of `measure` from here")
    p.set_defaults(func=constants)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

