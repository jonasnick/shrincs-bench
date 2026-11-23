# shrincs-bench

This repository measures the *verification density* of SHRINCS signatures: the time it takes to verify a spend, per weight unit of the spend, relative to that of a BIP340 Schnorr key-path spend.
A spend whose verification density is no higher than a Schnorr key-path spend's makes a full block take no longer to validate than a full block of Schnorr spends.
Equivalently, a SHRINCS spend may take as long to verify as the Schnorr key-path spends whose weight it displaces: its weight divided by 475 WU, in BIP340 verifications.

Nothing here is production code.

## What it does

**It measures how much of block validation is signature verification.**
A model of the validation time of full blocks (`model/shrincs_block_cost.py`) is calibrated with an unmodified Bitcoin Core on reconnected mainnet blocks (`model/measure_constants.py`, whose docstring describes how to run it).
It also gives the verification density limit as a limit on expected SHA-256 compressions per signature byte, and the break-even κ of each parameter set (κ: SHA-256 compressions per BIP340 verification).

**It times a real SHRINCS verifier against BIP340 verification.**
`verifier/shrincs_verify.cpp` follows `shrincs_verify` of the BIP's reference implementation (`impl/shrincs.py` in [SHRINCS/shrincs-bip](https://github.com/SHRINCS/shrincs-bip), as of commit `ad93be730f0a774631b4e8aac9905f0071b1276b`, the last to change it; the vectors were generated and checked at `8a0c3050b3801d44527b6bdca514f2ac86c10fc1`), with the parameter set chosen at compile time (`-DSL_WOTS_BITS=...`, see the file header).
It hashes either one at a time with Bitcoin Core's SHA-256, or the chains of each WOTS signature and the FORS trees 4 or 8 at a time in plain C ("lanes": every SHA-256 variable is an array over the lanes, and the compiler vectorizes the loops over them).
`shrincs_verify test FILE...` checks that every signature verifies in every variant and that tampered versions are rejected, and `shrincs_verify bench FILE` times the variants against BIP340 verification, including x-only public-key parsing as Bitcoin Core does.
`verifier/build.sh` builds it against a Bitcoin Core source tree, and `verifier/run_bench.sh` builds, tests and benchmarks it for every parameter set and several compiler configurations.
The signatures come from the reference implementation: `verifier/gen_vectors.py` regenerates the BIP's official vectors (checked against the fingerprint committed in the BIP repository) and benchmark signatures, and `verifier/gen_param_vectors.py` signs for other parameter sets with a copy of the reference implementation whose constants are changed.
`verifier/vectors/` holds their output.

The raw results are in `results/`, by machine: the verifier benchmark and the BIP340 and SHA-256 microbenchmarks on an Intel i7-6700 (Skylake, no SHA-NI), and the microbenchmarks on both core types of an Intel i7-1280P.

## Running

Building the verifier needs a Bitcoin Core source tree (v32.1 was used), for Bitcoin Core's SHA-256 implementations and libsecp256k1, as well as gcc, g++ and Python 3; `run_bench.sh` also needs clang.
Build the verifier, check it against the official and benchmark signatures, and time it against BIP340 verification:

```
git clone --depth 1 --branch v32.1 https://github.com/bitcoin/bitcoin.git src-32.1
verifier/build.sh src-32.1 shrincs_verify
./shrincs_verify test verifier/vectors/official.csv verifier/vectors/bench.csv
./shrincs_verify bench verifier/vectors/bench.csv
```

To build, test and time every parameter set in `verifier/vectors/` with every compiler configuration, pinned to CPU `CPU`, with the results in `out/results.jsonl`:

```
verifier/run_bench.sh src-32.1 verifier/vectors out CPU
```

The model's constants are measured with `model/measure_constants.py`, whose docstring gives the steps.
Run all timings on an otherwise idle machine, pinned to one core (`taskset -c CPU`, or the `--cpu` option of `measure_constants.py microbench`).
