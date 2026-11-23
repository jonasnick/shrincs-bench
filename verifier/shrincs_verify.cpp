// A SHRINCS verifier following shrincs_verify in the BIP's reference
// implementation (impl/shrincs.py), for benchmarking. Not for production use.
//
// The parameter set is fixed at compile time (defaults: the BIP's):
//   -DSL_WOTS_BITS=4 -DSL_LAYERS=5 -DSL_XMSS_HEIGHT=9 -DSL_FORS_HEIGHT=13
//   -DSL_FORS_COUNT=10 -DSF_WOTS_BITS=4
// The tweakable hash SHA256(pk_seed || 0^48 || ADRS || M)[:16] starts from
// the midstate after the first block, computed once per verification.
// Verify<0> hashes one at a time with Bitcoin Core's CSHA256 (whichever
// implementation SHA256AutoDetect selected); Verify<N> hashes the chains of
// each WOTS signature and the FORS trees in N lanes of plain C (a lane that
// finishes its chain takes the next chain of the same signature), and
// everything else one at a time with CSHA256.
//
//   shrincs_verify test FILE...     check vectors (pubkey,message,ctx,signature
//                                   in hex), every one must verify in every
//                                   variant, and tampered ones must not
//   shrincs_verify bench FILE [ROUNDS]  time the variants against BIP340
#include <crypto/sha256.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
void secp_setup(int n);
double secp_verify(void);
}

#ifndef SL_WOTS_BITS
#define SL_WOTS_BITS 4
#endif
#ifndef SL_LAYERS
#define SL_LAYERS 5
#endif
#ifndef SL_XMSS_HEIGHT
#define SL_XMSS_HEIGHT 9
#endif
#ifndef SL_FORS_HEIGHT
#define SL_FORS_HEIGHT 13
#endif
#ifndef SL_FORS_COUNT
#define SL_FORS_COUNT 10
#endif
#ifndef SF_WOTS_BITS
#define SF_WOTS_BITS 4
#endif

namespace {

constexpr int ceildiv(int a, int b) { return (a + b - 1) / b; }
constexpr int bitlen(int x) { return x ? 1 + bitlen(x >> 1) : 0; }

// Parameters and derived constants, as in impl/shrincs.py.
constexpr int TW_BITS = SL_WOTS_BITS, TW_W = 1 << TW_BITS;
constexpr int TW_LEN1 = ceildiv(128, TW_BITS);
constexpr int TW_CSUM_MAX = TW_LEN1 * (TW_W - 1);
constexpr int TW_LEN2 = ceildiv(bitlen(TW_CSUM_MAX), TW_BITS);
constexpr int TW_LEN = TW_LEN1 + TW_LEN2;
constexpr int C_BITS = SF_WOTS_BITS, C_W = 1 << C_BITS;
constexpr int C_LEN = ceildiv(128, C_BITS);
constexpr int C_SUM = ceildiv(C_LEN * (C_W - 1), 2);
constexpr int D = SL_LAYERS, HP = SL_XMSS_HEIGHT, A = SL_FORS_HEIGHT, K = SL_FORS_COUNT;
constexpr int FXMSS_HEIGHT = 255;
constexpr int XMSS_SIG = TW_LEN * 16 + 16 * HP;
constexpr int FORS_SIG = 16 * K * (A + 1);
constexpr int SPHX_SIG = 16 + FORS_SIG + D * XMSS_SIG;
constexpr int SL_SIG = 1 + SPHX_SIG;
constexpr int FORS_DIGEST = ceildiv(K * A, 8);
constexpr int TREE_BITS = HP * (D - 1);
constexpr int TREE_INDEX_BYTES = ceildiv(TREE_BITS, 8);
constexpr int LEAF_INDEX_BYTES = ceildiv(HP, 8);
constexpr int SF_SIG_MIN = 1 + 16 + 1 + 2 + C_LEN * 16 + 16;
constexpr int SF_SIG_MAX = 1 + 16 + 8 + 2 + C_LEN * 16 + 16 * FXMSS_HEIGHT;
// The supported parameter domain: 32-bit index arithmetic needs tree heights
// below 32 and FORS tree indexes (K trees of 2^A leaves) within 32 bits.
static_assert(TW_BITS >= 1 && TW_BITS <= 8 && C_BITS >= 1 && C_BITS <= 8, "chain bits out of range");
static_assert(D >= 1 && K >= 1 && HP >= 1 && HP < 32 && A >= 1 && A < 32, "tree heights out of range");
static_assert((uint64_t{K} << A) <= (uint64_t{1} << 32), "FORS tree indexes must fit in 32 bits");
static_assert(FORS_DIGEST + TREE_INDEX_BYTES + LEAF_INDEX_BYTES <= 32, "digest too short");
static_assert(TREE_BITS <= 64, "tree index too long");
// The BIP requires this; -DALLOW_ANY_SIZES drops it, to benchmark parameter
// sets whose stateless signatures are shorter than the longest stateful ones.
#ifndef ALLOW_ANY_SIZES
static_assert(SF_SIG_MAX < SL_SIG, "stateful signatures must be shorter than stateless ones");
#endif

// ADRS types.
enum : uint8_t {
    SL_WOTS_TW_HASH = 0, SL_WOTS_TW_PK = 1, SL_XMSS_TREE = 2, SL_FORS_TREE = 3, SL_FORS_ROOTS = 4,
    SF_WOTS_C_HASH = 16, SF_WOTS_C_PK = 17, SF_FXMSS_TREE = 18, SF_WOTS_C_GRIND = 22,
};

void PutBE32(uint8_t* p, uint32_t x) { p[0] = x >> 24; p[1] = x >> 16; p[2] = x >> 8; p[3] = x; }
uint32_t GetBE32(const uint8_t* p) { return uint32_t{p[0]} << 24 | uint32_t{p[1]} << 16 | uint32_t{p[2]} << 8 | p[3]; }
uint64_t GetBE(const uint8_t* p, int n)
{
    uint64_t x = 0;
    for (int i = 0; i < n; ++i) x = x << 8 | p[i];
    return x;
}

// Address::pack: height(1) || index(8) || type(1) || word1 || word2 || word3.
struct Adrs {
    uint8_t b[22];
    Adrs(uint8_t height, uint64_t index, uint8_t type, uint32_t w1 = 0, uint32_t w2 = 0, uint32_t w3 = 0)
    {
        b[0] = height;
        for (int i = 0; i < 8; ++i) b[1 + i] = index >> (56 - 8 * i);
        b[9] = type;
        PutBE32(b + 10, w1);
        PutBE32(b + 14, w2);
        PutBE32(b + 18, w3);
    }
};

// base_2b of impl/shrincs.py (missing trailing bits are zero).
template <size_t OUT>
void Base2b(const uint8_t* x, size_t len, int b, uint32_t (&out)[OUT])
{
    uint64_t acc = 0;
    int bits = 0;
    size_t j = 0;
    for (size_t i = 0; i < OUT; ++i) {
        while (bits < b) {
            acc = acc << 8 | (j < len ? x[j] : 0);
            ++j;
            bits += 8;
        }
        bits -= b;
        out[i] = acc >> bits;
        acc &= (uint64_t{1} << bits) - 1;
    }
}

// The tweakable hash, one at a time, from the pk_seed midstate.
struct Thash {
    CSHA256 mid;
    uint32_t midw[8];  // the same midstate as words, for the lanes
    void operator()(const Adrs& adrs, const uint8_t* m, size_t len, uint8_t out[16]) const
    {
        uint8_t h[32];
        CSHA256 s = mid;
        s.Write(adrs.b, 22).Write(m, len).Finalize(h);
        std::memcpy(out, h, 16);
    }
};

// ---------------------------------------------------------------------------
// Lanes: SHA-256 compressions of N independent tweakable hashes, plain C.
// ---------------------------------------------------------------------------

const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
const uint32_t IV[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

inline uint32_t Ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

template <int N>
void Compress(uint32_t state[8][N], const uint32_t block[16][N])
{
    uint32_t w[64][N];
    for (int t = 0; t < 16; ++t)
        for (int l = 0; l < N; ++l) w[t][l] = block[t][l];
    for (int t = 16; t < 64; ++t)
        for (int l = 0; l < N; ++l) {
            const uint32_t s0 = Ror(w[t - 15][l], 7) ^ Ror(w[t - 15][l], 18) ^ (w[t - 15][l] >> 3);
            const uint32_t s1 = Ror(w[t - 2][l], 17) ^ Ror(w[t - 2][l], 19) ^ (w[t - 2][l] >> 10);
            w[t][l] = w[t - 16][l] + s0 + w[t - 7][l] + s1;
        }
    uint32_t v[8][N];
    for (int i = 0; i < 8; ++i)
        for (int l = 0; l < N; ++l) v[i][l] = state[i][l];
    for (int t = 0; t < 64; ++t)
        for (int l = 0; l < N; ++l) {
            const uint32_t a = v[0][l], b = v[1][l], c = v[2][l], d = v[3][l];
            const uint32_t e = v[4][l], f = v[5][l], g = v[6][l], h = v[7][l];
            const uint32_t t1 = h + (Ror(e, 6) ^ Ror(e, 11) ^ Ror(e, 25)) + ((e & f) ^ (~e & g)) + K256[t] + w[t][l];
            const uint32_t t2 = (Ror(a, 2) ^ Ror(a, 13) ^ Ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            v[7][l] = g; v[6][l] = f; v[5][l] = e; v[4][l] = d + t1;
            v[3][l] = c; v[2][l] = b; v[1][l] = a; v[0][l] = t1 + t2;
        }
    for (int i = 0; i < 8; ++i)
        for (int l = 0; l < N; ++l) state[i][l] += v[i][l];
}

// The 22-byte address as message words: words 0-2 are the same in every lane
// (height, index, type and the high half of word1); words 3-4 and the high
// half of word 5 hold the rest of word1 and the per-lane word2 and word3.
template <int N>
struct LaneAdrs {
    uint32_t fixed[3];
    uint32_t w1lo;
    uint32_t w3[N], w4[N], a5[N];
    explicit LaneAdrs(const Adrs& a)
    {
        for (int i = 0; i < 3; ++i) fixed[i] = GetBE32(a.b + 4 * i);
        w1lo = uint32_t{a.b[12]} << 24 | uint32_t{a.b[13]} << 16;
    }
    void Set(int l, uint32_t word2, uint32_t word3)
    {
        w3[l] = w1lo | word2 >> 16;
        w4[l] = word2 << 16 | word3 >> 16;
        a5[l] = word3 << 16;
    }
};

// N tweakable hashes of one 16-byte value (F) or two (H). Values are four
// big-endian words; the message starts at byte 22 of the block after the midstate.
template <int N, int Words>
void LaneHash(const uint32_t midw[8], const LaneAdrs<N>& ad, const uint32_t (*val)[N], uint32_t out[4][N])
{
    uint32_t blk[16][N], st[8][N];
    for (int i = 0; i < 8; ++i)
        for (int l = 0; l < N; ++l) st[i][l] = midw[i];
    for (int l = 0; l < N; ++l) {
        blk[0][l] = ad.fixed[0]; blk[1][l] = ad.fixed[1]; blk[2][l] = ad.fixed[2];
        blk[3][l] = ad.w3[l]; blk[4][l] = ad.w4[l];
        blk[5][l] = ad.a5[l] | val[0][l] >> 16;
        for (int j = 1; j < Words; ++j) blk[5 + j][l] = val[j - 1][l] << 16 | val[j][l] >> 16;
        blk[5 + Words][l] = val[Words - 1][l] << 16 | 0x8000;
        for (int j = 6 + Words; j < 15; ++j) blk[j][l] = 0;
        blk[15][l] = (64 + 22 + 4 * Words) * 8;
    }
    Compress<N>(st, blk);
    for (int i = 0; i < 4; ++i)
        for (int l = 0; l < N; ++l) out[i][l] = st[i][l];
}

void ToWords(const uint8_t* b, uint32_t w[4]) { for (int i = 0; i < 4; ++i) w[i] = GetBE32(b + 4 * i); }
void ToBytes(const uint32_t w[4], uint8_t* b) { for (int i = 0; i < 4; ++i) PutBE32(b + 4 * i, w[i]); }

// ---------------------------------------------------------------------------
// WOTS chains, FORS, Merkle paths
// ---------------------------------------------------------------------------

// Completes the chains of one WOTS signature: chain i goes from digit[i] to
// w - 1 with ADRS (height, index, type, word1, word2 = i, word3 = step).
template <int Lanes, int LEN>
void Chains(const Thash& th, uint8_t height, uint64_t index, uint8_t type, uint32_t word1, int w,
            const uint32_t (&digits)[LEN], const uint8_t* sig, uint8_t* tips)
{
    if constexpr (Lanes == 0) {
        for (int i = 0; i < LEN; ++i) {
            uint8_t node[16];
            std::memcpy(node, sig + 16 * i, 16);
            for (int j = digits[i]; j < w - 1; ++j) th(Adrs(height, index, type, word1, i, j), node, 16, node);
            std::memcpy(tips + 16 * i, node, 16);
        }
    } else {
        constexpr int N = Lanes;
        int order[LEN], count = 0;
        for (int i = 0; i < LEN; ++i) {
            if (int(digits[i]) == w - 1) std::memcpy(tips + 16 * i, sig + 16 * i, 16);
            else order[count++] = i;
        }
        std::stable_sort(order, order + count, [&](int x, int y) { return digits[x] < digits[y]; });  // longest first
        LaneAdrs<N> ad(Adrs(height, index, type, word1));
        uint32_t v[4][N] = {}, left[N] = {}, cur[N] = {}, step[N] = {};
        constexpr uint32_t idle = UINT32_MAX;
        int next = 0;
        auto load = [&](int l) {
            if (next == count) {
                // An idle lane keeps hashing a fixed input; its outputs are discarded.
                left[l] = idle;
                cur[l] = step[l] = 0;
                ad.Set(l, 0, 0);
                return;
            }
            const int i = order[next++];
            cur[l] = i;
            step[l] = digits[i];
            left[l] = w - 1 - digits[i];
            ad.Set(l, i, step[l]);
            uint32_t x[4];
            ToWords(sig + 16 * i, x);
            for (int k = 0; k < 4; ++k) v[k][l] = x[k];
        };
        for (int l = 0; l < N; ++l) load(l);
        while (true) {
            const uint32_t r = *std::min_element(left, left + N);
            if (r == idle) break;
            for (uint32_t s = 0; s < r; ++s) {
                LaneHash<N, 4>(th.midw, ad, v, v);
                for (int l = 0; l < N; ++l) {
                    if (left[l] == idle) continue;
                    ++step[l];
                    ad.Set(l, cur[l], step[l]);
                }
            }
            for (int l = 0; l < N; ++l) {
                if (left[l] == idle) continue;
                left[l] -= r;
                if (left[l] == 0) {
                    uint32_t x[4];
                    for (int k = 0; k < 4; ++k) x[k] = v[k][l];
                    ToBytes(x, tips + 16 * cur[l]);
                    load(l);
                }
            }
        }
    }
}

// An authentication path: node at position idx, `levels` siblings. The
// parent ADRS of level k is given by make(k).
template <class MakeAdrs>
void MerklePath(const Thash& th, uint8_t node[16], uint64_t idx, const uint8_t* auth, int levels, MakeAdrs make)
{
    for (int k = 0; k < levels; ++k) {
        uint8_t m[32];
        const bool right = k < 64 && ((idx >> k) & 1);
        if (right) {
            std::memcpy(m, auth + 16 * k, 16);
            std::memcpy(m + 16, node, 16);
        } else {
            std::memcpy(m, node, 16);
            std::memcpy(m + 16, auth + 16 * k, 16);
        }
        th(make(k), m, 32, node);
    }
}

// fors_pubkey_from_sig.
template <int Lanes>
void Fors(const Thash& th, const uint8_t* sig, const uint8_t* digest, uint64_t tree, uint32_t keypair, uint8_t out[16])
{
    uint32_t idx[K];
    Base2b(digest, FORS_DIGEST, A, idx);
    uint8_t roots[16 * K];
    if constexpr (Lanes == 0) {
        for (int i = 0; i < K; ++i) {
            const uint8_t* s = sig + i * 16 * (A + 1);
            const uint32_t ti = uint32_t(i) << A | idx[i];
            uint8_t node[16];
            th(Adrs(0, tree, SL_FORS_TREE, keypair, 0, ti), s, 16, node);
            MerklePath(th, node, ti, s + 16, A, [&](int j) {
                return Adrs(0, tree, SL_FORS_TREE, keypair, j + 1, ti >> (j + 1));
            });
            std::memcpy(roots + 16 * i, node, 16);
        }
    } else {
        constexpr int N = Lanes;
        LaneAdrs<N> ad(Adrs(0, tree, SL_FORS_TREE, keypair));
        for (int g = 0; g < K; g += N) {
            uint32_t node[4][N], pair[8][N], ti[N];
            for (int l = 0; l < N; ++l) {
                const int i = std::min(g + l, K - 1);  // idle lanes repeat the last tree
                ti[l] = uint32_t(i) << A | idx[i];
                ad.Set(l, 0, ti[l]);
                uint32_t x[4];
                ToWords(sig + i * 16 * (A + 1), x);
                for (int k = 0; k < 4; ++k) node[k][l] = x[k];
            }
            LaneHash<N, 4>(th.midw, ad, node, node);
            for (int j = 0; j < A; ++j) {
                for (int l = 0; l < N; ++l) {
                    const int i = std::min(g + l, K - 1);
                    uint32_t sib[4];
                    ToWords(sig + i * 16 * (A + 1) + 16 * (j + 1), sib);
                    const bool right = (ti[l] >> j) & 1;
                    for (int k = 0; k < 4; ++k) {
                        pair[k][l] = right ? sib[k] : node[k][l];
                        pair[4 + k][l] = right ? node[k][l] : sib[k];
                    }
                    ad.Set(l, j + 1, ti[l] >> (j + 1));
                }
                LaneHash<N, 8>(th.midw, ad, pair, node);
            }
            for (int l = 0; l < N && g + l < K; ++l) {
                uint32_t x[4];
                for (int k = 0; k < 4; ++k) x[k] = node[k][l];
                ToBytes(x, roots + 16 * (g + l));
            }
        }
    }
    th(Adrs(0, tree, SL_FORS_ROOTS, keypair), roots, sizeof(roots), out);
}

void Sha256(const std::vector<const std::vector<uint8_t>*>& parts, uint8_t out[32])
{
    CSHA256 h;
    for (const auto* p : parts) h.Write(p->data(), p->size());
    h.Finalize(out);
}

std::vector<uint8_t> Bytes(const uint8_t* p, size_t n) { return std::vector<uint8_t>(p, p + n); }

// The pk_seed midstate; as words too only if the lanes need them.
Thash MakeThash(const uint8_t pk_seed[16], bool words)
{
    Thash th;
    uint8_t block[64] = {};
    std::memcpy(block, pk_seed, 16);
    th.mid.Write(block, 64);
    if (!words) return th;
    uint32_t st[8][1], blk[16][1];
    for (int i = 0; i < 8; ++i) st[i][0] = IV[i];
    for (int i = 0; i < 16; ++i) blk[i][0] = GetBE32(block + 4 * i);
    Compress<1>(st, blk);
    for (int i = 0; i < 8; ++i) th.midw[i] = st[i][0];
    return th;
}

// shrincs_verify.
template <int Lanes>
bool Verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& sig,
            const std::vector<uint8_t>& ctx, const std::vector<uint8_t>& pk)
{
    if (pk.size() != 48 || sig.empty() || ctx.size() > 255) return false;
    const std::vector<uint8_t> pk_seed = Bytes(pk.data(), 16), sl_root = Bytes(pk.data() + 16, 16),
                               sf_root = Bytes(pk.data() + 32, 16);
    const Thash th = MakeThash(pk_seed.data(), Lanes != 0);
    const int indicator = sig[0];

    if (indicator == FXMSS_HEIGHT) {
        // slh_dsa_verify(sf_root + message, signature[1:], ctx, pk_seed, sl_root).
        if (sig.size() != size_t(SL_SIG)) return false;
        std::vector<uint8_t> cmsg = {0, uint8_t(ctx.size())};
        cmsg.insert(cmsg.end(), ctx.begin(), ctx.end());
        cmsg.insert(cmsg.end(), sf_root.begin(), sf_root.end());
        cmsg.insert(cmsg.end(), message.begin(), message.end());
        const uint8_t* s = sig.data() + 1;
        const std::vector<uint8_t> R = Bytes(s, 16), zeros4(4, 0);
        uint8_t inner[32], digest[32];
        Sha256({&R, &pk_seed, &sl_root, &cmsg}, inner);
        const std::vector<uint8_t> innerv = Bytes(inner, 32);
        Sha256({&R, &pk_seed, &innerv, &zeros4}, digest);
        uint64_t tree = GetBE(digest + FORS_DIGEST, TREE_INDEX_BYTES);
        if (TREE_BITS < 64) tree &= (uint64_t{1} << TREE_BITS) - 1;
        uint32_t leaf = GetBE(digest + FORS_DIGEST + TREE_INDEX_BYTES, LEAF_INDEX_BYTES) & ((1u << HP) - 1);

        uint8_t node[16];
        Fors<Lanes>(th, s + 16, digest, tree, leaf, node);
        const uint8_t* ht = s + 16 + FORS_SIG;
        for (int layer = 0; layer < D; ++layer) {
            const uint8_t* ls = ht + layer * XMSS_SIG;
            uint32_t digits[TW_LEN];
            Base2b(node, 16, TW_BITS, *reinterpret_cast<uint32_t(*)[TW_LEN1]>(digits));
            int csum = TW_CSUM_MAX;
            for (int i = 0; i < TW_LEN1; ++i) csum -= digits[i];
            for (int i = 0; i < TW_LEN2; ++i) digits[TW_LEN - 1 - i] = (csum >> (TW_BITS * i)) & (TW_W - 1);
            uint8_t tips[16 * TW_LEN];
            Chains<Lanes>(th, layer, tree, SL_WOTS_TW_HASH, leaf, TW_W, digits, ls, tips);
            th(Adrs(layer, tree, SL_WOTS_TW_PK, leaf), tips, sizeof(tips), node);
            MerklePath(th, node, leaf, ls + 16 * TW_LEN, HP, [&](int k) {
                return Adrs(layer, tree, SL_XMSS_TREE, 0, k + 1, leaf >> (k + 1));
            });
            leaf = tree & ((1u << HP) - 1);
            tree >>= HP;
        }
        return std::memcmp(node, sl_root.data(), 16) == 0;
    }

    // Stateful path.
    if (sig.size() < size_t(SF_SIG_MIN) || sig.size() > size_t(SF_SIG_MAX)) return false;
    const int leaf_height = indicator, depth = FXMSS_HEIGHT - leaf_height;
    const int index_bytes = ceildiv(std::min(depth, 64), 8);
    const uint64_t leaf_index = GetBE(sig.data() + 17, index_bytes);
    if (depth < 64 && leaf_index >> depth) return false;
    const uint8_t* fx = sig.data() + 17 + index_bytes;
    if (sig.size() - 17 - index_bytes != size_t(2 + 16 * C_LEN + 16 * depth)) return false;

    std::vector<uint8_t> bound = {0, uint8_t(ctx.size())};
    bound.insert(bound.end(), ctx.begin(), ctx.end());
    bound.insert(bound.end(), sl_root.begin(), sl_root.end());
    bound.insert(bound.end(), message.begin(), message.end());
    std::vector<uint8_t> leafb(9);
    leafb[0] = leaf_height;
    for (int i = 0; i < 8; ++i) leafb[1 + i] = leaf_index >> (56 - 8 * i);
    const std::vector<uint8_t> R = Bytes(sig.data() + 1, 16);
    uint8_t inner[32], digest[32];
    Sha256({&R, &pk_seed, &sf_root, &leafb, &bound}, inner);
    const std::vector<uint8_t> innerv = Bytes(inner, 32);
    Sha256({&R, &pk_seed, &innerv, &leafb}, digest);

    // wots_c_map_digest: H_grind hashes the leading 10 bytes of the address.
    uint8_t gin[10 + 32 + 4 + 2] = {}, hashed[32];
    std::memcpy(gin, Adrs(leaf_height, leaf_index, SF_WOTS_C_GRIND).b, 10);
    std::memcpy(gin + 10, digest, 32);
    gin[46] = fx[0];
    gin[47] = fx[1];
    CSHA256 g = th.mid;
    g.Write(gin, sizeof(gin)).Finalize(hashed);
    uint32_t digits[C_LEN];
    Base2b(hashed, 16, C_BITS, digits);
    int sum = 0;
    for (int i = 0; i < C_LEN; ++i) sum += digits[i];
    if (sum != C_SUM) return false;

    uint8_t tips[16 * C_LEN], node[16];
    Chains<Lanes>(th, leaf_height, leaf_index, SF_WOTS_C_HASH, 0, C_W, digits, fx + 2, tips);
    th(Adrs(leaf_height, leaf_index, SF_WOTS_C_PK), tips, sizeof(tips), node);
    MerklePath(th, node, leaf_index, fx + 2 + 16 * C_LEN, depth, [&](int k) {
        return Adrs(leaf_height + k + 1, k + 1 < 64 ? leaf_index >> (k + 1) : 0, SF_FXMSS_TREE);
    });
    return std::memcmp(node, sf_root.data(), 16) == 0;
}

// ---------------------------------------------------------------------------
// Test and benchmark harness
// ---------------------------------------------------------------------------

struct Vec {
    std::vector<uint8_t> pk, msg, ctx, sig;
};

// Exact pairs of hexadecimal digits; false on anything else.
bool Unhex(const std::string& s, std::vector<uint8_t>& out)
{
    auto digit = [](char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    if (s.size() % 2) return false;
    out.clear();
    for (size_t i = 0; i < s.size(); i += 2) {
        const int hi = digit(s[i]), lo = digit(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(hi << 4 | lo);
    }
    return true;
}

// Rows of pubkey,message,ctx,signature in hex; exits on an unreadable file,
// a malformed row or an empty file.
std::vector<Vec> Load(const char* path)
{
    std::ifstream f(path);
    if (!f) {
        std::fprintf(stderr, "%s: cannot open\n", path);
        std::exit(2);
    }
    std::vector<Vec> out;
    std::string line;
    for (int n = 1; std::getline(f, line); ++n) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::vector<std::string> cols;
        std::stringstream ss(line);
        std::string col;
        while (std::getline(ss, col, ',')) cols.push_back(col);
        if (!line.empty() && line.back() == ',') cols.push_back("");
        Vec v;
        if (cols.size() != 4 || !Unhex(cols[0], v.pk) || !Unhex(cols[1], v.msg) || !Unhex(cols[2], v.ctx) ||
            !Unhex(cols[3], v.sig) || v.pk.size() != 48 || v.sig.empty()) {
            std::fprintf(stderr, "%s:%d: malformed row\n", path, n);
            std::exit(2);
        }
        out.push_back(v);
    }
    if (out.empty()) {
        std::fprintf(stderr, "%s: no signatures\n", path);
        std::exit(2);
    }
    return out;
}

// Whether every variant returns `expect`; names the first that does not.
bool VerifyAll(const Vec& v, bool expect, std::string& failed)
{
    for (const auto impl : {sha256_implementation::STANDARD, sha256_implementation::USE_SSE4_AND_SHANI}) {
        const std::string name = SHA256AutoDetect(impl);
        const bool r[3] = {Verify<0>(v.msg, v.sig, v.ctx, v.pk), Verify<4>(v.msg, v.sig, v.ctx, v.pk),
                           Verify<8>(v.msg, v.sig, v.ctx, v.pk)};
        for (int k = 0; k < 3; ++k) {
            if (r[k] != expect) {
                failed = std::to_string(k ? 4 * k : 0) + " lanes, " + name;
                return false;
            }
        }
    }
    return true;
}

int Test(int argc, char** argv)
{
    int checked = 0, failures = 0;
    for (int f = 2; f < argc; ++f) {
        for (const Vec& v : Load(argv[f])) {
            bool row_ok = true;
            std::string failed;
            if (!VerifyAll(v, true, failed)) {
                std::printf("FAIL: valid %zu-byte signature rejected (%s; %s)\n", v.sig.size(), failed.c_str(), argv[f]);
                row_ok = false;
            }
            // Tampered: every 97th signature byte flipped in turn, the last byte, the message,
            // each third of the public key, the context, and a truncated and an extended signature.
            std::vector<std::pair<std::string, Vec>> bad;
            for (size_t i = 0; i < v.sig.size(); i += 97) {
                Vec t = v;
                t.sig[i] ^= 0x01;
                bad.emplace_back("signature byte " + std::to_string(i), t);
            }
            Vec t = v; t.sig.back() ^= 0x80; bad.emplace_back("last signature byte", t);
            t = v; t.msg.push_back(0); bad.emplace_back("message", t);
            t = v; t.pk[0] ^= 1; bad.emplace_back("pk_seed", t);
            t = v; t.pk[20] ^= 1; bad.emplace_back("sl_root", t);
            t = v; t.pk[40] ^= 1; bad.emplace_back("sf_root", t);
            t = v; t.ctx.push_back(7); bad.emplace_back("context", t);
            t = v; t.sig.pop_back(); bad.emplace_back("truncated", t);
            t = v; t.sig.push_back(0); bad.emplace_back("extended", t);
            for (const auto& [what, b] : bad) {
                if (!VerifyAll(b, false, failed)) {
                    std::printf("FAIL: tampered %s accepted (%s; %s)\n", what.c_str(), failed.c_str(), argv[f]);
                    row_ok = false;
                }
            }
            ++checked;
            if (row_ok) {
                std::printf("ok: %zu-byte %s signature, %zu tampered variants rejected\n", v.sig.size(),
                            v.sig[0] == FXMSS_HEIGHT ? "stateless" : "stateful", bad.size());
            } else {
                ++failures;
            }
        }
    }
    std::printf("%d signatures checked, %d failed\n", checked, failures);
    return failures ? 1 : 0;
}

double Now() { return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count(); }

double Median(std::vector<double> x)
{
    std::sort(x.begin(), x.end());
    const size_t n = x.size();
    return n % 2 ? x[n / 2] : (x[n / 2 - 1] + x[n / 2]) / 2;
}

int Bench(int argc, char** argv)
{
    const std::vector<Vec> all = Load(argv[2]);
    int rounds = 5;
    if (argc > 3) {
        char* end;
        const long r = std::strtol(argv[3], &end, 10);
        if (*end || r < 1 || r > 1000) {
            std::fprintf(stderr, "ROUNDS must be a positive integer\n");
            return 2;
        }
        rounds = r;
    }
    secp_setup(2000);
    struct Variant {
        const char* name;
        sha256_implementation::UseImplementation impl;
        int lanes;
    };
    const Variant variants[] = {
        {"one at a time, portable C", sha256_implementation::STANDARD, 0},
        {"one at a time, best", sha256_implementation::USE_SSE4_AND_SHANI, 0},
        {"4 lanes, rest portable C", sha256_implementation::STANDARD, 4},
        {"8 lanes, rest portable C", sha256_implementation::STANDARD, 8},
        {"4 lanes, rest best", sha256_implementation::USE_SSE4_AND_SHANI, 4},
        {"8 lanes, rest best", sha256_implementation::USE_SSE4_AND_SHANI, 8},
    };
    // One group per path and exact signature size.
    std::vector<std::pair<size_t, std::vector<const Vec*>>> groups;
    for (const Vec& v : all) {
        auto it = std::find_if(groups.begin(), groups.end(), [&](const auto& g) { return g.first == v.sig.size(); });
        if (it == groups.end()) groups.push_back({v.sig.size(), {&v}});
        else it->second.push_back(&v);
    }
    for (const auto& [bytes, vs] : groups) {
        const bool stateless = vs[0]->sig[0] == FXMSS_HEIGHT;
        const size_t nv = std::size(variants);
        std::vector<std::vector<double>> ratio(nv), us(nv), bip(nv), drift(nv);
        std::vector<std::string> backend(nv);
        const int reps = std::max<int>(1, (stateless ? 64 : 2560) / vs.size());
        // Time `reps` passes over the corpus with variant k; false if any verification failed.
        auto run = [&](size_t k, double& t) {
            backend[k] = SHA256AutoDetect(variants[k].impl);
            bool ok = true;
            const double t0 = Now();
            for (int rep = 0; rep < reps; ++rep)
                for (const Vec* v : vs) {
                    switch (variants[k].lanes) {
                    case 0: ok &= Verify<0>(v->msg, v->sig, v->ctx, v->pk); break;
                    case 4: ok &= Verify<4>(v->msg, v->sig, v->ctx, v->pk); break;
                    default: ok &= Verify<8>(v->msg, v->sig, v->ctx, v->pk); break;
                    }
                }
            t = (Now() - t0) / (reps * vs.size());
            return ok;
        };
        // Warm-up: one untimed pass of every variant and of BIP340 verification.
        for (size_t k = 0; k < nv; ++k) {
            double t;
            if (!run(k, t)) {
                std::printf("verification failed\n");
                return 1;
            }
        }
        secp_verify();
        // Each round runs the variants in an order rotated by one, and times
        // BIP340 verification between consecutive variants; each variant is
        // normalized by the mean of the BIP340 timings just before and after it.
        for (int r = 0; r < rounds; ++r) {
            double tb = secp_verify();
            for (size_t i = 0; i < nv; ++i) {
                const size_t k = (i + r) % nv;
                double t;
                if (!run(k, t)) {
                    std::printf("verification failed\n");
                    return 1;
                }
                const double tb_after = secp_verify();
                const double b = (tb + tb_after) / 2;
                ratio[k].push_back(t / b);
                us[k].push_back(t * 1e6);
                bip[k].push_back(b * 1e6);
                drift[k].push_back(std::abs(tb_after / tb - 1));
                tb = tb_after;
            }
        }
        for (size_t k = 0; k < nv; ++k) {
            const auto [lo, hi] = std::minmax_element(ratio[k].begin(), ratio[k].end());
            std::string raw;
            for (double x : ratio[k]) raw += (raw.empty() ? "" : ", ") + std::to_string(x);
            std::printf("{\"path\": \"%s\", \"bytes\": %zu, \"signatures\": %zu, \"variant\": \"%s\", \"sha256\": \"%s\", "
                        "\"bip340_per_verification\": %.3f, \"min\": %.3f, \"max\": %.3f, \"verify_us\": %.2f, \"bip340_us\": %.2f, "
                        "\"max_bip340_drift\": %.4f, \"rounds\": [%s]}\n",
                        stateless ? "stateless" : "stateful", bytes, vs.size(), variants[k].name, backend[k].c_str(),
                        Median(ratio[k]), *lo, *hi, Median(us[k]), Median(bip[k]),
                        *std::max_element(drift[k].begin(), drift[k].end()), raw.c_str());
        }
        std::fflush(stdout);
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc >= 3 && std::string(argv[1]) == "test") return Test(argc, argv);
    if (argc >= 3 && std::string(argv[1]) == "bench") return Bench(argc, argv);
    std::fprintf(stderr, "usage: %s test FILE... | bench FILE [ROUNDS]\n", argv[0]);
    return 2;
}
