#include "yumi_nx/crypto.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>

#ifdef __SWITCH__
#include <switch.h>
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <bcrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace yumi_nx::net::crypto {

namespace {

inline uint32_t Rotr32(uint32_t v, unsigned n) noexcept { return (v >> n) | (v << (32u - n)); }
inline uint32_t Rotl32(uint32_t v, unsigned n) noexcept { return (v << n) | (v >> (32u - n)); }
inline uint64_t Rotr64(uint64_t v, unsigned n) noexcept { return (v >> n) | (v << (64u - n)); }
inline uint64_t Rotl64(uint64_t v, unsigned n) noexcept { return (v << n) | (v >> (64u - n)); }

inline uint32_t LoadBe32(const uint8_t* p) noexcept {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}
inline void StoreBe32(uint8_t* p, uint32_t v) noexcept {
    p[0] = uint8_t(v >> 24);
    p[1] = uint8_t(v >> 16);
    p[2] = uint8_t(v >> 8);
    p[3] = uint8_t(v);
}
inline uint32_t LoadLe32(const uint8_t* p) noexcept {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline void StoreLe32(uint8_t* p, uint32_t v) noexcept {
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
    p[2] = uint8_t(v >> 16);
    p[3] = uint8_t(v >> 24);
}
inline uint64_t LoadBe64(const uint8_t* p) noexcept {
    return (uint64_t(LoadBe32(p)) << 32) | uint64_t(LoadBe32(p + 4));
}
inline void StoreBe64(uint8_t* p, uint64_t v) noexcept {
    StoreBe32(p, uint32_t(v >> 32));
    StoreBe32(p + 4, uint32_t(v));
}
inline uint64_t LoadLe64(const uint8_t* p) noexcept {
    return uint64_t(LoadLe32(p)) | (uint64_t(LoadLe32(p + 4)) << 32);
}
inline void StoreLe64(uint8_t* p, uint64_t v) noexcept {
    StoreLe32(p, uint32_t(v));
    StoreLe32(p + 4, uint32_t(v >> 32));
}

// ---------------- MD5 & SHA-1 ----------------

constexpr uint32_t kMd5K[64] = {
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau, 0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u, 0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u, 0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u,
};
constexpr uint8_t kMd5S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

void Md5Transform(uint32_t s[4], const uint8_t block[64]) noexcept {
    uint32_t m[16];
    for (int i = 0; i < 16; ++i) m[i] = LoadLe32(block + i * 4);
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3];
    for (int i = 0; i < 64; ++i) {
        uint32_t f = 0, g = 0;
        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = static_cast<uint32_t>(i);
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = static_cast<uint32_t>((5 * i + 1) % 16);
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = static_cast<uint32_t>((3 * i + 5) % 16);
        } else {
            f = c ^ (b | (~d));
            g = static_cast<uint32_t>((7 * i) % 16);
        }
        f += a + kMd5K[i] + m[g];
        a = d;
        d = c;
        c = b;
        b += Rotl32(f, kMd5S[i]);
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d;
}

void Sha1Transform(uint32_t s[5], const uint8_t block[64]) noexcept {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) w[i] = LoadBe32(block + i * 4);
    for (int i = 16; i < 80; ++i) w[i] = Rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f = 0, k = 0;
        if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5a827999u; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1u; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcu; }
        else { f = b ^ c ^ d; k = 0xca62c1d6u; }
        const uint32_t temp = Rotl32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = Rotl32(b, 30); b = a; a = temp;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e;
}

// ---------------- SHA-256 ----------------

constexpr uint32_t kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

void Sha256Transform(uint32_t s[8], const uint8_t block[64]) noexcept {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) w[i] = LoadBe32(block + i * 4);
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = Rotr32(w[i - 15], 7) ^ Rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = Rotr32(w[i - 2], 17) ^ Rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3];
    uint32_t e = s[4], f = s[5], g = s[6], h = s[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t S1 = Rotr32(e, 6) ^ Rotr32(e, 11) ^ Rotr32(e, 25);
        const uint32_t ch = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + S1 + ch + kSha256K[i] + w[i];
        const uint32_t S0 = Rotr32(a, 2) ^ Rotr32(a, 13) ^ Rotr32(a, 22);
        const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d;
    s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

// ---------------- SHA-512 / SHA-384 ----------------

constexpr uint64_t kSha512K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

void Sha512Transform(uint64_t s[8], const uint8_t block[128]) noexcept {
    uint64_t w[80];
    for (int i = 0; i < 16; ++i) w[i] = LoadBe64(block + i * 8);
    for (int i = 16; i < 80; ++i) {
        const uint64_t s0 = Rotr64(w[i - 15], 1) ^ Rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        const uint64_t s1 = Rotr64(w[i - 2], 19) ^ Rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint64_t a = s[0], b = s[1], c = s[2], d = s[3];
    uint64_t e = s[4], f = s[5], g = s[6], h = s[7];
    for (int i = 0; i < 80; ++i) {
        const uint64_t S1 = Rotr64(e, 14) ^ Rotr64(e, 18) ^ Rotr64(e, 41);
        const uint64_t ch = (e & f) ^ ((~e) & g);
        const uint64_t temp1 = h + S1 + ch + kSha512K[i] + w[i];
        const uint64_t S0 = Rotr64(a, 28) ^ Rotr64(a, 34) ^ Rotr64(a, 39);
        const uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
        const uint64_t temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }
    s[0] += a; s[1] += b; s[2] += c; s[3] += d;
    s[4] += e; s[5] += f; s[6] += g; s[7] += h;
}

// ---------------- BLAKE2s ----------------

constexpr uint32_t kBlake2sIv[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

constexpr uint8_t kBlake2sSigma[10][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
};

void Blake2sCompress(uint32_t h[8], uint32_t t0, uint32_t t1, const uint8_t block[64], bool last) noexcept {
    uint32_t m[16];
    for (int i = 0; i < 16; ++i) m[i] = LoadLe32(block + i * 4);
    uint32_t v[16];
    for (int i = 0; i < 8; ++i) {
        v[i] = h[i];
        v[i + 8] = kBlake2sIv[i];
    }
    v[12] ^= t0;
    v[13] ^= t1;
    if (last) v[14] = ~v[14];

    auto G = [&](int a, int b, int c, int d, uint32_t x, uint32_t y) {
        v[a] = v[a] + v[b] + x;
        v[d] = Rotr32(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Rotr32(v[b] ^ v[c], 12);
        v[a] = v[a] + v[b] + y;
        v[d] = Rotr32(v[d] ^ v[a], 8);
        v[c] = v[c] + v[d];
        v[b] = Rotr32(v[b] ^ v[c], 7);
    };
    for (int r = 0; r < 10; ++r) {
        const auto* s = kBlake2sSigma[r];
        G(0, 4, 8, 12, m[s[0]], m[s[1]]);
        G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(2, 6, 10, 14, m[s[4]], m[s[5]]);
        G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(0, 5, 10, 15, m[s[8]], m[s[9]]);
        G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7, 8, 13, m[s[12]], m[s[13]]);
        G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
}

// ---------------- Curve25519 (TweetNaCl 16-limb) ----------------

using Gf = int64_t[16];

void Car25519(Gf o) noexcept {
    for (int i = 0; i < 16; ++i) {
        o[i] += (1LL << 16);
        const int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

void Sel25519(Gf p, Gf q, int b) noexcept {
    const int64_t c = ~(b - 1);
    for (int i = 0; i < 16; ++i) {
        const int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

void GfAdd(Gf o, const Gf a, const Gf b) noexcept {
    for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}
void GfSub(Gf o, const Gf a, const Gf b) noexcept {
    for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}
void GfMul(Gf o, const Gf a, const Gf b) noexcept {
    int64_t t[31]{};
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j) t[i + j] += a[i] * b[j];
    }
    for (int i = 0; i < 15; ++i) t[i] += 38 * t[i + 16];
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    Car25519(o);
    Car25519(o);
}
void GfSq(Gf o, const Gf a) noexcept { GfMul(o, a, a); }

void Inv25519(Gf o, const Gf i) noexcept {
    Gf c;
    for (int a = 0; a < 16; ++a) c[a] = i[a];
    for (int a = 253; a >= 0; --a) {
        GfSq(c, c);
        if (a != 2 && a != 4) GfMul(c, c, i);
    }
    for (int a = 0; a < 16; ++a) o[a] = c[a];
}

void Pack25519(uint8_t o[32], const Gf n) noexcept {
    Gf m, t;
    for (int i = 0; i < 16; ++i) t[i] = n[i];
    Car25519(t);
    Car25519(t);
    Car25519(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        const int b = static_cast<int>((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        Sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i) {
        o[2 * i] = static_cast<uint8_t>(t[i] & 0xff);
        o[2 * i + 1] = static_cast<uint8_t>(t[i] >> 8);
    }
}

void Unpack25519(Gf o, const uint8_t n[32]) noexcept {
    for (int i = 0; i < 16; ++i) {
        o[i] = static_cast<int64_t>(n[2 * i]) + (static_cast<int64_t>(n[2 * i + 1]) << 8);
    }
    o[15] &= 0x7fff;
}

// ---------------- AES + GCM ----------------

constexpr uint8_t kAesSbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

constexpr uint8_t kAesRcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

struct AesKey {
    uint32_t rk[60]{};
    int nr = 10;
};

uint32_t SubWord(uint32_t w) noexcept {
    return (uint32_t(kAesSbox[(w >> 24) & 0xFF]) << 24) | (uint32_t(kAesSbox[(w >> 16) & 0xFF]) << 16) |
           (uint32_t(kAesSbox[(w >> 8) & 0xFF]) << 8) | uint32_t(kAesSbox[w & 0xFF]);
}

bool AesInit(AesKey& ctx, const uint8_t* key, size_t key_len) noexcept {
    if (key_len != 16 && key_len != 32) return false;
    const int nk = (key_len == 16) ? 4 : 8;
    ctx.nr = nk + 6;
    for (int i = 0; i < nk; ++i) ctx.rk[i] = LoadBe32(key + i * 4);
    for (int i = nk; i < 4 * (ctx.nr + 1); ++i) {
        uint32_t temp = ctx.rk[i - 1];
        if (i % nk == 0) {
            temp = SubWord(Rotl32(temp, 8)) ^ (uint32_t(kAesRcon[i / nk]) << 24);
        } else if (nk > 6 && (i % nk) == 4) {
            temp = SubWord(temp);
        }
        ctx.rk[i] = ctx.rk[i - nk] ^ temp;
    }
    return true;
}

inline uint8_t Xtime(uint8_t x) noexcept { return uint8_t((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00)); }

void AesEncryptBlock(const AesKey& ctx, const uint8_t in[16], uint8_t out[16]) noexcept {
    uint8_t s[16];
    for (int i = 0; i < 16; ++i) {
        s[i] = in[i] ^ uint8_t((ctx.rk[i >> 2] >> (24 - 8 * (i & 3))) & 0xFF);
    }
    for (int r = 1; r <= ctx.nr; ++r) {
        uint8_t t[16];
        for (int i = 0; i < 16; ++i) t[i] = kAesSbox[s[i]];
        // ShiftRows (column-major)
        s[0] = t[0]; s[4] = t[4]; s[8] = t[8]; s[12] = t[12];
        s[1] = t[5]; s[5] = t[9]; s[9] = t[13]; s[13] = t[1];
        s[2] = t[10]; s[6] = t[14]; s[10] = t[2]; s[14] = t[6];
        s[3] = t[15]; s[7] = t[3]; s[11] = t[7]; s[15] = t[11];

        if (r < ctx.nr) {
            for (int c = 0; c < 4; ++c) {
                const int i = c * 4;
                const uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
                const uint8_t xr = a0 ^ a1 ^ a2 ^ a3;
                s[i]     = a0 ^ xr ^ Xtime(a0 ^ a1);
                s[i + 1] = a1 ^ xr ^ Xtime(a1 ^ a2);
                s[i + 2] = a2 ^ xr ^ Xtime(a2 ^ a3);
                s[i + 3] = a3 ^ xr ^ Xtime(a3 ^ a0);
            }
        }
        for (int i = 0; i < 16; ++i) {
            s[i] ^= uint8_t((ctx.rk[r * 4 + (i >> 2)] >> (24 - 8 * (i & 3))) & 0xFF);
        }
    }
    std::memcpy(out, s, 16);
}

void Gf128Mul(const uint8_t X[16], const uint8_t Y[16], uint8_t Z[16]) noexcept {
    uint64_t z0 = 0, z1 = 0;
    uint64_t v0 = LoadBe64(Y), v1 = LoadBe64(Y + 8);
    for (int i = 0; i < 16; ++i) {
        const uint8_t b = X[i];
        for (int bit = 7; bit >= 0; --bit) {
            const uint64_t mask = -uint64_t((b >> bit) & 1u);
            z0 ^= v0 & mask;
            z1 ^= v1 & mask;
            const uint64_t lsb = v1 & 1u;
            v1 = (v1 >> 1) | ((v0 & 1u) << 63);
            v0 >>= 1;
            v0 ^= (-lsb) & 0xe100000000000000ULL;
        }
    }
    StoreBe64(Z, z0);
    StoreBe64(Z + 8, z1);
}

void Ghash(const uint8_t H[16],
           const uint8_t* aad,
           size_t aad_len,
           const uint8_t* ct,
           size_t ct_len,
           uint8_t out[16]) noexcept {
    std::memset(out, 0, 16);
    auto feed_blocks = [&](const uint8_t* data, size_t len) {
        size_t off = 0;
        while (off < len) {
            uint8_t block[16]{};
            const size_t n = std::min<size_t>(16, len - off);
            std::memcpy(block, data + off, n);
            for (int i = 0; i < 16; ++i) out[i] ^= block[i];
            uint8_t next[16];
            Gf128Mul(out, H, next);
            std::memcpy(out, next, 16);
            off += n;
        }
    };
    feed_blocks(aad, aad_len);
    feed_blocks(ct, ct_len);

    uint8_t len_block[16];
    StoreBe64(len_block, uint64_t(aad_len) * 8ULL);
    StoreBe64(len_block + 8, uint64_t(ct_len) * 8ULL);
    for (int i = 0; i < 16; ++i) out[i] ^= len_block[i];
    uint8_t next[16];
    Gf128Mul(out, H, next);
    std::memcpy(out, next, 16);
}

// ---------------- ChaCha20 & Poly1305 ----------------

void ChaCha20Block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]) noexcept {
    uint32_t s[16] = {
        0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u,
        LoadLe32(key + 0),  LoadLe32(key + 4),  LoadLe32(key + 8),  LoadLe32(key + 12),
        LoadLe32(key + 16), LoadLe32(key + 20), LoadLe32(key + 24), LoadLe32(key + 28),
        counter,
        LoadLe32(nonce + 0), LoadLe32(nonce + 4), LoadLe32(nonce + 8),
    };
    uint32_t x[16];
    std::memcpy(x, s, sizeof(x));
    auto qr = [&](int a, int b, int c, int d) {
        x[a] += x[b]; x[d] = Rotl32(x[d] ^ x[a], 16);
        x[c] += x[d]; x[b] = Rotl32(x[b] ^ x[c], 12);
        x[a] += x[b]; x[d] = Rotl32(x[d] ^ x[a], 8);
        x[c] += x[d]; x[b] = Rotl32(x[b] ^ x[c], 7);
    };
    for (int i = 0; i < 10; ++i) {
        qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15);
        qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 10 + 4);
    }
    for (int i = 0; i < 16; ++i) StoreLe32(out + i * 4, x[i] + s[i]);
}

void ChaCha20XorInternal(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], const uint8_t* in, size_t len, uint8_t* out) noexcept {
    uint8_t ks[64];
    size_t off = 0;
    while (off < len) {
        ChaCha20Block(key, counter++, nonce, ks);
        const size_t n = std::min<size_t>(64, len - off);
        for (size_t i = 0; i < n; ++i) out[off + i] = in[off + i] ^ ks[i];
        off += n;
    }
}

// ---------------- BLAKE2b / Keccak-f[1600] / BLAKE3 ----------------

constexpr uint64_t kBlake2bIv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

constexpr uint8_t kBlake2bSigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

void Blake2bCompress(uint64_t h[8], uint64_t t0, uint64_t t1, const uint8_t block[128], bool last) noexcept {
    uint64_t m[16];
    for (int i = 0; i < 16; ++i) m[i] = LoadLe64(block + i * 8);
    uint64_t v[16];
    for (int i = 0; i < 8; ++i) {
        v[i] = h[i];
        v[i + 8] = kBlake2bIv[i];
    }
    v[12] ^= t0;
    v[13] ^= t1;
    if (last) v[14] = ~v[14];

    auto G = [&](int a, int b, int c, int d, uint64_t x, uint64_t y) {
        v[a] = v[a] + v[b] + x;
        v[d] = Rotr64(v[d] ^ v[a], 32);
        v[c] = v[c] + v[d];
        v[b] = Rotr64(v[b] ^ v[c], 24);
        v[a] = v[a] + v[b] + y;
        v[d] = Rotr64(v[d] ^ v[a], 16);
        v[c] = v[c] + v[d];
        v[b] = Rotr64(v[b] ^ v[c], 63);
    };
    for (int r = 0; r < 12; ++r) {
        const auto* s = kBlake2bSigma[r];
        G(0, 4, 8, 12, m[s[0]], m[s[1]]);
        G(1, 5, 9, 13, m[s[2]], m[s[3]]);
        G(2, 6, 10, 14, m[s[4]], m[s[5]]);
        G(3, 7, 11, 15, m[s[6]], m[s[7]]);
        G(0, 5, 10, 15, m[s[8]], m[s[9]]);
        G(1, 6, 11, 12, m[s[10]], m[s[11]]);
        G(2, 7, 8, 13, m[s[12]], m[s[13]]);
        G(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (int i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
}

constexpr uint64_t kKeccakRc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

void KeccakF1600(uint64_t a[25]) noexcept {
    for (int round = 0; round < 24; ++round) {
        uint64_t c[5], d[5];
        for (int x = 0; x < 5; ++x) {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for (int x = 0; x < 5; ++x) {
            d[x] = c[(x + 4) % 5] ^ Rotl64(c[(x + 1) % 5], 1);
            for (int y = 0; y < 25; y += 5) a[x + y] ^= d[x];
        }
        // Rho + Pi
        uint64_t cur = a[1];
        int x = 1, y = 0;
        for (int t = 0; t < 24; ++t) {
            const unsigned r = static_cast<unsigned>(((t + 1) * (t + 2) / 2) % 64);
            const int nx = y;
            const int ny = (2 * x + 3 * y) % 5;
            const size_t nidx = static_cast<size_t>(nx + 5 * ny);
            const uint64_t tmp = a[nidx];
            a[nidx] = (r == 0) ? cur : Rotl64(cur, r);
            cur = tmp;
            x = nx;
            y = ny;
        }
        // Chi
        for (int row = 0; row < 25; row += 5) {
            uint64_t t5[5];
            for (int i = 0; i < 5; ++i) t5[i] = a[row + i];
            for (int i = 0; i < 5; ++i) {
                a[row + i] = t5[i] ^ ((~t5[(i + 1) % 5]) & t5[(i + 2) % 5]);
            }
        }
        // Iota
        a[0] ^= kKeccakRc[round];
    }
}

constexpr uint32_t kBlake3Iv[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};
constexpr uint8_t kBlake3Perm[16] = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
constexpr uint32_t kBlake3ChunkStart = 1u << 0;
constexpr uint32_t kBlake3ChunkEnd = 1u << 1;
constexpr uint32_t kBlake3Parent = 1u << 2;
constexpr uint32_t kBlake3Root = 1u << 3;
constexpr uint32_t kBlake3KeyedHash = 1u << 4;
constexpr uint32_t kBlake3DeriveCtx = 1u << 5;
constexpr uint32_t kBlake3DeriveMat = 1u << 6;

void Blake3Compress(const uint32_t cv[8],
                    const uint8_t block[64],
                    uint8_t block_len,
                    uint64_t counter,
                    uint32_t flags,
                    uint32_t out_words[16]) noexcept {
    uint32_t m[16];
    for (int i = 0; i < 16; ++i) m[i] = LoadLe32(block + i * 4);
    uint32_t s[16] = {
        cv[0], cv[1], cv[2], cv[3],
        cv[4], cv[5], cv[6], cv[7],
        kBlake3Iv[0], kBlake3Iv[1], kBlake3Iv[2], kBlake3Iv[3],
        static_cast<uint32_t>(counter),
        static_cast<uint32_t>(counter >> 32),
        static_cast<uint32_t>(block_len),
        flags,
    };
    auto G = [&](int a, int b, int c, int d, uint32_t mx, uint32_t my) {
        s[a] = s[a] + s[b] + mx;
        s[d] = Rotr32(s[d] ^ s[a], 16);
        s[c] = s[c] + s[d];
        s[b] = Rotr32(s[b] ^ s[c], 12);
        s[a] = s[a] + s[b] + my;
        s[d] = Rotr32(s[d] ^ s[a], 8);
        s[c] = s[c] + s[d];
        s[b] = Rotr32(s[b] ^ s[c], 7);
    };
    for (int round = 0; round < 7; ++round) {
        G(0, 4, 8, 12, m[0], m[1]);
        G(1, 5, 9, 13, m[2], m[3]);
        G(2, 6, 10, 14, m[4], m[5]);
        G(3, 7, 11, 15, m[6], m[7]);
        G(0, 5, 10, 15, m[8], m[9]);
        G(1, 6, 11, 12, m[10], m[11]);
        G(2, 7, 8, 13, m[12], m[13]);
        G(3, 4, 9, 14, m[14], m[15]);
        if (round < 6) {
            uint32_t permuted[16];
            for (int i = 0; i < 16; ++i) permuted[i] = m[kBlake3Perm[i]];
            std::memcpy(m, permuted, sizeof(m));
        }
    }
    for (int i = 0; i < 8; ++i) {
        out_words[i] = s[i] ^ s[i + 8];
        out_words[i + 8] = s[i + 8] ^ cv[i];
    }
}

struct Blake3Output {
    uint32_t input_cv[8]{};
    uint8_t block[64]{};
    uint8_t block_len = 0;
    uint64_t counter = 0;
    uint32_t flags = 0;

    void ChainingValue(uint32_t out[8]) const noexcept {
        uint32_t w[16];
        Blake3Compress(input_cv, block, block_len, counter, flags, w);
        std::memcpy(out, w, 32);
    }

    void RootBytes(uint8_t* out, size_t out_len) const noexcept {
        uint64_t blk_ctr = 0;
        size_t off = 0;
        while (off < out_len) {
            uint32_t w[16];
            Blake3Compress(input_cv, block, block_len, blk_ctr++, flags | kBlake3Root, w);
            uint8_t bytes[64];
            for (int i = 0; i < 16; ++i) StoreLe32(bytes + i * 4, w[i]);
            const size_t n = std::min<size_t>(64, out_len - off);
            std::memcpy(out + off, bytes, n);
            off += n;
        }
    }
};

Blake3Output Blake3ParentOutput(const uint32_t left_cv[8], const uint32_t right_cv[8],
                                const uint32_t key_words[8], uint32_t flags) noexcept {
    Blake3Output out{};
    std::memcpy(out.input_cv, key_words, 32);
    for (int i = 0; i < 8; ++i) {
        StoreLe32(out.block + i * 4, left_cv[i]);
        StoreLe32(out.block + 32 + i * 4, right_cv[i]);
    }
    out.block_len = 64;
    out.counter = 0;
    out.flags = flags | kBlake3Parent;
    return out;
}

void Poly1305TagAead(const uint8_t otk[32],
                     const uint8_t* aad,
                     size_t aad_len,
                     const uint8_t* ct,
                     size_t ct_len,
                     uint8_t tag[16]) noexcept {
    // 26-bit limb Poly1305
    uint32_t r0 = LoadLe32(otk + 0) & 0x3ffffffu;
    uint32_t r1 = (LoadLe32(otk + 3) >> 2) & 0x3ffff03u;
    uint32_t r2 = (LoadLe32(otk + 6) >> 4) & 0x3ffc0ffu;
    uint32_t r3 = (LoadLe32(otk + 9) >> 6) & 0x3f03fffu;
    uint32_t r4 = (LoadLe32(otk + 12) >> 8) & 0x00fffffu;

    const uint32_t s1 = r1 * 5u, s2 = r2 * 5u, s3 = r3 * 5u, s4 = r4 * 5u;
    uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    auto feed_block = [&](const uint8_t* b, size_t n, uint32_t hibit) {
        uint8_t pad[17]{};
        std::memcpy(pad, b, n);
        pad[n] = 1;
        h0 += LoadLe32(pad + 0) & 0x3ffffffu;
        h1 += (LoadLe32(pad + 3) >> 2) & 0x3ffffffu;
        h2 += (LoadLe32(pad + 6) >> 4) & 0x3ffffffu;
        h3 += (LoadLe32(pad + 9) >> 6) & 0x3ffffffu;
        h4 += (LoadLe32(pad + 12) >> 8) | ((n == 16) ? hibit : 0u);

        const uint64_t d0 = uint64_t(h0) * r0 + uint64_t(h1) * s4 + uint64_t(h2) * s3 + uint64_t(h3) * s2 + uint64_t(h4) * s1;
        uint64_t d1 = uint64_t(h0) * r1 + uint64_t(h1) * r0 + uint64_t(h2) * s4 + uint64_t(h3) * s3 + uint64_t(h4) * s2;
        uint64_t d2 = uint64_t(h0) * r2 + uint64_t(h1) * r1 + uint64_t(h2) * r0 + uint64_t(h3) * s4 + uint64_t(h4) * s3;
        uint64_t d3 = uint64_t(h0) * r3 + uint64_t(h1) * r2 + uint64_t(h2) * r1 + uint64_t(h3) * r0 + uint64_t(h4) * s4;
        uint64_t d4 = uint64_t(h0) * r4 + uint64_t(h1) * r3 + uint64_t(h2) * r2 + uint64_t(h3) * r1 + uint64_t(h4) * r0;

        uint32_t c = uint32_t(d0 >> 26); h0 = uint32_t(d0) & 0x3ffffffu;
        d1 += c; c = uint32_t(d1 >> 26); h1 = uint32_t(d1) & 0x3ffffffu;
        d2 += c; c = uint32_t(d2 >> 26); h2 = uint32_t(d2) & 0x3ffffffu;
        d3 += c; c = uint32_t(d3 >> 26); h3 = uint32_t(d3) & 0x3ffffffu;
        d4 += c; c = uint32_t(d4 >> 26); h4 = uint32_t(d4) & 0x3ffffffu;
        h0 += c * 5u; c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c;
    };

    auto feed_padded = [&](const uint8_t* data, size_t len) {
        size_t off = 0;
        while (off < len) {
            const size_t n = std::min<size_t>(16, len - off);
            uint8_t blk[16]{};
            std::memcpy(blk, data + off, n);
            feed_block(blk, 16, 1u << 24);
            off += n;
        }
    };
    feed_padded(aad, aad_len);
    feed_padded(ct, ct_len);

    uint8_t lens[16];
    for (int i = 0; i < 8; ++i) {
        lens[i] = uint8_t((uint64_t(aad_len) >> (8 * i)) & 0xFFu);
        lens[8 + i] = uint8_t((uint64_t(ct_len) >> (8 * i)) & 0xFFu);
    }
    feed_block(lens, 16, 1u << 24);

    uint32_t c = h1 >> 26; h1 &= 0x3ffffffu;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffffu;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffffu;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffffu;
    h0 += c * 5u; c = h0 >> 26; h0 &= 0x3ffffffu;
    h1 += c;

    uint32_t g0 = h0 + 5u; c = g0 >> 26; g0 &= 0x3ffffffu;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffffu;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffffu;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffffu;
    uint32_t g4 = h4 + c - (1u << 26);

    const uint32_t mask = (g4 >> 31) - 1u;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    const uint32_t f0 = (h0) | (h1 << 26);
    const uint32_t f1 = (h1 >> 6) | (h2 << 20);
    const uint32_t f2 = (h2 >> 12) | (h3 << 14);
    const uint32_t f3 = (h3 >> 18) | (h4 << 8);

    uint64_t s = uint64_t(f0) + LoadLe32(otk + 16);
    StoreLe32(tag + 0, uint32_t(s));
    s = uint64_t(f1) + LoadLe32(otk + 20) + (s >> 32);
    StoreLe32(tag + 4, uint32_t(s));
    s = uint64_t(f2) + LoadLe32(otk + 24) + (s >> 32);
    StoreLe32(tag + 8, uint32_t(s));
    s = uint64_t(f3) + LoadLe32(otk + 28) + (s >> 32);
    StoreLe32(tag + 12, uint32_t(s));
}

}  // namespace

// ---------------- RandomBytes & ConstantTimeEqual ----------------

bool RandomBytes(uint8_t* out, size_t len) noexcept {
    if (!out || len == 0) return true;
#ifdef __SWITCH__
    static std::atomic<int> s_csrng_state{0};  // 0=uninit, 1=ok, 2=failed
    int st = s_csrng_state.load();
    if (st == 0) {
        if (R_SUCCEEDED(csrngInitialize())) {
            s_csrng_state.store(1);
            st = 1;
        } else {
            s_csrng_state.store(2);
            st = 2;
        }
    }
    if (st == 1 && R_SUCCEEDED(csrngGetRandomBytes(out, len))) {
        return true;
    }
    static std::atomic<uint64_t> s_fallback_seq{1};
    size_t off = 0;
    while (off < len) {
        uint64_t seed[4] = {
            armGetSystemTick(),
            s_fallback_seq.fetch_add(1),
            reinterpret_cast<uintptr_t>(out) ^ off,
            len,
        };
        uint8_t digest[32];
        Sha256::Digest(seed, sizeof(seed), digest);
        const size_t n = std::min<size_t>(32, len - off);
        std::memcpy(out + off, digest, n);
        off += n;
    }
    return true;
#elif defined(_WIN32)
    return BCryptGenRandom(nullptr, out, static_cast<ULONG>(len), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    const int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < len) {
        const ssize_t r = ::read(fd, out + off, len - off);
        if (r <= 0) {
            ::close(fd);
            return false;
        }
        off += static_cast<size_t>(r);
    }
    ::close(fd);
    return true;
#endif
}

bool ConstantTimeEqual(const uint8_t* a, const uint8_t* b, size_t len) noexcept {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

// ---------------- Extended Hash / Checksum implementations ----------------

void Md5::Init() noexcept {
    state_[0] = 0x67452301u;
    state_[1] = 0xefcdab89u;
    state_[2] = 0x98badcfeu;
    state_[3] = 0x10325476u;
    total_bytes_ = 0;
    buf_len_ = 0;
}

void Md5::Update(const void* data, size_t len) noexcept {
    const auto* p = static_cast<const uint8_t*>(data);
    total_bytes_ += len;
    if (buf_len_ > 0) {
        const size_t n = std::min<size_t>(64 - buf_len_, len);
        std::memcpy(buf_ + buf_len_, p, n);
        buf_len_ += n;
        p += n;
        len -= n;
        if (buf_len_ == 64) {
            Md5Transform(state_, buf_);
            buf_len_ = 0;
        }
    }
    while (len >= 64) {
        Md5Transform(state_, p);
        p += 64;
        len -= 64;
    }
    if (len > 0) {
        std::memcpy(buf_, p, len);
        buf_len_ = len;
    }
}

void Md5::Final(uint8_t out[16]) noexcept {
    const uint64_t total_bits = total_bytes_ * 8ULL;
    const uint8_t pad_80 = 0x80;
    Update(&pad_80, 1);
    const uint8_t zero = 0x00;
    while (buf_len_ != 56) Update(&zero, 1);
    StoreLe64(buf_ + 56, total_bits);
    Md5Transform(state_, buf_);
    for (int i = 0; i < 4; ++i) StoreLe32(out + i * 4, state_[i]);
}

void Md5::Digest(const void* data, size_t len, uint8_t out[16]) noexcept {
    Md5 ctx;
    ctx.Init();
    if (len > 0 && data) ctx.Update(data, len);
    ctx.Final(out);
}

void Sha1::Init() noexcept {
    state_[0] = 0x67452301u;
    state_[1] = 0xefcdab89u;
    state_[2] = 0x98badcfeu;
    state_[3] = 0x10325476u;
    state_[4] = 0xc3d2e1f0u;
    total_bytes_ = 0;
    buf_len_ = 0;
}

void Sha1::Update(const void* data, size_t len) noexcept {
    const auto* p = static_cast<const uint8_t*>(data);
    total_bytes_ += len;
    if (buf_len_ > 0) {
        const size_t n = std::min<size_t>(64 - buf_len_, len);
        std::memcpy(buf_ + buf_len_, p, n);
        buf_len_ += n;
        p += n;
        len -= n;
        if (buf_len_ == 64) {
            Sha1Transform(state_, buf_);
            buf_len_ = 0;
        }
    }
    while (len >= 64) {
        Sha1Transform(state_, p);
        p += 64;
        len -= 64;
    }
    if (len > 0) {
        std::memcpy(buf_, p, len);
        buf_len_ = len;
    }
}

void Sha1::Final(uint8_t out[20]) noexcept {
    const uint64_t total_bits = total_bytes_ * 8ULL;
    const uint8_t pad_80 = 0x80;
    Update(&pad_80, 1);
    const uint8_t zero = 0x00;
    while (buf_len_ != 56) Update(&zero, 1);
    StoreBe64(buf_ + 56, total_bits);
    Sha1Transform(state_, buf_);
    for (int i = 0; i < 5; ++i) StoreBe32(out + i * 4, state_[i]);
}

void Sha1::Digest(const void* data, size_t len, uint8_t out[20]) noexcept {
    Sha1 ctx;
    ctx.Init();
    if (len > 0 && data) ctx.Update(data, len);
    ctx.Final(out);
}

void Sha224::Digest(const void* data, size_t len, uint8_t out[28]) noexcept {
    uint32_t s[8] = {
        0xc1059ed8u, 0x367cd507u, 0x3070dd17u, 0xf70e5939u,
        0xffc00b31u, 0x68581511u, 0x64f98fa7u, 0xbefa4fa4u,
    };
    uint8_t buf[64]{};
    size_t blen = 0;
    const auto* p = static_cast<const uint8_t*>(data);
    size_t rem = len;
    while (rem >= 64) {
        Sha256Transform(s, p);
        p += 64;
        rem -= 64;
    }
    if (rem > 0 && p) {
        std::memcpy(buf, p, rem);
        blen = rem;
    }
    buf[blen++] = 0x80;
    if (blen > 56) {
        while (blen < 64) buf[blen++] = 0;
        Sha256Transform(s, buf);
        blen = 0;
    }
    while (blen < 56) buf[blen++] = 0;
    StoreBe64(buf + 56, static_cast<uint64_t>(len) * 8ULL);
    Sha256Transform(s, buf);
    for (int i = 0; i < 7; ++i) StoreBe32(out + i * 4, s[i]);
}

void Blake2b::Init(size_t out_len, const uint8_t* key, size_t key_len) noexcept {
    out_len_ = std::clamp<size_t>(out_len, 1, 64);
    key_len = std::min<size_t>(key_len, 64);
    for (int i = 0; i < 8; ++i) h_[i] = kBlake2bIv[i];
    h_[0] ^= 0x01010000ULL | (static_cast<uint64_t>(key_len) << 8) | static_cast<uint64_t>(out_len_);
    t_[0] = 0;
    t_[1] = 0;
    buf_len_ = 0;
    if (key && key_len > 0) {
        std::memset(buf_, 0, sizeof(buf_));
        std::memcpy(buf_, key, key_len);
        buf_len_ = 128;
    }
}

void Blake2b::Update(const void* data, size_t len) noexcept {
    const auto* p = static_cast<const uint8_t*>(data);
    while (len > 0) {
        if (buf_len_ == 128) {
            t_[0] += 128;
            if (t_[0] < 128) ++t_[1];
            Blake2bCompress(h_, t_[0], t_[1], buf_, false);
            buf_len_ = 0;
        }
        const size_t n = std::min<size_t>(128 - buf_len_, len);
        std::memcpy(buf_ + buf_len_, p, n);
        buf_len_ += n;
        p += n;
        len -= n;
    }
}

void Blake2b::Final(uint8_t* out) noexcept {
    t_[0] += static_cast<uint64_t>(buf_len_);
    if (t_[0] < buf_len_) ++t_[1];
    while (buf_len_ < 128) buf_[buf_len_++] = 0;
    Blake2bCompress(h_, t_[0], t_[1], buf_, true);
    uint8_t full[64];
    for (int i = 0; i < 8; ++i) StoreLe64(full + i * 8, h_[i]);
    std::memcpy(out, full, out_len_);
}

void Blake2b::Digest(const uint8_t* key, size_t key_len, const void* data, size_t len, uint8_t* out, size_t out_len) noexcept {
    Blake2b ctx;
    ctx.Init(out_len, key, key_len);
    if (len > 0 && data) ctx.Update(data, len);
    ctx.Final(out);
}

void Shake128::Init() noexcept {
    std::memset(state_, 0, sizeof(state_));
    pos_ = 0;
    finalized_ = false;
}

void Shake128::Update(const void* data, size_t len) noexcept {
    if (finalized_ || !data || len == 0) return;
    const auto* p = static_cast<const uint8_t*>(data);
    constexpr size_t kRate = 168;
    while (len > 0) {
        const size_t lane_idx = pos_ / 8;
        const size_t byte_off = pos_ % 8;
        state_[lane_idx] ^= static_cast<uint64_t>(*p++) << (byte_off * 8);
        ++pos_;
        --len;
        if (pos_ == kRate) {
            KeccakF1600(state_);
            pos_ = 0;
        }
    }
}

void Shake128::Final() noexcept {
    if (finalized_) return;
    constexpr size_t kRate = 168;
    state_[pos_ / 8] ^= static_cast<uint64_t>(0x1Fu) << ((pos_ % 8) * 8);
    state_[(kRate - 1) / 8] ^= static_cast<uint64_t>(0x80u) << (((kRate - 1) % 8) * 8);
    KeccakF1600(state_);
    pos_ = 0;
    finalized_ = true;
}

void Shake128::Squeeze(uint8_t* out, size_t len) noexcept {
    if (!finalized_) Final();
    if (!out || len == 0) return;
    constexpr size_t kRate = 168;
    size_t i = 0;
    while (i < len) {
        if (pos_ == kRate) {
            KeccakF1600(state_);
            pos_ = 0;
        }
        out[i++] = static_cast<uint8_t>((state_[pos_ / 8] >> ((pos_ % 8) * 8)) & 0xFFu);
        ++pos_;
    }
}

void Blake3::InitWithKeyWords(const uint32_t key_words[8], uint32_t flags) noexcept {
    std::memcpy(key_words_, key_words, 32);
    flags_ = flags;
    std::memcpy(chunk_cv_, key_words, 32);
    chunk_counter_ = 0;
    chunk_buf_len_ = 0;
    chunk_blocks_compressed_ = 0;
    cv_stack_len_ = 0;
}

void Blake3::Init() noexcept {
    InitWithKeyWords(kBlake3Iv, 0);
}

void Blake3::InitKeyed(const uint8_t key[32]) noexcept {
    uint32_t kw[8];
    for (int i = 0; i < 8; ++i) kw[i] = LoadLe32(key + i * 4);
    InitWithKeyWords(kw, kBlake3KeyedHash);
}

void Blake3::InitDeriveKey(std::string_view context) noexcept {
    Blake3 ctx_hasher;
    ctx_hasher.InitWithKeyWords(kBlake3Iv, kBlake3DeriveCtx);
    if (!context.empty()) ctx_hasher.Update(context.data(), context.size());
    uint8_t ctx_key[32]{};
    ctx_hasher.Final(ctx_key, 32);
    uint32_t kw[8];
    for (int i = 0; i < 8; ++i) kw[i] = LoadLe32(ctx_key + i * 4);
    InitWithKeyWords(kw, kBlake3DeriveMat);
}

void Blake3::AddChunkChainingValue(uint32_t cv[8], uint64_t total_chunks) noexcept {
    while ((total_chunks & 1ULL) == 0ULL && cv_stack_len_ > 0) {
        --cv_stack_len_;
        const Blake3Output parent = Blake3ParentOutput(cv_stack_[cv_stack_len_], cv, key_words_, flags_);
        parent.ChainingValue(cv);
        total_chunks >>= 1;
    }
    if (cv_stack_len_ < kMaxDepth) {
        std::memcpy(cv_stack_[cv_stack_len_++], cv, 32);
    }
}

void Blake3::Update(const void* data, size_t len) noexcept {
    const auto* p = static_cast<const uint8_t*>(data);
    while (len > 0) {
        if (chunk_blocks_compressed_ * 64u + chunk_buf_len_ == 1024u) {
            uint32_t w[16];
            const uint32_t bflags = flags_ | kBlake3ChunkEnd;
            Blake3Compress(chunk_cv_, chunk_buf_, 64, chunk_counter_, bflags, w);
            uint32_t done_cv[8];
            std::memcpy(done_cv, w, 32);
            ++chunk_counter_;
            AddChunkChainingValue(done_cv, chunk_counter_);
            std::memcpy(chunk_cv_, key_words_, 32);
            chunk_buf_len_ = 0;
            chunk_blocks_compressed_ = 0;
        }
        if (chunk_buf_len_ == 64) {
            uint32_t w[16];
            uint32_t bflags = flags_;
            if (chunk_blocks_compressed_ == 0) bflags |= kBlake3ChunkStart;
            Blake3Compress(chunk_cv_, chunk_buf_, 64, chunk_counter_, bflags, w);
            std::memcpy(chunk_cv_, w, 32);
            ++chunk_blocks_compressed_;
            chunk_buf_len_ = 0;
        }
        const size_t n = std::min<size_t>(64u - chunk_buf_len_, len);
        std::memcpy(chunk_buf_ + chunk_buf_len_, p, n);
        chunk_buf_len_ = static_cast<uint8_t>(chunk_buf_len_ + n);
        p += n;
        len -= n;
    }
}

void Blake3::Final(uint8_t* out, size_t out_len) const noexcept {
    if (!out || out_len == 0) return;
    Blake3Output output{};
    std::memcpy(output.input_cv, chunk_cv_, 32);
    std::memset(output.block, 0, sizeof(output.block));
    std::memcpy(output.block, chunk_buf_, chunk_buf_len_);
    output.block_len = chunk_buf_len_;
    output.counter = chunk_counter_;
    output.flags = flags_ | kBlake3ChunkEnd | ((chunk_blocks_compressed_ == 0) ? kBlake3ChunkStart : 0u);

    uint8_t stack_idx = cv_stack_len_;
    while (stack_idx > 0) {
        --stack_idx;
        uint32_t right_cv[8];
        output.ChainingValue(right_cv);
        output = Blake3ParentOutput(cv_stack_[stack_idx], right_cv, key_words_, flags_);
    }
    output.RootBytes(out, out_len);
}

void Blake3::Digest(const void* data, size_t len, uint8_t* out, size_t out_len) noexcept {
    Blake3 ctx;
    ctx.Init();
    if (len > 0 && data) ctx.Update(data, len);
    ctx.Final(out, out_len);
}

void Blake3::DigestKeyed(const uint8_t key[32], const void* data, size_t len, uint8_t* out, size_t out_len) noexcept {
    Blake3 ctx;
    ctx.InitKeyed(key);
    if (len > 0 && data) ctx.Update(data, len);
    ctx.Final(out, out_len);
}

void Blake3::DeriveKey(std::string_view context, const void* material, size_t mat_len, uint8_t* out, size_t out_len) noexcept {
    Blake3 ctx;
    ctx.InitDeriveKey(context);
    if (mat_len > 0 && material) ctx.Update(material, mat_len);
    ctx.Final(out, out_len);
}

uint32_t Crc32Ieee(const void* data, size_t len) noexcept {
    const auto* p = static_cast<const uint8_t*>(data);
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        c ^= p[i];
        for (int b = 0; b < 8; ++b) {
            c = (c >> 1) ^ ((c & 1u) ? 0xEDB88320u : 0u);
        }
    }
    return ~c;
}

uint32_t Fnv1a32(const void* data, size_t len) noexcept {
    const auto* p = static_cast<const uint8_t*>(data);
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}

// ---------------- Hash implementations ----------------

void Sha256::Init() noexcept {
    state_[0] = 0x6a09e667u; state_[1] = 0xbb67ae85u; state_[2] = 0x3c6ef372u; state_[3] = 0xa54ff53au;
    state_[4] = 0x510e527fu; state_[5] = 0x9b05688cu; state_[6] = 0x1f83d9abu; state_[7] = 0x5be0cd19u;
    total_bytes_ = 0;
    buf_len_ = 0;
}

void Sha256::Update(const void* data, size_t len) noexcept {
    const auto* p = static_cast<const uint8_t*>(data);
    total_bytes_ += len;
    if (buf_len_ > 0) {
        const size_t n = std::min<size_t>(64 - buf_len_, len);
        std::memcpy(buf_ + buf_len_, p, n);
        buf_len_ += n;
        p += n;
        len -= n;
        if (buf_len_ == 64) {
            Sha256Transform(state_, buf_);
            buf_len_ = 0;
        }
    }
    while (len >= 64) {
        Sha256Transform(state_, p);
        p += 64;
        len -= 64;
    }
    if (len > 0) {
        std::memcpy(buf_, p, len);
        buf_len_ = len;
    }
}

void Sha256::Final(uint8_t out[32]) noexcept {
    const uint64_t total_bits = total_bytes_ * 8ULL;
    const uint8_t pad_80 = 0x80;
    Update(&pad_80, 1);
    const uint8_t zero = 0x00;
    while (buf_len_ != 56) {
        Update(&zero, 1);
    }
    uint8_t len_be[8];
    StoreBe64(len_be, total_bits);
    buf_len_ = 56;
    std::memcpy(buf_ + 56, len_be, 8);
    Sha256Transform(state_, buf_);
    for (int i = 0; i < 8; ++i) StoreBe32(out + i * 4, state_[i]);
}

void Sha256::Digest(const void* data, size_t len, uint8_t out[32]) noexcept {
    Sha256 ctx;
    ctx.Init();
    if (len > 0 && data) ctx.Update(data, len);
    ctx.Final(out);
}

void Sha512::Init(bool is_sha384) noexcept {
    if (is_sha384) {
        state_[0] = 0xcbbb9d5dc1059ed8ULL; state_[1] = 0x629a292a367cd507ULL;
        state_[2] = 0x9159015a3070dd17ULL; state_[3] = 0x152fecd8f70e5939ULL;
        state_[4] = 0x67332667ffc00b31ULL; state_[5] = 0x8eb44a8768581511ULL;
        state_[6] = 0xdb0c2e0d64f98fa7ULL; state_[7] = 0x47b5481dbefa4fa4ULL;
    } else {
        state_[0] = 0x6a09e667f3bcc908ULL; state_[1] = 0xbb67ae8584caa73bULL;
        state_[2] = 0x3c6ef372fe94f82bULL; state_[3] = 0xa54ff53a5f1d36f1ULL;
        state_[4] = 0x510e527fade682d1ULL; state_[5] = 0x9b05688c2b3e6c1fULL;
        state_[6] = 0x1f83d9abfb41bd6bULL; state_[7] = 0x5be0cd19137e2179ULL;
    }
    total_lo_ = 0;
    total_hi_ = 0;
    buf_len_ = 0;
}

void Sha512::Update(const void* data, size_t len) noexcept {
    const auto* p = static_cast<const uint8_t*>(data);
    const uint64_t prev = total_lo_;
    total_lo_ += len;
    if (total_lo_ < prev) ++total_hi_;
    if (buf_len_ > 0) {
        const size_t n = std::min<size_t>(128 - buf_len_, len);
        std::memcpy(buf_ + buf_len_, p, n);
        buf_len_ += n;
        p += n;
        len -= n;
        if (buf_len_ == 128) {
            Sha512Transform(state_, buf_);
            buf_len_ = 0;
        }
    }
    while (len >= 128) {
        Sha512Transform(state_, p);
        p += 128;
        len -= 128;
    }
    if (len > 0) {
        std::memcpy(buf_, p, len);
        buf_len_ = len;
    }
}

void Sha512::Final(uint8_t* out, size_t out_len) noexcept {
    const uint64_t bits_lo = total_lo_ << 3;
    const uint64_t bits_hi = (total_hi_ << 3) | (total_lo_ >> 61);
    const uint8_t pad_80 = 0x80;
    Update(&pad_80, 1);
    const uint8_t zero = 0x00;
    while (buf_len_ != 112) {
        Update(&zero, 1);
    }
    StoreBe64(buf_ + 112, bits_hi);
    StoreBe64(buf_ + 120, bits_lo);
    Sha512Transform(state_, buf_);
    uint8_t full[64];
    for (int i = 0; i < 8; ++i) StoreBe64(full + i * 8, state_[i]);
    std::memcpy(out, full, std::min<size_t>(out_len, 64));
}

void Sha512::Digest512(const void* data, size_t len, uint8_t out[64]) noexcept {
    Sha512 ctx;
    ctx.Init(false);
    if (len > 0 && data) ctx.Update(data, len);
    ctx.Final(out, 64);
}

void Sha512::Digest384(const void* data, size_t len, uint8_t out[48]) noexcept {
    Sha512 ctx;
    ctx.Init(true);
    if (len > 0 && data) ctx.Update(data, len);
    ctx.Final(out, 48);
}

void Blake2s::Init(size_t out_len, const uint8_t* key, size_t key_len) noexcept {
    out_len_ = std::clamp<size_t>(out_len, 1, 32);
    key_len = std::min<size_t>(key_len, 32);
    for (int i = 0; i < 8; ++i) h_[i] = kBlake2sIv[i];
    h_[0] ^= 0x01010000u | (static_cast<uint32_t>(key_len) << 8) | static_cast<uint32_t>(out_len_);
    t_[0] = 0;
    t_[1] = 0;
    buf_len_ = 0;
    if (key && key_len > 0) {
        std::memset(buf_, 0, sizeof(buf_));
        std::memcpy(buf_, key, key_len);
        buf_len_ = 64;
    }
}

void Blake2s::Update(const void* data, size_t len) noexcept {
    const auto* p = static_cast<const uint8_t*>(data);
    while (len > 0) {
        if (buf_len_ == 64) {
            t_[0] += 64;
            if (t_[0] < 64) ++t_[1];
            Blake2sCompress(h_, t_[0], t_[1], buf_, false);
            buf_len_ = 0;
        }
        const size_t n = std::min<size_t>(64 - buf_len_, len);
        std::memcpy(buf_ + buf_len_, p, n);
        buf_len_ += n;
        p += n;
        len -= n;
    }
}

void Blake2s::Final(uint8_t* out) noexcept {
    t_[0] += static_cast<uint32_t>(buf_len_);
    if (t_[0] < buf_len_) ++t_[1];
    while (buf_len_ < 64) buf_[buf_len_++] = 0;
    Blake2sCompress(h_, t_[0], t_[1], buf_, true);
    uint8_t full[32];
    for (int i = 0; i < 8; ++i) StoreLe32(full + i * 4, h_[i]);
    std::memcpy(out, full, out_len_);
}

void Blake2s::Digest(const uint8_t* key, size_t key_len, const void* data, size_t len, uint8_t* out, size_t out_len) noexcept {
    Blake2s ctx;
    ctx.Init(out_len, key, key_len);
    if (len > 0 && data) ctx.Update(data, len);
    ctx.Final(out);
}

// ---------------- HMAC / HKDF ----------------

void HmacSha1(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t out[20]) noexcept {
    uint8_t k0[64]{};
    if (key && key_len > 64) {
        Sha1::Digest(key, key_len, k0);
    } else if (key && key_len > 0) {
        std::memcpy(k0, key, key_len);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k0[i] ^ 0x36u;
        opad[i] = k0[i] ^ 0x5cu;
    }
    uint8_t inner[20];
    Sha1 h;
    h.Init();
    h.Update(ipad, 64);
    if (data && data_len > 0) h.Update(data, data_len);
    h.Final(inner);

    h.Init();
    h.Update(opad, 64);
    h.Update(inner, 20);
    h.Final(out);
}

void HkdfExtractSha1(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[20]) noexcept {
    uint8_t zeros[20]{};
    if (!salt || salt_len == 0) {
        salt = zeros;
        salt_len = 20;
    }
    HmacSha1(salt, salt_len, ikm, ikm_len, prk);
}

bool HkdfExpandSha1(const uint8_t prk[20], const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) noexcept {
    if (okm_len > 255u * 20u) return false;
    uint8_t t[20]{};
    size_t t_len = 0;
    size_t out_off = 0;
    uint8_t ctr = 1;
    std::vector<uint8_t> buf;
    buf.reserve(20 + info_len + 1);
    while (out_off < okm_len) {
        buf.clear();
        buf.insert(buf.end(), t, t + t_len);
        if (info && info_len > 0) buf.insert(buf.end(), info, info + info_len);
        buf.push_back(ctr++);
        HmacSha1(prk, 20, buf.data(), buf.size(), t);
        t_len = 20;
        const size_t n = std::min<size_t>(20, okm_len - out_off);
        std::memcpy(okm + out_off, t, n);
        out_off += n;
    }
    return true;
}

void EvpBytesToKeyMd5(const uint8_t* pass, size_t pass_len, uint8_t* out_key, size_t key_len) noexcept {
    if (!out_key || key_len == 0) return;
    uint8_t d[16]{};
    bool has_prev = false;
    size_t off = 0;
    while (off < key_len) {
        Md5 ctx;
        ctx.Init();
        if (has_prev) ctx.Update(d, 16);
        if (pass && pass_len > 0) ctx.Update(pass, pass_len);
        ctx.Final(d);
        has_prev = true;
        const size_t n = std::min<size_t>(16, key_len - off);
        std::memcpy(out_key + off, d, n);
        off += n;
    }
}

void HmacSha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t out[32]) noexcept {
    uint8_t k0[64]{};
    if (key && key_len > 64) {
        Sha256::Digest(key, key_len, k0);
    } else if (key && key_len > 0) {
        std::memcpy(k0, key, key_len);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k0[i] ^ 0x36u;
        opad[i] = k0[i] ^ 0x5cu;
    }
    uint8_t inner[32];
    Sha256 h;
    h.Init();
    h.Update(ipad, 64);
    if (data && data_len > 0) h.Update(data, data_len);
    h.Final(inner);

    h.Init();
    h.Update(opad, 64);
    h.Update(inner, 32);
    h.Final(out);
}

void HmacSha384(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t out[48]) noexcept {
    uint8_t k0[128]{};
    if (key && key_len > 128) {
        Sha512::Digest384(key, key_len, k0);
    } else if (key && key_len > 0) {
        std::memcpy(k0, key, key_len);
    }
    uint8_t ipad[128], opad[128];
    for (int i = 0; i < 128; ++i) {
        ipad[i] = k0[i] ^ 0x36u;
        opad[i] = k0[i] ^ 0x5cu;
    }
    uint8_t inner[48];
    Sha512 h;
    h.Init(true);
    h.Update(ipad, 128);
    if (data && data_len > 0) h.Update(data, data_len);
    h.Final(inner, 48);

    h.Init(true);
    h.Update(opad, 128);
    h.Update(inner, 48);
    h.Final(out, 48);
}

void HmacSha512(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t out[64]) noexcept {
    uint8_t k0[128]{};
    if (key && key_len > 128) {
        Sha512::Digest512(key, key_len, k0);
    } else if (key && key_len > 0) {
        std::memcpy(k0, key, key_len);
    }
    uint8_t ipad[128], opad[128];
    for (int i = 0; i < 128; ++i) {
        ipad[i] = k0[i] ^ 0x36u;
        opad[i] = k0[i] ^ 0x5cu;
    }
    uint8_t inner[64];
    Sha512 h;
    h.Init(false);
    h.Update(ipad, 128);
    if (data && data_len > 0) h.Update(data, data_len);
    h.Final(inner, 64);

    h.Init(false);
    h.Update(opad, 128);
    h.Update(inner, 64);
    h.Final(out, 64);
}

void HkdfExtractSha256(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[32]) noexcept {
    uint8_t zeros[32]{};
    if (!salt || salt_len == 0) {
        salt = zeros;
        salt_len = 32;
    }
    HmacSha256(salt, salt_len, ikm, ikm_len, prk);
}

bool HkdfExpandSha256(const uint8_t prk[32], const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) noexcept {
    if (okm_len > 255u * 32u) return false;
    uint8_t t[32]{};
    size_t t_len = 0;
    size_t out_off = 0;
    uint8_t ctr = 1;
    std::vector<uint8_t> buf;
    buf.reserve(32 + info_len + 1);
    while (out_off < okm_len) {
        buf.clear();
        buf.insert(buf.end(), t, t + t_len);
        if (info && info_len > 0) buf.insert(buf.end(), info, info + info_len);
        buf.push_back(ctr++);
        HmacSha256(prk, 32, buf.data(), buf.size(), t);
        t_len = 32;
        const size_t n = std::min<size_t>(32, okm_len - out_off);
        std::memcpy(okm + out_off, t, n);
        out_off += n;
    }
    return true;
}

void HkdfExtractSha384(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t prk[48]) noexcept {
    uint8_t zeros[48]{};
    if (!salt || salt_len == 0) {
        salt = zeros;
        salt_len = 48;
    }
    HmacSha384(salt, salt_len, ikm, ikm_len, prk);
}

bool HkdfExpandSha384(const uint8_t prk[48], const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) noexcept {
    if (okm_len > 255u * 48u) return false;
    uint8_t t[48]{};
    size_t t_len = 0;
    size_t out_off = 0;
    uint8_t ctr = 1;
    std::vector<uint8_t> buf;
    buf.reserve(48 + info_len + 1);
    while (out_off < okm_len) {
        buf.clear();
        buf.insert(buf.end(), t, t + t_len);
        if (info && info_len > 0) buf.insert(buf.end(), info, info + info_len);
        buf.push_back(ctr++);
        HmacSha384(prk, 48, buf.data(), buf.size(), t);
        t_len = 48;
        const size_t n = std::min<size_t>(48, okm_len - out_off);
        std::memcpy(okm + out_off, t, n);
        out_off += n;
    }
    return true;
}

bool Tls13HkdfExpandLabel(bool use_sha384,
                          const uint8_t* secret,
                          std::string_view label,
                          const uint8_t* context,
                          size_t context_len,
                          uint8_t* out,
                          size_t out_len) noexcept {
    std::vector<uint8_t> hkdf_label;
    hkdf_label.reserve(10 + label.size() + context_len);
    hkdf_label.push_back(uint8_t((out_len >> 8) & 0xFFu));
    hkdf_label.push_back(uint8_t(out_len & 0xFFu));
    hkdf_label.push_back(uint8_t(6 + label.size()));
    const char* prefix = "tls13 ";
    hkdf_label.insert(hkdf_label.end(), prefix, prefix + 6);
    hkdf_label.insert(hkdf_label.end(), label.begin(), label.end());
    hkdf_label.push_back(uint8_t(context_len & 0xFFu));
    if (context && context_len > 0) {
        hkdf_label.insert(hkdf_label.end(), context, context + context_len);
    }
    if (use_sha384) {
        return HkdfExpandSha384(secret, hkdf_label.data(), hkdf_label.size(), out, out_len);
    }
    return HkdfExpandSha256(secret, hkdf_label.data(), hkdf_label.size(), out, out_len);
}

// ---------------- X25519 ----------------

bool X25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u_coord[32]) noexcept {
    uint8_t z[32];
    std::memcpy(z, scalar, 32);
    z[0] &= 248;
    z[31] &= 127;
    z[31] |= 64;

    Gf x, a{}, b{}, c{}, d{}, e, f;
    Unpack25519(x, u_coord);
    a[0] = 1;
    d[0] = 1;
    for (int i = 0; i < 16; ++i) b[i] = x[i];

    Gf _121665{};
    _121665[0] = 0xdb41;
    _121665[1] = 1;

    for (int i = 254; i >= 0; --i) {
        const int r = (z[i >> 3] >> (i & 7)) & 1;
        Sel25519(a, b, r);
        Sel25519(c, d, r);
        GfAdd(e, a, c);
        GfSub(a, a, c);
        GfAdd(c, b, d);
        GfSub(b, b, d);
        GfSq(d, e);
        GfSq(f, a);
        GfMul(a, c, a);
        GfMul(c, b, e);
        GfAdd(e, a, c);
        GfSub(a, a, c);
        GfSq(b, a);
        GfSub(c, d, f);
        GfMul(a, c, _121665);
        GfAdd(a, a, d);
        GfMul(c, c, a);
        GfMul(a, d, f);
        GfMul(d, b, x);
        GfSq(b, e);
        Sel25519(a, b, r);
        Sel25519(c, d, r);
    }
    Inv25519(c, c);
    GfMul(a, a, c);
    Pack25519(out, a);

    uint8_t nonzero = 0;
    for (int i = 0; i < 32; ++i) nonzero |= out[i];
    return nonzero != 0;
}

void X25519Base(uint8_t out_pub[32], const uint8_t scalar[32]) noexcept {
    static constexpr uint8_t kBase9[32] = {9};
    X25519(out_pub, scalar, kBase9);
}

// ---------------- AES-ECB & AES-GCM & ChaCha20 ----------------

bool AesEcbEncryptBlock(const uint8_t* key, size_t key_len, const uint8_t in[16], uint8_t out[16]) noexcept {
    AesKey aes{};
    if (!AesInit(aes, key, key_len)) return false;
    AesEncryptBlock(aes, in, out);
    return true;
}

void ChaCha20Xor(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12],
                 const uint8_t* in, size_t len, uint8_t* out) noexcept {
    ChaCha20XorInternal(key, counter, nonce, in, len, out);
}

bool AesGcmEncrypt(const uint8_t* key, size_t key_len, const uint8_t iv[12],
                   const uint8_t* aad, size_t aad_len, const uint8_t* pt, size_t len,
                   uint8_t* ct, uint8_t tag[16]) noexcept {
    AesKey aes{};
    if (!AesInit(aes, key, key_len)) return false;

    uint8_t H[16]{};
    const uint8_t zeros[16]{};
    AesEncryptBlock(aes, zeros, H);

    uint8_t j0[16]{};
    std::memcpy(j0, iv, 12);
    j0[15] = 1;

    uint8_t ctr[16];
    std::memcpy(ctr, j0, 16);
    uint32_t c_val = 2;
    size_t off = 0;
    while (off < len) {
        StoreBe32(ctr + 12, c_val++);
        uint8_t ks[16];
        AesEncryptBlock(aes, ctr, ks);
        const size_t n = std::min<size_t>(16, len - off);
        for (size_t i = 0; i < n; ++i) ct[off + i] = pt[off + i] ^ ks[i];
        off += n;
    }

    uint8_t s[16];
    Ghash(H, aad, aad_len, ct, len, s);
    uint8_t e0[16];
    AesEncryptBlock(aes, j0, e0);
    for (int i = 0; i < 16; ++i) tag[i] = s[i] ^ e0[i];
    return true;
}

bool AesGcmDecrypt(const uint8_t* key, size_t key_len, const uint8_t iv[12],
                   const uint8_t* aad, size_t aad_len, const uint8_t* ct, size_t len,
                   const uint8_t tag[16], uint8_t* pt) noexcept {
    AesKey aes{};
    if (!AesInit(aes, key, key_len)) return false;

    uint8_t H[16]{};
    const uint8_t zeros[16]{};
    AesEncryptBlock(aes, zeros, H);

    uint8_t j0[16]{};
    std::memcpy(j0, iv, 12);
    j0[15] = 1;

    uint8_t s[16];
    Ghash(H, aad, aad_len, ct, len, s);
    uint8_t e0[16];
    AesEncryptBlock(aes, j0, e0);
    uint8_t expected[16];
    for (int i = 0; i < 16; ++i) expected[i] = s[i] ^ e0[i];
    if (!ConstantTimeEqual(expected, tag, 16)) return false;

    uint8_t ctr[16];
    std::memcpy(ctr, j0, 16);
    uint32_t c_val = 2;
    size_t off = 0;
    while (off < len) {
        StoreBe32(ctr + 12, c_val++);
        uint8_t ks[16];
        AesEncryptBlock(aes, ctr, ks);
        const size_t n = std::min<size_t>(16, len - off);
        for (size_t i = 0; i < n; ++i) pt[off + i] = ct[off + i] ^ ks[i];
        off += n;
    }
    return true;
}

// ---------------- ChaCha20-Poly1305 ----------------

bool ChaCha20Poly1305Encrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t* aad, size_t aad_len, const uint8_t* pt, size_t len,
                             uint8_t* ct, uint8_t tag[16]) noexcept {
    uint8_t block0[64];
    ChaCha20Block(key, 0, nonce, block0);
    if (len > 0) ChaCha20XorInternal(key, 1, nonce, pt, len, ct);
    Poly1305TagAead(block0, aad, aad_len, ct, len, tag);
    return true;
}

bool ChaCha20Poly1305Decrypt(const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t* aad, size_t aad_len, const uint8_t* ct, size_t len,
                             const uint8_t tag[16], uint8_t* pt) noexcept {
    uint8_t block0[64];
    ChaCha20Block(key, 0, nonce, block0);
    uint8_t expected[16];
    Poly1305TagAead(block0, aad, aad_len, ct, len, expected);
    if (!ConstantTimeEqual(expected, tag, 16)) return false;
    if (len > 0) ChaCha20XorInternal(key, 1, nonce, ct, len, pt);
    return true;
}

std::string HexEncode(const uint8_t* data, size_t len) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0xFu]);
        out.push_back(kHex[data[i] & 0xFu]);
    }
    return out;
}

// ---------------- Text Codecs ----------------

std::string Base64Encode(const uint8_t* data, size_t len, bool url_safe, bool padding) {
    const char* alpha = url_safe
        ? "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        const uint32_t a = data[i];
        const uint32_t b = (i + 1 < len) ? data[i + 1] : 0;
        const uint32_t c = (i + 2 < len) ? data[i + 2] : 0;
        const uint32_t t = (a << 16) | (b << 8) | c;
        out.push_back(alpha[(t >> 18) & 0x3Fu]);
        out.push_back(alpha[(t >> 12) & 0x3Fu]);
        if (i + 1 < len) out.push_back(alpha[(t >> 6) & 0x3Fu]);
        else if (padding) out.push_back('=');
        if (i + 2 < len) out.push_back(alpha[t & 0x3Fu]);
        else if (padding) out.push_back('=');
    }
    return out;
}

std::optional<std::vector<uint8_t>> Base64Decode(std::string_view input) {
    auto val = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+' || c == '-') return 62;
        if (c == '/' || c == '_') return 63;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve((input.size() * 3) / 4);
    uint32_t acc = 0;
    int bits = 0;
    for (char ch : input) {
        if (ch == '=' || ch == '\r' || ch == '\n' || ch == ' ') continue;
        const int v = val(static_cast<unsigned char>(ch));
        if (v < 0) return std::nullopt;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFFu));
        }
    }
    return out;
}

std::optional<std::vector<uint8_t>> HexDecode(std::string_view hex) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    int hi = -1;
    for (char c : hex) {
        if (c == '-' || c == ' ' || c == ':') continue;
        const int n = nib(c);
        if (n < 0) return std::nullopt;
        if (hi < 0) hi = n;
        else {
            out.push_back(static_cast<uint8_t>((hi << 4) | n));
            hi = -1;
        }
    }
    if (hi >= 0) return std::nullopt;
    return out;
}

bool ParseUuidBytes(std::string_view uuid, uint8_t out[16]) noexcept {
    auto bytes = HexDecode(uuid);
    if (!bytes || bytes->size() != 16) return false;
    std::memcpy(out, bytes->data(), 16);
    return true;
}

}  // namespace yumi_nx::net::crypto
