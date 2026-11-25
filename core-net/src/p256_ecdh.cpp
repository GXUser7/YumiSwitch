#include "yumi_nx/crypto.hpp"

#include <cstring>

namespace yumi_nx::net::crypto {

namespace {

// NIST P-256 (secp256r1) field element in Montgomery domain as 8x 32-bit little-endian limbs.
struct Fe {
    uint32_t v[8]{};
};

// p = 2^256 - 2^224 + 2^192 + 2^96 - 1
constexpr Fe kP256P = {{
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u,
    0x00000000u, 0x00000000u, 0x00000001u, 0xFFFFFFFFu,
}};

// n = curve order
constexpr uint8_t kP256OrderBe[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
};

// R = 2^256 mod p = {1, 0, 0, FFFFFFFF, FFFFFFFF, FFFFFFFF, FFFFFFFE, 0}
constexpr Fe kMontOne = {{
    0x00000001u, 0x00000000u, 0x00000000u, 0xFFFFFFFFu,
    0xFFFFFFFFu, 0xFFFFFFFFu, 0xFFFFFFFEu, 0x00000000u,
}};

// Curve constant b in normal form (little-endian 32-bit limbs)
// 5AC635D8 AA3A93E7 B3EBBD55 769886BC 651D06B0 CC53B0F6 3BCE3C3E 27D2604B
constexpr Fe kCurveB = {{
    0x27D2604Bu, 0x3BCE3C3Eu, 0xCC53B0F6u, 0x651D06B0u,
    0x769886BCu, 0xB3EBBD55u, 0xAA3A93E7u, 0x5AC635D8u,
}};

// Base point Gx, Gy in normal form (little-endian 32-bit limbs)
// Gx = 6B17D1F2 E12C4247 F8BCE6E5 63A440F2 77037D81 2DEB33A0 F4A13945 D898C296
constexpr Fe kGx = {{
    0xD898C296u, 0xF4A13945u, 0x2DEB33A0u, 0x77037D81u,
    0x63A440F2u, 0xF8BCE6E5u, 0xE12C4247u, 0x6B17D1F2u,
}};
// Gy = 4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16 2BCE3357 6B315ECE CBB64068 37BF51F5
constexpr Fe kGy = {{
    0x37BF51F5u, 0xCBB64068u, 0x6B315ECEu, 0x2BCE3357u,
    0x7C0F9E16u, 0x8EE7EB4Au, 0xFE1A7F9Bu, 0x4FE342E2u,
}};

bool FeGte(const Fe& a, const Fe& b) noexcept {
    for (int i = 7; i >= 0; --i) {
        if (a.v[i] > b.v[i]) return true;
        if (a.v[i] < b.v[i]) return false;
    }
    return true;
}

bool FeIsZero(const Fe& a) noexcept {
    uint32_t x = 0;
    for (int i = 0; i < 8; ++i) x |= a.v[i];
    return x == 0;
}

Fe FeAdd(const Fe& a, const Fe& b) noexcept {
    Fe r{};
    uint64_t c = 0;
    for (int i = 0; i < 8; ++i) {
        const uint64_t s = uint64_t(a.v[i]) + b.v[i] + c;
        r.v[i] = static_cast<uint32_t>(s);
        c = s >> 32;
    }
    if (c != 0 || FeGte(r, kP256P)) {
        uint64_t borrow = 0;
        for (int i = 0; i < 8; ++i) {
            const uint64_t diff = uint64_t(r.v[i]) - kP256P.v[i] - borrow;
            r.v[i] = static_cast<uint32_t>(diff);
            borrow = (diff >> 63) & 1ULL;
        }
    }
    return r;
}

Fe FeSub(const Fe& a, const Fe& b) noexcept {
    Fe r{};
    uint64_t borrow = 0;
    for (int i = 0; i < 8; ++i) {
        const uint64_t diff = uint64_t(a.v[i]) - b.v[i] - borrow;
        r.v[i] = static_cast<uint32_t>(diff);
        borrow = (diff >> 63) & 1ULL;
    }
    if (borrow != 0) {
        uint64_t c = 0;
        for (int i = 0; i < 8; ++i) {
            const uint64_t s = uint64_t(r.v[i]) + kP256P.v[i] + c;
            r.v[i] = static_cast<uint32_t>(s);
            c = s >> 32;
        }
    }
    return r;
}

// Montgomery CIOS multiplication mod p; (-p)^-1 mod 2^32 == 1 because p[0] == 0xFFFFFFFF.
Fe FeMontMul(const Fe& a, const Fe& b) noexcept {
    uint32_t t[10]{};
    for (int i = 0; i < 8; ++i) {
        uint64_t c = 0;
        for (int j = 0; j < 8; ++j) {
            const uint64_t prod = uint64_t(a.v[i]) * b.v[j] + t[j] + c;
            t[j] = static_cast<uint32_t>(prod);
            c = prod >> 32;
        }
        const uint64_t top = uint64_t(t[8]) + c;
        t[8] = static_cast<uint32_t>(top);
        t[9] = static_cast<uint32_t>(top >> 32);

        const uint32_t m = t[0];  // * m0 (which is 1)
        uint64_t c2 = 0;
        uint64_t p0 = uint64_t(m) * kP256P.v[0] + t[0];
        c2 = p0 >> 32;
        for (int j = 1; j < 8; ++j) {
            const uint64_t s = uint64_t(m) * kP256P.v[j] + t[j] + c2;
            t[j - 1] = static_cast<uint32_t>(s);
            c2 = s >> 32;
        }
        const uint64_t s8 = uint64_t(t[8]) + c2;
        t[7] = static_cast<uint32_t>(s8);
        t[8] = t[9] + static_cast<uint32_t>(s8 >> 32);
        t[9] = 0;
    }

    Fe r{};
    for (int i = 0; i < 8; ++i) r.v[i] = t[i];
    if (t[8] != 0 || FeGte(r, kP256P)) {
        uint64_t borrow = 0;
        for (int i = 0; i < 8; ++i) {
            const uint64_t diff = uint64_t(r.v[i]) - kP256P.v[i] - borrow;
            r.v[i] = static_cast<uint32_t>(diff);
            borrow = (diff >> 63) & 1ULL;
        }
    }
    return r;
}

Fe FeMontSqr(const Fe& a) noexcept { return FeMontMul(a, a); }

const Fe& GetMontR2() noexcept {
    static const Fe r2 = []() {
        Fe acc = kMontOne;
        for (int i = 0; i < 256; ++i) acc = FeAdd(acc, acc);
        return acc;
    }();
    return r2;
}

Fe FeToMont(const Fe& a) noexcept { return FeMontMul(a, GetMontR2()); }
Fe FeFromMont(const Fe& a) noexcept {
    Fe one{};
    one.v[0] = 1;
    return FeMontMul(a, one);
}

// Modular inversion in Montgomery domain via Fermat's Little Theorem: a^(p - 2) mod p
Fe FeMontInv(const Fe& a) noexcept {
    Fe res = kMontOne;
    Fe base = a;
    for (int w = 0; w < 8; ++w) {
        uint32_t pw = kP256P.v[w];
        if (w == 0) pw -= 2u;  // p[0] is 0xFFFFFFFF -> 0xFFFFFFFD
        for (int bit = 0; bit < 32; ++bit) {
            if ((pw >> bit) & 1u) res = FeMontMul(res, base);
            base = FeMontSqr(base);
        }
    }
    return res;
}

Fe FeFromBytesBe(const uint8_t b[32]) noexcept {
    Fe out{};
    for (int i = 0; i < 8; ++i) {
        const int off = (7 - i) * 4;
        out.v[i] = (uint32_t(b[off]) << 24) | (uint32_t(b[off + 1]) << 16) |
                   (uint32_t(b[off + 2]) << 8) | uint32_t(b[off + 3]);
    }
    return out;
}

void FeToBytesBe(const Fe& a, uint8_t out[32]) noexcept {
    for (int i = 0; i < 8; ++i) {
        const int off = (7 - i) * 4;
        out[off]     = uint8_t((a.v[i] >> 24) & 0xFFu);
        out[off + 1] = uint8_t((a.v[i] >> 16) & 0xFFu);
        out[off + 2] = uint8_t((a.v[i] >> 8) & 0xFFu);
        out[off + 3] = uint8_t(a.v[i] & 0xFFu);
    }
}

struct JacPoint {
    Fe x{};
    Fe y{};
    Fe z{};  // z == 0 => infinity
};

JacPoint PointDouble(const JacPoint& p) noexcept {
    if (FeIsZero(p.z) || FeIsZero(p.y)) return {};

    // Jacobian doubling for a = -3
    const Fe delta = FeMontSqr(p.z);
    const Fe gamma = FeMontSqr(p.y);
    const Fe beta = FeMontMul(p.x, gamma);

    const Fe x_minus_d = FeSub(p.x, delta);
    const Fe x_plus_d = FeAdd(p.x, delta);
    const Fe xd_prod = FeMontMul(x_minus_d, x_plus_d);
    const Fe alpha = FeAdd(FeAdd(xd_prod, xd_prod), xd_prod);  // 3*(x^2 - z^4)

    const Fe two_beta = FeAdd(beta, beta);
    const Fe four_beta = FeAdd(two_beta, two_beta);
    const Fe eight_beta = FeAdd(four_beta, four_beta);

    JacPoint out{};
    out.x = FeSub(FeMontSqr(alpha), eight_beta);
    const Fe y_plus_z = FeAdd(p.y, p.z);
    out.z = FeSub(FeSub(FeMontSqr(y_plus_z), gamma), delta);

    const Fe g_sq = FeMontSqr(gamma);
    const Fe two_g_sq = FeAdd(g_sq, g_sq);
    const Fe four_g_sq = FeAdd(two_g_sq, two_g_sq);
    const Fe eight_g_sq = FeAdd(four_g_sq, four_g_sq);
    out.y = FeSub(FeMontMul(alpha, FeSub(four_beta, out.x)), eight_g_sq);
    return out;
}

JacPoint PointAddAffine(const JacPoint& p, const Fe& qx_m, const Fe& qy_m) noexcept {
    if (FeIsZero(p.z)) {
        return {qx_m, qy_m, kMontOne};
    }

    const Fe z1z1 = FeMontSqr(p.z);
    const Fe u2 = FeMontMul(qx_m, z1z1);
    const Fe s2 = FeMontMul(qy_m, FeMontMul(p.z, z1z1));

    const Fe h = FeSub(u2, p.x);
    const Fe hh = FeMontSqr(h);
    const Fe i = FeAdd(FeAdd(hh, hh), FeAdd(hh, hh));  // 4*H^2
    const Fe j = FeMontMul(h, i);
    const Fe r_tmp = FeSub(s2, p.y);
    const Fe r = FeAdd(r_tmp, r_tmp);

    if (FeIsZero(h)) {
        if (FeIsZero(r_tmp)) return PointDouble(p);
        return {};  // P == -Q -> infinity
    }

    const Fe v = FeMontMul(p.x, i);
    const Fe two_v = FeAdd(v, v);

    JacPoint out{};
    out.x = FeSub(FeSub(FeMontSqr(r), j), two_v);
    const Fe p_y_j = FeMontMul(p.y, j);
    out.y = FeSub(FeMontMul(r, FeSub(v, out.x)), FeAdd(p_y_j, p_y_j));
    const Fe z_plus_h = FeAdd(p.z, h);
    out.z = FeSub(FeSub(FeMontSqr(z_plus_h), z1z1), hh);
    return out;
}

bool CheckScalarValid(const uint8_t priv[32]) noexcept {
    uint8_t nz = 0;
    for (int i = 0; i < 32; ++i) nz |= priv[i];
    if (nz == 0) return false;
    // Must be strictly less than order n
    for (int i = 0; i < 32; ++i) {
        if (priv[i] < kP256OrderBe[i]) return true;
        if (priv[i] > kP256OrderBe[i]) return false;
    }
    return false;
}

bool ValidatePointAffine(const uint8_t pub65[65], Fe& out_x_m, Fe& out_y_m) noexcept {
    if (!pub65 || pub65[0] != 0x04) return false;
    const Fe x = FeFromBytesBe(pub65 + 1);
    const Fe y = FeFromBytesBe(pub65 + 33);
    if (FeGte(x, kP256P) || FeGte(y, kP256P)) return false;

    out_x_m = FeToMont(x);
    out_y_m = FeToMont(y);
    const Fe b_m = FeToMont(kCurveB);

    // Check y^2 == x^3 - 3x + b mod p
    const Fe yy = FeMontSqr(out_y_m);
    const Fe x3 = FeMontMul(FeMontSqr(out_x_m), out_x_m);
    const Fe three_x = FeAdd(FeAdd(out_x_m, out_x_m), out_x_m);
    const Fe rhs = FeAdd(FeSub(x3, three_x), b_m);
    return std::memcmp(yy.v, rhs.v, sizeof(yy.v)) == 0;
}

bool ScalarMul(const uint8_t scalar[32], const Fe& px_m, const Fe& py_m, uint8_t out_x[32], uint8_t* out_y_opt) noexcept {
    JacPoint acc{};
    for (int byte_i = 0; byte_i < 32; ++byte_i) {
        const uint8_t b = scalar[byte_i];
        for (int bit = 7; bit >= 0; --bit) {
            if (!FeIsZero(acc.z)) acc = PointDouble(acc);
            if ((b >> bit) & 1u) {
                acc = PointAddAffine(acc, px_m, py_m);
            }
        }
    }
    if (FeIsZero(acc.z)) return false;

    const Fe z_inv = FeMontInv(acc.z);
    const Fe z_inv2 = FeMontSqr(z_inv);
    const Fe ax_m = FeMontMul(acc.x, z_inv2);
    FeToBytesBe(FeFromMont(ax_m), out_x);

    if (out_y_opt) {
        const Fe z_inv3 = FeMontMul(z_inv2, z_inv);
        const Fe ay_m = FeMontMul(acc.y, z_inv3);
        FeToBytesBe(FeFromMont(ay_m), out_y_opt);
    }
    return true;
}

// ASN.1 X.509 SubjectPublicKeyInfo header for P-256 (91 bytes total = 26-byte header + 65-byte uncompressed point)
constexpr uint8_t kP256SpkiHeader[26] = {
    0x30, 0x59,
    0x30, 0x13,
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
    0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00,
};

}  // namespace

bool P256PublicFromPrivate(const uint8_t priv[32], uint8_t out_pub65[65]) noexcept {
    if (!priv || !out_pub65 || !CheckScalarValid(priv)) return false;
    const Fe gx_m = FeToMont(kGx);
    const Fe gy_m = FeToMont(kGy);
    out_pub65[0] = 0x04;
    return ScalarMul(priv, gx_m, gy_m, out_pub65 + 1, out_pub65 + 33);
}

bool P256GenerateKeyPair(P256KeyPair& out) noexcept {
    for (int attempt = 0; attempt < 32; ++attempt) {
        if (!RandomBytes(out.priv, 32)) return false;
        if (P256PublicFromPrivate(out.priv, out.pub65)) return true;
    }
    return false;
}

bool P256Ecdh(uint8_t out_shared32[32], const uint8_t priv[32], const uint8_t peer_pub65[65]) noexcept {
    if (!out_shared32 || !priv || !peer_pub65 || !CheckScalarValid(priv)) return false;
    Fe qx_m{}, qy_m{};
    if (!ValidatePointAffine(peer_pub65, qx_m, qy_m)) return false;
    return ScalarMul(priv, qx_m, qy_m, out_shared32, nullptr);
}

std::vector<uint8_t> P256EncodeSpkiDer(const uint8_t pub65[65]) {
    std::vector<uint8_t> der(91, 0);
    std::memcpy(der.data(), kP256SpkiHeader, sizeof(kP256SpkiHeader));
    if (pub65) std::memcpy(der.data() + sizeof(kP256SpkiHeader), pub65, 65);
    return der;
}

bool P256DecodeSpkiDer(const uint8_t* der, size_t len, uint8_t out_pub65[65]) noexcept {
    if (!der || !out_pub65 || len != 91u) return false;
    if (std::memcmp(der, kP256SpkiHeader, sizeof(kP256SpkiHeader)) != 0) return false;
    std::memcpy(out_pub65, der + sizeof(kP256SpkiHeader), 65);
    Fe x_m{}, y_m{};
    return ValidatePointAffine(out_pub65, x_m, y_m);
}

}  // namespace yumi_nx::net::crypto
