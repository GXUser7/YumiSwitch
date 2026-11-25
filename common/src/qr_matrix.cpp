#include "yumi_nx/qr_matrix.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <vector>

namespace yumi_nx {

namespace {

struct GfTables {
    std::array<uint8_t, 512> exp{};
    std::array<uint8_t, 256> log{};

    constexpr GfTables() noexcept {
        int x = 1;
        for (int i = 0; i < 255; ++i) {
            exp[static_cast<size_t>(i)] = static_cast<uint8_t>(x);
            exp[static_cast<size_t>(i + 255)] = static_cast<uint8_t>(x);
            log[static_cast<size_t>(x)] = static_cast<uint8_t>(i);
            x <<= 1;
            if (x & 0x100) x ^= 0x11d;
        }
    }
};

inline constexpr GfTables kGf{};

constexpr uint8_t GfMul(uint8_t a, uint8_t b) noexcept {
    if (a == 0 || b == 0) return 0;
    return kGf.exp[static_cast<size_t>(kGf.log[a]) + static_cast<size_t>(kGf.log[b])];
}

std::vector<uint8_t> RsEncode(const uint8_t* data, size_t data_len, size_t ec_len) {
    std::vector<uint8_t> gen(ec_len + 1, 0);
    gen[0] = 1;
    size_t gen_len = 1;
    for (size_t i = 0; i < ec_len; ++i) {
        const uint8_t root = kGf.exp[i];
        for (size_t j = gen_len; j > 0; --j) {
            gen[j] ^= GfMul(gen[j - 1], root);
        }
        ++gen_len;
    }

    std::vector<uint8_t> res(data_len + ec_len, 0);
    for (size_t i = 0; i < data_len; ++i) res[i] = data[i];

    for (size_t i = 0; i < data_len; ++i) {
        const uint8_t coef = res[i];
        if (coef != 0) {
            for (size_t j = 0; j <= ec_len; ++j) {
                res[i + j] ^= GfMul(gen[j], coef);
            }
        }
    }
    return std::vector<uint8_t>(res.begin() + static_cast<ptrdiff_t>(data_len), res.end());
}

struct VersionEcSpec {
    uint16_t total_cw;
    uint8_t ec_per_block;
    uint8_t b1;
    uint8_t d1;
    uint8_t b2;
    uint8_t d2;

    [[nodiscard]] size_t DataCodewords() const noexcept {
        return static_cast<size_t>(b1) * d1 + static_cast<size_t>(b2) * d2;
    }
};

// ISO/IEC 18004 Versions 1..15, Error Correction Level M (bits = 00)
constexpr VersionEcSpec kSpecM[15] = {
    {26,  10, 1, 16, 0, 0},   // V1
    {44,  16, 1, 28, 0, 0},   // V2
    {70,  26, 1, 44, 0, 0},   // V3
    {100, 18, 2, 32, 0, 0},   // V4
    {134, 24, 2, 43, 0, 0},   // V5
    {172, 16, 4, 27, 0, 0},   // V6
    {196, 18, 4, 31, 0, 0},   // V7
    {242, 22, 2, 38, 2, 39},  // V8
    {292, 22, 3, 36, 2, 37},  // V9
    {346, 26, 4, 43, 1, 44},  // V10
    {404, 30, 1, 50, 4, 51},  // V11
    {466, 22, 6, 36, 2, 37},  // V12
    {532, 22, 8, 37, 1, 38},  // V13
    {581, 24, 4, 40, 5, 41},  // V14
    {655, 24, 5, 41, 5, 42},  // V15
};

// ISO/IEC 18004 Versions 1..15, Error Correction Level L (bits = 01)
constexpr VersionEcSpec kSpecL[15] = {
    {26,  7,  1, 19, 0, 0},   // V1
    {44,  10, 1, 34, 0, 0},   // V2
    {70,  15, 1, 55, 0, 0},   // V3
    {100, 20, 1, 80, 0, 0},   // V4
    {134, 26, 1, 108, 0, 0},  // V5
    {172, 18, 2, 68, 0, 0},   // V6
    {196, 20, 2, 78, 0, 0},   // V7
    {242, 24, 2, 97, 0, 0},   // V8
    {292, 30, 2, 116, 0, 0},  // V9
    {346, 18, 2, 68, 2, 69},  // V10
    {404, 20, 4, 81, 0, 0},   // V11
    {466, 24, 2, 92, 2, 93},  // V12
    {532, 26, 4, 107, 0, 0},  // V13
    {581, 30, 3, 115, 1, 116},// V14
    {655, 22, 5, 87, 1, 88},  // V15
};

std::vector<int> AlignmentCoords(int version) {
    if (version <= 1) return {};
    if (version <= 6) return {6, 4 * version + 10};
    if (version <= 13) return {6, 2 * version + 8, 4 * version + 10};
    if (version == 14) return {6, 26, 46, 66};
    return {6, 26, 48, 70};
}

uint16_t EncodeFormatBits(int ec_bits, int mask) noexcept {
    uint32_t data = static_cast<uint32_t>((ec_bits << 3) | (mask & 7));
    uint32_t rem = data << 10;
    for (int bit = 14; bit >= 10; --bit) {
        if ((rem >> bit) & 1u) {
            rem ^= (0x537u << (bit - 10));
        }
    }
    return static_cast<uint16_t>(((data << 10) | rem) ^ 0x5412u);
}

uint32_t EncodeVersionBch(int version) noexcept {
    uint32_t rem = static_cast<uint32_t>(version) << 12;
    for (int bit = 17; bit >= 12; --bit) {
        if ((rem >> bit) & 1u) {
            rem ^= (0x1F25u << (bit - 12));
        }
    }
    return (static_cast<uint32_t>(version) << 12) | rem;
}

bool MaskApplies(int mask, int r, int c) noexcept {
    switch (mask) {
        case 0: return ((r + c) % 2) == 0;
        case 1: return (r % 2) == 0;
        case 2: return (c % 3) == 0;
        case 3: return ((r + c) % 3) == 0;
        case 4: return (((r / 2) + (c / 3)) % 2) == 0;
        case 5: return (((r * c) % 2) + ((r * c) % 3)) == 0;
        case 6: return ((((r * c) % 2) + ((r * c) % 3)) % 2) == 0;
        case 7: return ((((r + c) % 2) + ((r * c) % 3)) % 2) == 0;
    }
    return false;
}

int ComputePenaltyScore(const std::vector<uint8_t>& m, int n) noexcept {
    int score = 0;
    // Rule 1: 5+ same-color modules in row/col
    for (int r = 0; r < n; ++r) {
        int run = 1;
        for (int c = 1; c < n; ++c) {
            if (m[static_cast<size_t>(r * n + c)] == m[static_cast<size_t>(r * n + c - 1)]) {
                ++run;
                if (run == 5) score += 3;
                else if (run > 5) ++score;
            } else {
                run = 1;
            }
        }
    }
    for (int c = 0; c < n; ++c) {
        int run = 1;
        for (int r = 1; r < n; ++r) {
            if (m[static_cast<size_t>(r * n + c)] == m[static_cast<size_t>((r - 1) * n + c)]) {
                ++run;
                if (run == 5) score += 3;
                else if (run > 5) ++score;
            } else {
                run = 1;
            }
        }
    }
    // Rule 2: 2x2 same-color blocks
    for (int r = 0; r + 1 < n; ++r) {
        for (int c = 0; c + 1 < n; ++c) {
            const uint8_t v = m[static_cast<size_t>(r * n + c)];
            if (v == m[static_cast<size_t>(r * n + c + 1)] &&
                v == m[static_cast<size_t>((r + 1) * n + c)] &&
                v == m[static_cast<size_t>((r + 1) * n + c + 1)]) {
                score += 3;
            }
        }
    }
    // Rule 3: Finder-like 1:1:3:1:1:4 patterns
    auto match_pat = [](const uint8_t* seq) -> bool {
        return (seq[0] == 1 && seq[1] == 0 && seq[2] == 1 && seq[3] == 1 && seq[4] == 1 && seq[5] == 0 && seq[6] == 1 &&
                seq[7] == 0 && seq[8] == 0 && seq[9] == 0 && seq[10] == 0) ||
               (seq[0] == 0 && seq[1] == 0 && seq[2] == 0 && seq[3] == 0 && seq[4] == 1 && seq[5] == 0 && seq[6] == 1 &&
                seq[7] == 1 && seq[8] == 1 && seq[9] == 0 && seq[10] == 1);
    };
    for (int r = 0; r < n; ++r) {
        for (int c = 0; c + 10 < n; ++c) {
            if (match_pat(&m[static_cast<size_t>(r * n + c)])) score += 40;
        }
    }
    for (int c = 0; c < n; ++c) {
        for (int r = 0; r + 10 < n; ++r) {
            uint8_t col_seq[11];
            for (int k = 0; k < 11; ++k) col_seq[k] = m[static_cast<size_t>((r + k) * n + c)];
            if (match_pat(col_seq)) score += 40;
        }
    }
    // Rule 4: dark ratio balance
    int dark = 0;
    for (uint8_t v : m) dark += (v != 0) ? 1 : 0;
    const int pct = (dark * 100) / (n * n);
    const int prev5 = (pct / 5) * 5;
    const int next5 = prev5 + 5;
    score += std::min(std::abs(prev5 - 50) / 5, std::abs(next5 - 50) / 5) * 10;
    return score;
}

QrMatrix BuildVersionedQr(std::string_view text, int version, const VersionEcSpec& spec, int ec_bits, int fixed_mask) {
    const int N = 4 * version + 17;
    const size_t total_data_cw = spec.DataCodewords();
    const int count_bits = (version >= 10) ? 16 : 8;
    const size_t max_bytes = (total_data_cw * 8u - 4u - static_cast<size_t>(count_bits)) / 8u;
    const size_t payload_len = std::min(text.size(), max_bytes);

    std::vector<uint8_t> bits;
    bits.reserve(total_data_cw * 8u);
    auto push_bits = [&](uint32_t val, int len) {
        for (int i = len - 1; i >= 0; --i) {
            bits.push_back(static_cast<uint8_t>((val >> i) & 1u));
        }
    };

    push_bits(0b0100, 4);  // Byte mode
    push_bits(static_cast<uint32_t>(payload_len), count_bits);
    for (size_t i = 0; i < payload_len; ++i) {
        push_bits(static_cast<uint8_t>(text[i]), 8);
    }

    const size_t total_data_bits = total_data_cw * 8u;
    const size_t term_bits = std::min<size_t>(4, total_data_bits - bits.size());
    push_bits(0, static_cast<int>(term_bits));
    while (bits.size() % 8 != 0) bits.push_back(0);

    static constexpr uint8_t kPads[2] = {0xECu, 0x11u};
    size_t pad_idx = 0;
    while (bits.size() < total_data_bits) {
        push_bits(kPads[pad_idx++ & 1u], 8);
    }

    std::vector<uint8_t> data_cw(total_data_cw, 0);
    for (size_t i = 0; i < total_data_cw; ++i) {
        uint8_t cw = 0;
        for (size_t b = 0; b < 8; ++b) {
            cw = static_cast<uint8_t>((cw << 1) | bits[i * 8 + b]);
        }
        data_cw[i] = cw;
    }

    // Split into Group 1 and Group 2 blocks and compute RS error correction
    const size_t total_blocks = static_cast<size_t>(spec.b1) + static_cast<size_t>(spec.b2);
    std::vector<std::vector<uint8_t>> data_blocks(total_blocks);
    std::vector<std::vector<uint8_t>> ec_blocks(total_blocks);
    size_t cw_off = 0;
    for (size_t b = 0; b < total_blocks; ++b) {
        const size_t dlen = (b < spec.b1) ? spec.d1 : spec.d2;
        data_blocks[b].assign(data_cw.begin() + static_cast<ptrdiff_t>(cw_off),
                              data_cw.begin() + static_cast<ptrdiff_t>(cw_off + dlen));
        ec_blocks[b] = RsEncode(data_blocks[b].data(), dlen, spec.ec_per_block);
        cw_off += dlen;
    }

    std::vector<uint8_t> stream;
    stream.reserve(spec.total_cw);
    const size_t max_dlen = std::max<size_t>(spec.d1, spec.d2);
    for (size_t i = 0; i < max_dlen; ++i) {
        for (size_t b = 0; b < total_blocks; ++b) {
            if (i < data_blocks[b].size()) stream.push_back(data_blocks[b][i]);
        }
    }
    for (size_t i = 0; i < spec.ec_per_block; ++i) {
        for (size_t b = 0; b < total_blocks; ++b) {
            stream.push_back(ec_blocks[b][i]);
        }
    }

    std::vector<uint8_t> stream_bits;
    stream_bits.reserve(stream.size() * 8 + 7);
    for (uint8_t cw : stream) {
        for (int b = 7; b >= 0; --b) {
            stream_bits.push_back(static_cast<uint8_t>((cw >> b) & 1u));
        }
    }

    // Function patterns
    std::vector<uint8_t> base(static_cast<size_t>(N * N), 0);
    std::vector<uint8_t> fixed(static_cast<size_t>(N * N), 0);
    auto set_mod = [&](int r, int c, uint8_t val, bool is_func) {
        if (r < 0 || r >= N || c < 0 || c >= N) return;
        const size_t idx = static_cast<size_t>(r * N + c);
        base[idx] = val;
        if (is_func) fixed[idx] = 1;
    };

    auto place_finder = [&](int top, int left) {
        for (int dr = -1; dr <= 7; ++dr) {
            for (int dc = -1; dc <= 7; ++dc) {
                const int r = top + dr;
                const int c = left + dc;
                if (r < 0 || r >= N || c < 0 || c >= N) continue;
                const bool on = (dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6) &&
                                (dr == 0 || dr == 6 || dc == 0 || dc == 6 ||
                                 (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4));
                set_mod(r, c, on ? 1 : 0, true);
            }
        }
    };

    place_finder(0, 0);
    place_finder(0, N - 7);
    place_finder(N - 7, 0);

    // Alignment patterns
    const auto align = AlignmentCoords(version);
    for (int ar : align) {
        for (int ac : align) {
            if ((ar <= 8 && ac <= 8) || (ar <= 8 && ac >= N - 8) || (ar >= N - 8 && ac <= 8)) {
                continue;
            }
            for (int dr = -2; dr <= 2; ++dr) {
                for (int dc = -2; dc <= 2; ++dc) {
                    const bool on = (dr == -2 || dr == 2 || dc == -2 || dc == 2 || (dr == 0 && dc == 0));
                    set_mod(ar + dr, ac + dc, on ? 1 : 0, true);
                }
            }
        }
    }

    // Timing patterns
    for (int i = 8; i < N - 8; ++i) {
        set_mod(6, i, (i % 2 == 0) ? 1 : 0, true);
        set_mod(i, 6, (i % 2 == 0) ? 1 : 0, true);
    }

    // Dark module + reserve format info
    set_mod(N - 8, 8, 1, true);
    for (int i = 0; i <= 8; ++i) {
        if (i != 6) {
            fixed[static_cast<size_t>(8 * N + i)] = 1;
            fixed[static_cast<size_t>(i * N + 8)] = 1;
        }
    }
    for (int i = 0; i < 8; ++i) fixed[static_cast<size_t>(8 * N + (N - 1 - i))] = 1;
    for (int i = 0; i < 7; ++i) fixed[static_cast<size_t>((N - 1 - i) * N + 8)] = 1;

    // Version info for Version >= 7 (6x3 bottom-left & 3x6 top-right)
    if (version >= 7) {
        const uint32_t vbch = EncodeVersionBch(version);
        for (int i = 0; i < 18; ++i) {
            const uint8_t bit = static_cast<uint8_t>((vbch >> i) & 1u);
            const int r_bl = (N - 11) + (i % 3);
            const int c_bl = i / 3;
            set_mod(r_bl, c_bl, bit, true);
            set_mod(c_bl, r_bl, bit, true);
        }
    }

    // Raw unmasked module placements (zig-zag coordinates)
    std::vector<uint8_t> unmasked = base;
    size_t bi = 0;
    bool up = true;
    for (int col = N - 1; col > 0; col -= 2) {
        if (col == 6) --col;
        for (int step = 0; step < N; ++step) {
            const int r = up ? (N - 1 - step) : step;
            for (int dc = 0; dc < 2; ++dc) {
                const int c = col - dc;
                const size_t idx = static_cast<size_t>(r * N + c);
                if (!fixed[idx]) {
                    unmasked[idx] = (bi < stream_bits.size()) ? stream_bits[bi++] : 0;
                }
            }
        }
        up = !up;
    }

    auto build_masked = [&](int mask) -> std::vector<uint8_t> {
        std::vector<uint8_t> mod = unmasked;
        for (int r = 0; r < N; ++r) {
            for (int c = 0; c < N; ++c) {
                const size_t idx = static_cast<size_t>(r * N + c);
                if (!fixed[idx] && MaskApplies(mask, r, c)) {
                    mod[idx] ^= 1u;
                }
            }
        }
        const uint16_t fmt = EncodeFormatBits(ec_bits, mask);
        const int fmt1[15][2] = {
            {8, 0}, {8, 1}, {8, 2}, {8, 3}, {8, 4}, {8, 5}, {8, 7}, {8, 8},
            {7, 8}, {5, 8}, {4, 8}, {3, 8}, {2, 8}, {1, 8}, {0, 8},
        };
        const int fmt2[15][2] = {
            {N - 1, 8}, {N - 2, 8}, {N - 3, 8}, {N - 4, 8}, {N - 5, 8}, {N - 6, 8}, {N - 7, 8},
            {8, N - 8}, {8, N - 7}, {8, N - 6}, {8, N - 5}, {8, N - 4}, {8, N - 3}, {8, N - 2}, {8, N - 1},
        };
        for (int i = 0; i < 15; ++i) {
            const uint8_t bit = static_cast<uint8_t>((fmt >> (14 - i)) & 1u);
            mod[static_cast<size_t>(fmt1[i][0] * N + fmt1[i][1])] = bit;
            mod[static_cast<size_t>(fmt2[i][0] * N + fmt2[i][1])] = bit;
        }
        return mod;
    };

    QrMatrix qr;
    qr.size = N;
    if (fixed_mask >= 0 && fixed_mask <= 7) {
        qr.modules = build_masked(fixed_mask);
    } else {
        int best_score = std::numeric_limits<int>::max();
        for (int m = 0; m < 8; ++m) {
            auto cand = build_masked(m);
            const int s = ComputePenaltyScore(cand, N);
            if (s < best_score) {
                best_score = s;
                qr.modules = std::move(cand);
            }
        }
    }
    return qr;
}

}  // namespace

QrMatrix BuildQrMatrixV4M(std::string_view text) {
    return BuildVersionedQr(text, 4, kSpecM[3], 0 /*M=00*/, 0 /*Mask 0*/);
}

QrMatrix BuildQrMatrixAuto(std::string_view text) {
    // Prefer ECC-M (Versions 1..15, up to 412 UTF-8 bytes), matching Android QrMatrix.kt
    for (int v = 1; v <= 15; ++v) {
        const auto& spec = kSpecM[v - 1];
        const int count_bits = (v >= 10) ? 16 : 8;
        const size_t cap = (spec.DataCodewords() * 8u - 4u - static_cast<size_t>(count_bits)) / 8u;
        if (text.size() <= cap) {
            return BuildVersionedQr(text, v, spec, 0 /*M=00*/, -1);
        }
    }
    // Fallback to ECC-L (up to 520 bytes)
    for (int v = 13; v <= 15; ++v) {
        const auto& spec = kSpecL[v - 1];
        const size_t cap = (spec.DataCodewords() * 8u - 4u - 16u) / 8u;
        if (text.size() <= cap) {
            return BuildVersionedQr(text, v, spec, 1 /*L=01*/, -1);
        }
    }
    return BuildVersionedQr(text, 15, kSpecL[14], 1 /*L=01*/, -1);
}

}  // namespace yumi_nx
