#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

namespace yumi_nx {

struct QrMatrix {
    static constexpr int kSize = 33;  // Legacy constant for Version 4-M compatibility
    int size = 33;
    std::vector<uint8_t> modules{};

    [[nodiscard]] bool At(int x, int y) const noexcept {
        if (x < 0 || x >= size || y < 0 || y >= size) return false;
        const size_t idx = static_cast<size_t>(y * size + x);
        if (idx >= modules.size()) return false;
        return modules[idx] != 0;
    }

    [[nodiscard]] bool IsFinder(int x, int y) const noexcept {
        return (x < 7 && y < 7) || (x >= size - 7 && y < 7) || (x < 7 && y >= size - 7);
    }
};

/// Fixed ISO/IEC 18004 Version 4-M QR code (33x33, up to 62 UTF-8 bytes).
[[nodiscard]] QrMatrix BuildQrMatrixV4M(std::string_view text);

/// Auto-sizing ISO/IEC 18004 QR code (Versions 1..15, Byte mode, ECC-M up to 412B, ECC-L fallback up to 520B).
[[nodiscard]] QrMatrix BuildQrMatrixAuto(std::string_view text);

}  // namespace yumi_nx
