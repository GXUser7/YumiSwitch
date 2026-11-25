#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>

struct NVGcontext;

namespace yumi_nx::ui {

enum class PaletteId : uint8_t {
    Glacier = 0,
    Rose = 1,
    Lilac = 2,
    Mint = 3,
    Peach = 4,
    Sand = 5,
    Sea = 6,
};

struct ColorRgba {
    uint8_t r = 0;
    uint8_t g = 0;
    uint8_t b = 0;
    uint8_t a = 255;

    [[nodiscard]] constexpr bool operator==(const ColorRgba& other) const noexcept = default;
    [[nodiscard]] constexpr ColorRgba WithAlpha(uint8_t alpha) const noexcept {
        return {r, g, b, alpha};
    }
};

struct YumiTheme {
    PaletteId id = PaletteId::Glacier;
    bool amoled = false;
    const char* name = "Glacier";

    ColorRgba background{9, 11, 15, 255};
    ColorRgba surface{9, 11, 15, 255};
    ColorRgba surface_lowest{5, 7, 10, 255};
    ColorRgba surface_low{15, 19, 26, 255};
    ColorRgba surface_container{21, 26, 34, 255};
    ColorRgba surface_high{28, 34, 44, 255};
    ColorRgba surface_highest{35, 42, 53, 255};
    ColorRgba surface_variant{41, 49, 61, 255};

    ColorRgba primary{168, 199, 255, 255};
    ColorRgba on_primary{7, 32, 63, 255};
    ColorRgba primary_container{36, 49, 74, 255};
    ColorRgba on_primary_container{213, 227, 255, 255};

    ColorRgba secondary{240, 190, 115, 255};
    ColorRgba on_secondary{64, 43, 8, 255};
    ColorRgba secondary_container{90, 65, 24, 255};
    ColorRgba on_secondary_container{255, 222, 176, 255};

    ColorRgba tertiary{143, 214, 192, 255};
    ColorRgba on_tertiary{0, 56, 42, 255};
    ColorRgba tertiary_container{6, 80, 60, 255};
    ColorRgba on_tertiary_container{169, 242, 220, 255};

    ColorRgba error{255, 152, 133, 255};
    ColorRgba on_error{92, 21, 8, 255};
    ColorRgba error_container{126, 36, 21, 255};
    ColorRgba on_error_container{255, 218, 211, 255};

    ColorRgba on_surface{231, 236, 244, 255};
    ColorRgba on_surface_variant{154, 165, 182, 255};
    ColorRgba outline{78, 88, 103, 255};
    ColorRgba outline_variant{41, 49, 61, 255};

    ColorRgba marker_accent{219, 232, 255, 255};

    // Fixed semantic latency ramp (never repainted by palette)
    ColorRgba latency_fast{126, 224, 168, 255};
    ColorRgba latency_medium{240, 190, 115, 255};
    ColorRgba latency_slow{255, 152, 133, 255};
    ColorRgba latency_dead{122, 132, 150, 255};
};

inline ColorRgba HslColor(float h, float s, float l) noexcept {
    float hue = std::fmod(h, 360.0f);
    if (hue < 0.0f) hue += 360.0f;
    const float c = (1.0f - std::fabs(2.0f * l - 1.0f)) * s;
    const float x = c * (1.0f - std::fabs(std::fmod(hue / 60.0f, 2.0f) - 1.0f));
    const float m = l - c * 0.5f;
    float r = 0.0f, g = 0.0f, b = 0.0f;
    if (hue < 60.0f) { r = c; g = x; }
    else if (hue < 120.0f) { r = x; g = c; }
    else if (hue < 180.0f) { g = c; b = x; }
    else if (hue < 240.0f) { g = x; b = c; }
    else if (hue < 300.0f) { r = x; b = c; }
    else { r = c; b = x; }
    auto clamp_u8 = [](float v) -> uint8_t {
        const float scaled = std::round(v * 255.0f);
        return static_cast<uint8_t>(std::clamp(scaled, 0.0f, 255.0f));
    };
    return {clamp_u8(r + m), clamp_u8(g + m), clamp_u8(b + m), 255};
}

inline ColorRgba ComputeMarkerAccent(ColorRgba pri) noexcept {
    const float r = pri.r / 255.0f;
    const float g = pri.g / 255.0f;
    const float b = pri.b / 255.0f;
    const float high = std::max({r, g, b});
    const float low = std::min({r, g, b});
    const float span = high - low;
    if (span < 0.0001f) return {237, 237, 237, 255};
    const float l = (high + low) * 0.5f;
    float h = 0.0f;
    if (high == r) h = (g - b) / span + (g < b ? 6.0f : 0.0f);
    else if (high == g) h = (b - r) / span + 2.0f;
    else h = (r - g) / span + 4.0f;
    h *= 60.0f;
    const float sat = std::min(0.85f, std::max(0.0f, span / (1.0f - std::fabs(2.0f * l - 1.0f))));
    return HslColor(h, sat, 0.93f);
}

inline YumiTheme BuildYumiTheme(PaletteId id, bool amoled) noexcept {
    struct PaletteSpec {
        const char* name;
        int16_t hue;
        int16_t partner;
    };
    static constexpr std::array<PaletteSpec, 7> kSpecs = {{
        {"Glacier", -1, 162},
        {"Rose", 344, 186},
        {"Lilac", 268, 160},
        {"Mint", 158, 28},
        {"Peach", 22, 194},
        {"Sand", 44, 210},
        {"Sea", 196, 32},
    }};

    const size_t idx = std::min<size_t>(static_cast<size_t>(id), kSpecs.size() - 1);
    const auto& spec = kSpecs[idx];
    YumiTheme t{};
    t.id = static_cast<PaletteId>(idx);
    t.amoled = amoled;
    t.name = spec.name;

    if (spec.hue >= 0) {
        const float h = static_cast<float>(spec.hue);
        const float second = std::fmod(h + 26.0f, 360.0f);
        const float partner = static_cast<float>(spec.partner);

        t.primary = HslColor(h, 0.55f, 0.80f);
        t.on_primary = HslColor(h, 0.72f, 0.13f);
        t.primary_container = HslColor(h, 0.30f, 0.25f);
        t.on_primary_container = HslColor(h, 0.62f, 0.90f);

        t.secondary = HslColor(second, 0.52f, 0.76f);
        t.on_secondary = HslColor(second, 0.80f, 0.13f);
        t.secondary_container = HslColor(second, 0.30f, 0.27f);
        t.on_secondary_container = HslColor(second, 0.70f, 0.88f);

        t.tertiary = HslColor(partner, 0.42f, 0.70f);
        t.on_tertiary = HslColor(partner, 0.85f, 0.11f);
        t.tertiary_container = HslColor(partner, 0.60f, 0.17f);
        t.on_tertiary_container = HslColor(partner, 0.66f, 0.80f);

        t.background = HslColor(h, 0.34f, 0.055f);
        t.surface = t.background;
        t.surface_lowest = HslColor(h, 0.40f, 0.032f);
        t.surface_low = HslColor(h, 0.32f, 0.085f);
        t.surface_container = HslColor(h, 0.30f, 0.115f);
        t.surface_high = HslColor(h, 0.28f, 0.150f);
        t.surface_highest = HslColor(h, 0.26f, 0.190f);
        t.surface_variant = HslColor(h, 0.26f, 0.210f);

        t.outline = HslColor(h, 0.18f, 0.380f);
        t.outline_variant = HslColor(h, 0.24f, 0.220f);
        t.on_surface = HslColor(h, 0.40f, 0.930f);
        t.on_surface_variant = HslColor(h, 0.20f, 0.680f);
    }

    if (amoled) {
        t.background = {0, 0, 0, 255};
        t.surface = {0, 0, 0, 255};
        t.surface_lowest = {0, 0, 0, 255};
        if (spec.hue < 0) {
            t.surface_low = {10, 10, 12, 255};
            t.surface_container = {18, 18, 21, 255};
            t.surface_high = {27, 27, 31, 255};
            t.surface_highest = {36, 36, 41, 255};
        } else {
            const float h = static_cast<float>(spec.hue);
            t.surface_low = HslColor(h, 0.30f, 0.042f);
            t.surface_container = HslColor(h, 0.28f, 0.072f);
            t.surface_high = HslColor(h, 0.26f, 0.108f);
            t.surface_highest = HslColor(h, 0.24f, 0.145f);
        }
    }

    t.marker_accent = ComputeMarkerAccent(t.primary);
    return t;
}

inline ColorRgba LatencyColorFor(const YumiTheme& t, int ping_ms) noexcept {
    if (ping_ms < 0) return t.latency_dead;
    if (ping_ms <= 65) return t.latency_fast;
    if (ping_ms <= 130) return t.latency_medium;
    return t.latency_slow;
}

enum class UiIcon : uint8_t {
    Shield = 0,
    Servers,
    Cloud,
    Rules,
    Settings,
    Power,
    Pause,
    Error,
    Waves,
    Planet,
    Block,
    Ping,
    Refresh,
    Sd,
    Phone,
    Lock,
    Apps,
    Log,
    Qr,
    Memory,
    Speed,
    Update,
    Close,
    Contrast,
    CheckCircle,
    Plus,
    ArrowRight,
};

void DrawRoundedPanel(NVGcontext* vg, float x, float y, float w, float h,
                      float r_tl, float r_tr, float r_br, float r_bl, ColorRgba fill);

inline void DrawRoundedBox(NVGcontext* vg, float x, float y, float w, float h, float r, ColorRgba fill) {
    DrawRoundedPanel(vg, x, y, w, h, r, r, r, r, fill);
}

void DrawFocusStroke(NVGcontext* vg, float x, float y, float w, float h,
                     float r_tl, float r_tr, float r_br, float r_bl,
                     ColorRgba stroke_col, float stroke_w = 3.0f);

void DrawM3Switch(NVGcontext* vg, float x, float y, bool on, const YumiTheme& t);

void DrawVectorIcon(NVGcontext* vg, UiIcon icon, float cx, float cy, float size, ColorRgba col);

}  // namespace yumi_nx::ui
