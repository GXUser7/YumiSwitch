#include "yumi_theme.hpp"

#include <cmath>

#include "nanovg.h"

namespace yumi_nx::ui {

namespace {

inline NVGcolor ToNvg(ColorRgba c) noexcept {
    return nvgRGBA(c.r, c.g, c.b, c.a);
}

}  // namespace

void DrawRoundedPanel(NVGcontext* vg, float x, float y, float w, float h,
                      float r_tl, float r_tr, float r_br, float r_bl, ColorRgba fill) {
    const float max_r = std::max(0.0f, std::min(w, h) * 0.5f);
    nvgBeginPath(vg);
    nvgRoundedRectVarying(vg, x, y, w, h,
                          std::clamp(r_tl, 0.0f, max_r),
                          std::clamp(r_tr, 0.0f, max_r),
                          std::clamp(r_br, 0.0f, max_r),
                          std::clamp(r_bl, 0.0f, max_r));
    nvgFillColor(vg, ToNvg(fill));
    nvgFill(vg);
}

void DrawFocusStroke(NVGcontext* vg, float x, float y, float w, float h,
                     float r_tl, float r_tr, float r_br, float r_bl,
                     ColorRgba stroke_col, float stroke_w) {
    const float half = stroke_w * 0.5f;
    const float iw = std::max(1.0f, w - stroke_w);
    const float ih = std::max(1.0f, h - stroke_w);
    const float max_r = std::max(0.0f, std::min(iw, ih) * 0.5f);
    nvgBeginPath(vg);
    nvgRoundedRectVarying(vg, x + half, y + half, iw, ih,
                          std::clamp(r_tl - half, 0.0f, max_r),
                          std::clamp(r_tr - half, 0.0f, max_r),
                          std::clamp(r_br - half, 0.0f, max_r),
                          std::clamp(r_bl - half, 0.0f, max_r));
    nvgStrokeColor(vg, ToNvg(stroke_col));
    nvgStrokeWidth(vg, stroke_w);
    nvgStroke(vg);
}

void DrawM3Switch(NVGcontext* vg, float x, float y, bool on, const YumiTheme& t) {
    constexpr float kW = 54.0f;
    constexpr float kH = 30.0f;
    DrawRoundedBox(vg, x, y, kW, kH, kH * 0.5f, on ? t.primary : t.surface_highest);
    const float thumb_x = on ? (x + kW - 15.0f) : (x + 15.0f);
    nvgBeginPath(vg);
    nvgCircle(vg, thumb_x, y + kH * 0.5f, 11.5f);
    nvgFillColor(vg, ToNvg(on ? t.on_primary : t.on_surface_variant));
    nvgFill(vg);
}

void DrawVectorIcon(NVGcontext* vg, UiIcon icon, float cx, float cy, float size, ColorRgba rgba) {
    const NVGcolor col = ToNvg(rgba);
    const float s = size * 0.5f;
    nvgSave(vg);
    nvgLineCap(vg, NVG_ROUND);
    nvgLineJoin(vg, NVG_ROUND);

    switch (icon) {
        case UiIcon::Shield: {
            nvgBeginPath(vg);
            nvgMoveTo(vg, cx, cy - s * 0.88f);
            nvgLineTo(vg, cx + s * 0.74f, cy - s * 0.56f);
            nvgLineTo(vg, cx + s * 0.74f, cy + s * 0.04f);
            nvgQuadTo(vg, cx + s * 0.70f, cy + s * 0.64f, cx, cy + s * 0.90f);
            nvgQuadTo(vg, cx - s * 0.70f, cy + s * 0.64f, cx - s * 0.74f, cy + s * 0.04f);
            nvgLineTo(vg, cx - s * 0.74f, cy - s * 0.56f);
            nvgClosePath(vg);
            nvgFillColor(vg, col);
            nvgFill(vg);
            break;
        }
        case UiIcon::Servers: {
            const float bw = s * 1.44f;
            const float bh = s * 0.58f;
            DrawRoundedBox(vg, cx - bw * 0.5f, cy - s * 0.72f, bw, bh, s * 0.16f, rgba);
            DrawRoundedBox(vg, cx - bw * 0.5f, cy + s * 0.14f, bw, bh, s * 0.16f, rgba);
            nvgBeginPath(vg);
            nvgCircle(vg, cx - bw * 0.28f, cy - s * 0.43f, s * 0.10f);
            nvgCircle(vg, cx - bw * 0.28f, cy + s * 0.43f, s * 0.10f);
            nvgFillColor(vg, nvgRGBA(9, 11, 15, 210));
            nvgFill(vg);
            break;
        }
        case UiIcon::Cloud: {
            nvgBeginPath(vg);
            nvgRoundedRect(vg, cx - s * 0.80f, cy + s * 0.02f, s * 1.60f, s * 0.58f, s * 0.29f);
            nvgCircle(vg, cx - s * 0.18f, cy - s * 0.12f, s * 0.44f);
            nvgCircle(vg, cx + s * 0.28f, cy - s * 0.02f, s * 0.34f);
            nvgFillColor(vg, col);
            nvgFill(vg);
            break;
        }
        case UiIcon::Rules: {
            const float lw = std::max(1.8f, s * 0.16f);
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, lw);
            for (int r = -1; r <= 1; ++r) {
                const float y = cy + r * s * 0.52f;
                nvgBeginPath(vg);
                nvgMoveTo(vg, cx - s * 0.78f, y);
                nvgLineTo(vg, cx + s * 0.78f, y);
                nvgStroke(vg);
                const float kx = cx + (r == 0 ? -s * 0.28f : (r < 0 ? s * 0.26f : s * 0.08f));
                nvgBeginPath(vg);
                nvgCircle(vg, kx, y, s * 0.18f);
                nvgFillColor(vg, col);
                nvgFill(vg);
            }
            break;
        }
        case UiIcon::Settings: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(2.0f, s * 0.24f));
            nvgBeginPath(vg);
            nvgCircle(vg, cx, cy, s * 0.48f);
            nvgStroke(vg);
            for (int i = 0; i < 6; ++i) {
                const float a = static_cast<float>(i) * 1.0471975f;
                nvgBeginPath(vg);
                nvgMoveTo(vg, cx + std::cos(a) * s * 0.55f, cy + std::sin(a) * s * 0.55f);
                nvgLineTo(vg, cx + std::cos(a) * s * 0.80f, cy + std::sin(a) * s * 0.80f);
                nvgStrokeWidth(vg, std::max(2.4f, s * 0.28f));
                nvgStroke(vg);
            }
            break;
        }
        case UiIcon::Power: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(2.6f, s * 0.24f));
            nvgBeginPath(vg);
            nvgArc(vg, cx, cy + s * 0.04f, s * 0.64f, -0.82f, 3.96f, NVG_CW);
            nvgStroke(vg);
            nvgBeginPath(vg);
            nvgMoveTo(vg, cx, cy - s * 0.82f);
            nvgLineTo(vg, cx, cy - s * 0.02f);
            nvgStroke(vg);
            break;
        }
        case UiIcon::Pause: {
            const float bw = s * 0.34f;
            const float bh = s * 1.18f;
            DrawRoundedBox(vg, cx - s * 0.48f, cy - bh * 0.5f, bw, bh, bw * 0.35f, rgba);
            DrawRoundedBox(vg, cx + s * 0.14f, cy - bh * 0.5f, bw, bh, bw * 0.35f, rgba);
            break;
        }
        case UiIcon::Error: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(2.2f, s * 0.22f));
            nvgBeginPath(vg);
            nvgCircle(vg, cx, cy, s * 0.72f);
            nvgStroke(vg);
            nvgBeginPath(vg);
            nvgMoveTo(vg, cx, cy - s * 0.36f);
            nvgLineTo(vg, cx, cy + s * 0.12f);
            nvgStroke(vg);
            nvgBeginPath(vg);
            nvgCircle(vg, cx, cy + s * 0.38f, std::max(1.8f, s * 0.12f));
            nvgFillColor(vg, col);
            nvgFill(vg);
            break;
        }
        case UiIcon::Waves: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(1.8f, s * 0.18f));
            for (int r = -1; r <= 1; ++r) {
                const float y = cy + r * s * 0.44f;
                nvgBeginPath(vg);
                nvgMoveTo(vg, cx - s * 0.78f, y);
                nvgQuadTo(vg, cx - s * 0.36f, y - s * 0.26f, cx, y);
                nvgQuadTo(vg, cx + s * 0.36f, y + s * 0.26f, cx + s * 0.78f, y);
                nvgStroke(vg);
            }
            break;
        }
        case UiIcon::Planet: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(1.8f, s * 0.18f));
            nvgBeginPath(vg);
            nvgCircle(vg, cx, cy, s * 0.72f);
            nvgStroke(vg);
            nvgBeginPath(vg);
            nvgEllipse(vg, cx, cy, s * 0.34f, s * 0.72f);
            nvgStroke(vg);
            nvgBeginPath(vg);
            nvgMoveTo(vg, cx - s * 0.70f, cy);
            nvgLineTo(vg, cx + s * 0.70f, cy);
            nvgStroke(vg);
            break;
        }
        case UiIcon::Block: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(1.8f, s * 0.20f));
            nvgBeginPath(vg);
            nvgCircle(vg, cx, cy, s * 0.70f);
            nvgMoveTo(vg, cx - s * 0.48f, cy + s * 0.48f);
            nvgLineTo(vg, cx + s * 0.48f, cy - s * 0.48f);
            nvgStroke(vg);
            break;
        }
        case UiIcon::Ping:
        case UiIcon::Speed: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(1.8f, s * 0.20f));
            nvgBeginPath(vg);
            nvgArc(vg, cx, cy + s * 0.16f, s * 0.72f, 2.75f, 0.39f, NVG_CW);
            nvgStroke(vg);
            nvgBeginPath(vg);
            nvgMoveTo(vg, cx, cy + s * 0.16f);
            nvgLineTo(vg, cx + s * 0.44f, cy - s * 0.34f);
            nvgStroke(vg);
            break;
        }
        case UiIcon::Refresh:
        case UiIcon::Update: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(1.9f, s * 0.21f));
            nvgBeginPath(vg);
            nvgArc(vg, cx, cy, s * 0.62f, 0.45f, 5.42f, NVG_CW);
            nvgStroke(vg);
            nvgBeginPath(vg);
            nvgMoveTo(vg, cx + s * 0.42f, cy - s * 0.82f);
            nvgLineTo(vg, cx + s * 0.72f, cy - s * 0.30f);
            nvgLineTo(vg, cx + s * 0.16f, cy - s * 0.32f);
            nvgClosePath(vg);
            nvgFillColor(vg, col);
            nvgFill(vg);
            break;
        }
        case UiIcon::Sd: {
            nvgBeginPath(vg);
            nvgMoveTo(vg, cx - s * 0.32f, cy - s * 0.78f);
            nvgLineTo(vg, cx + s * 0.58f, cy - s * 0.78f);
            nvgLineTo(vg, cx + s * 0.58f, cy + s * 0.78f);
            nvgLineTo(vg, cx - s * 0.58f, cy + s * 0.78f);
            nvgLineTo(vg, cx - s * 0.58f, cy - s * 0.40f);
            nvgClosePath(vg);
            nvgFillColor(vg, col);
            nvgFill(vg);
            break;
        }
        case UiIcon::Phone: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(1.8f, s * 0.18f));
            nvgBeginPath(vg);
            nvgRoundedRect(vg, cx - s * 0.44f, cy - s * 0.78f, s * 0.88f, s * 1.56f, s * 0.16f);
            nvgStroke(vg);
            break;
        }
        case UiIcon::Lock: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(1.8f, s * 0.18f));
            nvgBeginPath(vg);
            nvgArc(vg, cx, cy - s * 0.22f, s * 0.36f, 3.14159f, 6.28318f, NVG_CW);
            nvgStroke(vg);
            DrawRoundedBox(vg, cx - s * 0.54f, cy - s * 0.12f, s * 1.08f, s * 0.84f, s * 0.18f, rgba);
            break;
        }
        case UiIcon::Apps: {
            const float dot = s * 0.36f;
            for (int r = -1; r <= 1; ++r) {
                for (int c = -1; c <= 1; ++c) {
                    DrawRoundedBox(vg, cx + c * s * 0.54f - dot * 0.5f,
                                   cy + r * s * 0.54f - dot * 0.5f, dot, dot, dot * 0.25f, rgba);
                }
            }
            break;
        }
        case UiIcon::Log: {
            DrawRoundedBox(vg, cx - s * 0.62f, cy - s * 0.74f, s * 1.24f, s * 1.48f, s * 0.18f, rgba);
            nvgStrokeColor(vg, nvgRGBA(9, 11, 15, 220));
            nvgStrokeWidth(vg, std::max(1.6f, s * 0.15f));
            for (int i = -1; i <= 1; ++i) {
                nvgBeginPath(vg);
                nvgMoveTo(vg, cx - s * 0.34f, cy + i * s * 0.36f);
                nvgLineTo(vg, cx + s * 0.34f, cy + i * s * 0.36f);
                nvgStroke(vg);
            }
            break;
        }
        case UiIcon::Qr: {
            const float box = s * 0.56f;
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(1.6f, s * 0.18f));
            nvgBeginPath(vg);
            nvgRect(vg, cx - s * 0.70f, cy - s * 0.70f, box, box);
            nvgRect(vg, cx + s * 0.14f, cy - s * 0.70f, box, box);
            nvgRect(vg, cx - s * 0.70f, cy + s * 0.14f, box, box);
            nvgStroke(vg);
            DrawRoundedBox(vg, cx + s * 0.20f, cy + s * 0.20f, s * 0.44f, s * 0.44f, s * 0.08f, rgba);
            break;
        }
        case UiIcon::Memory: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(1.6f, s * 0.18f));
            nvgBeginPath(vg);
            nvgRoundedRect(vg, cx - s * 0.52f, cy - s * 0.52f, s * 1.04f, s * 1.04f, s * 0.18f);
            nvgStroke(vg);
            DrawRoundedBox(vg, cx - s * 0.24f, cy - s * 0.24f, s * 0.48f, s * 0.48f, s * 0.10f, rgba);
            break;
        }
        case UiIcon::Close: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(1.8f, s * 0.22f));
            nvgBeginPath(vg);
            nvgMoveTo(vg, cx - s * 0.48f, cy - s * 0.48f);
            nvgLineTo(vg, cx + s * 0.48f, cy + s * 0.48f);
            nvgMoveTo(vg, cx + s * 0.48f, cy - s * 0.48f);
            nvgLineTo(vg, cx - s * 0.48f, cy + s * 0.48f);
            nvgStroke(vg);
            break;
        }
        case UiIcon::Contrast: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(1.8f, s * 0.18f));
            nvgBeginPath(vg);
            nvgCircle(vg, cx, cy, s * 0.68f);
            nvgStroke(vg);
            nvgBeginPath(vg);
            nvgArc(vg, cx, cy, s * 0.68f, -1.570796f, 1.570796f, NVG_CW);
            nvgClosePath(vg);
            nvgFillColor(vg, col);
            nvgFill(vg);
            break;
        }
        case UiIcon::CheckCircle: {
            nvgBeginPath(vg);
            nvgCircle(vg, cx, cy, s * 0.78f);
            nvgFillColor(vg, col);
            nvgFill(vg);
            nvgStrokeColor(vg, nvgRGBA(9, 11, 15, 240));
            nvgStrokeWidth(vg, std::max(1.8f, s * 0.20f));
            nvgBeginPath(vg);
            nvgMoveTo(vg, cx - s * 0.34f, cy);
            nvgLineTo(vg, cx - s * 0.08f, cy + s * 0.28f);
            nvgLineTo(vg, cx + s * 0.36f, cy - s * 0.24f);
            nvgStroke(vg);
            break;
        }
        case UiIcon::Plus: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(2.0f, s * 0.22f));
            nvgBeginPath(vg);
            nvgMoveTo(vg, cx - s * 0.56f, cy);
            nvgLineTo(vg, cx + s * 0.56f, cy);
            nvgMoveTo(vg, cx, cy - s * 0.56f);
            nvgLineTo(vg, cx, cy + s * 0.56f);
            nvgStroke(vg);
            break;
        }
        case UiIcon::ArrowRight: {
            nvgStrokeColor(vg, col);
            nvgStrokeWidth(vg, std::max(1.8f, s * 0.22f));
            nvgBeginPath(vg);
            nvgMoveTo(vg, cx - s * 0.24f, cy - s * 0.44f);
            nvgLineTo(vg, cx + s * 0.26f, cy);
            nvgLineTo(vg, cx - s * 0.24f, cy + s * 0.44f);
            nvgStroke(vg);
            break;
        }
    }

    nvgRestore(vg);
}

}  // namespace yumi_nx::ui
