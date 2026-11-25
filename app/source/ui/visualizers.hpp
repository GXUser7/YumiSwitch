#pragma once

#include "yumi_nx/qr_matrix.hpp"
#include "yumi_theme.hpp"

struct NVGcontext;

namespace yumi_nx::ui {

struct PlanetCameraState {
    float scroll = 260.0f;
    float scroll_speed = 0.0f;
    float zoom = 1.50f;
    float zoom_speed = 0.0f;
    float marker_deg = 18.0f;
};

[[nodiscard]] float PaceOfMibPerSec(float mib_per_sec) noexcept;

void DrawTrafficWaves(NVGcontext* vg, float x, float y, float w, float h,
                      float time_sec, float down_swell, float up_swell,
                      const YumiTheme& theme);

void DrawPixelPlanet(NVGcontext* vg, float x, float y, float w, float h,
                     float dt_sec, bool connected, bool warming,
                     float lat_deg, float lon_deg,
                     PlanetCameraState& cam, const YumiTheme& theme);

void DrawShapeSpinner(NVGcontext* vg, float cx, float cy, float radius,
                      float time_sec, ColorRgba color);

void DrawQrPlate(NVGcontext* vg, float x, float y, float size,
                 float corner_radius, const QrMatrix& qr);

}  // namespace yumi_nx::ui
