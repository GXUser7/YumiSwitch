#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#define GLEW_STATIC
#include <GL/glew.h>
#include <GLFW/glfw3.h>

#include "nanovg.h"
#define NANOVG_GL3_IMPLEMENTATION
#include "nanovg_gl.h"

#include "mock_ctl_client.hpp"
#include "ui_app.hpp"

namespace {

float g_wheel_delta = 0.0f;

void ScrollCallback(GLFWwindow*, double, double yoffset) {
    g_wheel_delta += static_cast<float>(yoffset);
}

struct InputEdgeTracker {
    bool prev_up = false;
    bool prev_down = false;
    bool prev_left = false;
    bool prev_right = false;
    bool prev_enter = false;
    bool prev_x = false;
    bool prev_y = false;
    bool prev_l = false;
    bool prev_r = false;
    bool prev_mouse = false;

    yumi_nx::ui::UiInputState Poll(GLFWwindow* win, int win_w, int win_h) {
        yumi_nx::ui::UiInputState out{};
        auto edge = [&](int key, bool& prev) -> bool {
            const bool now = glfwGetKey(win, key) == GLFW_PRESS;
            const bool triggered = now && !prev;
            prev = now;
            return triggered;
        };

        out.up = edge(GLFW_KEY_UP, prev_up);
        out.down = edge(GLFW_KEY_DOWN, prev_down);
        out.left = edge(GLFW_KEY_LEFT, prev_left);
        out.right = edge(GLFW_KEY_RIGHT, prev_right);
        out.confirm = edge(GLFW_KEY_ENTER, prev_enter);
        out.action_x = edge(GLFW_KEY_X, prev_x);
        out.action_y = edge(GLFW_KEY_Y, prev_y);
        out.shoulder_l = edge(GLFW_KEY_Q, prev_l) || (glfwGetKey(win, GLFW_KEY_LEFT_BRACKET) == GLFW_PRESS && !prev_l);
        out.shoulder_r = edge(GLFW_KEY_E, prev_r) || (glfwGetKey(win, GLFW_KEY_RIGHT_BRACKET) == GLFW_PRESS && !prev_r);

        out.scroll_delta = g_wheel_delta;
        g_wheel_delta = 0.0f;

        const bool mouse_now = glfwGetMouseButton(win, GLFW_MOUSE_BUTTON_LEFT) == GLFW_PRESS;
        out.clicked = mouse_now && !prev_mouse;
        prev_mouse = mouse_now;

        double mx = 0.0, my = 0.0;
        glfwGetCursorPos(win, &mx, &my);
        if (win_w > 0 && win_h > 0) {
            out.pointer_x = static_cast<float>(mx) * (1280.0f / static_cast<float>(win_w));
            out.pointer_y = static_cast<float>(my) * (720.0f / static_cast<float>(win_h));
        }
        return out;
    }
};

std::string ResolveFontDirectory() {
    const std::filesystem::path candidates[] = {
        "app/romfs/fonts",
        "../app/romfs/fonts",
        "../../app/romfs/fonts",
    };
    for (const auto& c : candidates) {
        if (std::filesystem::exists(c / "roboto_flex_display.ttf")) {
            return c.string();
        }
    }
    return "app/romfs/fonts";
}

// Minimal uncompressed PNG writer (zlib stored deflate blocks + CRC32 + Adler32, zero external deps).
bool WriteRgbaPng(const std::string& path, int w, int h, const std::vector<uint8_t>& rgba_bottom_up) {
    std::vector<uint8_t> out;
    auto push_be32 = [&](uint32_t v) {
        out.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
        out.push_back(static_cast<uint8_t>(v & 0xFFu));
    };
    auto crc32 = [](const uint8_t* data, size_t len) -> uint32_t {
        uint32_t c = 0xFFFFFFFFu;
        for (size_t i = 0; i < len; ++i) {
            c ^= data[i];
            for (int b = 0; b < 8; ++b) {
                c = (c >> 1) ^ ((c & 1u) ? 0xEDB88320u : 0u);
            }
        }
        return ~c;
    };
    auto write_chunk = [&](const char type[4], const std::vector<uint8_t>& body) {
        push_be32(static_cast<uint32_t>(body.size()));
        const size_t type_pos = out.size();
        out.insert(out.end(), type, type + 4);
        out.insert(out.end(), body.begin(), body.end());
        push_be32(crc32(out.data() + type_pos, 4 + body.size()));
    };

    static constexpr uint8_t kSig[8] = {137, 80, 78, 71, 13, 10, 26, 10};
    out.insert(out.end(), kSig, kSig + 8);

    std::vector<uint8_t> ihdr(13, 0);
    ihdr[0] = static_cast<uint8_t>((w >> 24) & 0xFF); ihdr[1] = static_cast<uint8_t>((w >> 16) & 0xFF);
    ihdr[2] = static_cast<uint8_t>((w >> 8) & 0xFF);  ihdr[3] = static_cast<uint8_t>(w & 0xFF);
    ihdr[4] = static_cast<uint8_t>((h >> 24) & 0xFF); ihdr[5] = static_cast<uint8_t>((h >> 16) & 0xFF);
    ihdr[6] = static_cast<uint8_t>((h >> 8) & 0xFF);  ihdr[7] = static_cast<uint8_t>(h & 0xFF);
    ihdr[8] = 8;  // bit depth
    ihdr[9] = 6;  // RGBA
    write_chunk("IHDR", ihdr);

    const size_t stride = static_cast<size_t>(w) * 4u;
    const size_t raw_size = static_cast<size_t>(h) * (1u + stride);
    std::vector<uint8_t> raw;
    raw.reserve(raw_size);
    for (int y = h - 1; y >= 0; --y) {
        raw.push_back(0);  // Filter type 0 (None)
        const uint8_t* row = rgba_bottom_up.data() + static_cast<size_t>(y) * stride;
        raw.insert(raw.end(), row, row + stride);
    }

    uint32_t s1 = 1, s2 = 0;
    for (uint8_t b : raw) {
        s1 = (s1 + b) % 65521u;
        s2 = (s2 + s1) % 65521u;
    }

    std::vector<uint8_t> idat;
    idat.reserve(raw.size() + (raw.size() / 65535 + 1) * 5 + 8);
    idat.push_back(0x78);  // zlib CMF
    idat.push_back(0x01);  // zlib FLG (no dict, fastest)
    size_t pos = 0;
    while (pos < raw.size()) {
        const size_t chunk = std::min<size_t>(65535u, raw.size() - pos);
        const bool last = (pos + chunk == raw.size());
        idat.push_back(last ? 0x01 : 0x00);
        const uint16_t len16 = static_cast<uint16_t>(chunk);
        const uint16_t nlen16 = static_cast<uint16_t>(~len16);
        idat.push_back(static_cast<uint8_t>(len16 & 0xFFu));
        idat.push_back(static_cast<uint8_t>((len16 >> 8) & 0xFFu));
        idat.push_back(static_cast<uint8_t>(nlen16 & 0xFFu));
        idat.push_back(static_cast<uint8_t>((nlen16 >> 8) & 0xFFu));
        idat.insert(idat.end(), raw.begin() + static_cast<ptrdiff_t>(pos),
                    raw.begin() + static_cast<ptrdiff_t>(pos + chunk));
        pos += chunk;
    }
    const uint32_t adler = (s2 << 16) | s1;
    idat.push_back(static_cast<uint8_t>((adler >> 24) & 0xFFu));
    idat.push_back(static_cast<uint8_t>((adler >> 16) & 0xFFu));
    idat.push_back(static_cast<uint8_t>((adler >> 8) & 0xFFu));
    idat.push_back(static_cast<uint8_t>(adler & 0xFFu));
    write_chunk("IDAT", idat);
    write_chunk("IEND", {});

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    f.write(reinterpret_cast<const char*>(out.data()), static_cast<std::streamsize>(out.size()));
    return f.good();
}

}  // namespace

int main(int argc, char** argv) {
    std::string screenshot_path;
    std::string opt_tab = "connect";
    std::string opt_cat = "routing";
    std::string opt_vis = "waves";
    std::string opt_palette = "Glacier";
    bool opt_amoled = false;
    bool opt_connected = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next_val = [&](std::string& dst) {
            if (i + 1 < argc) dst = argv[++i];
        };
        if (a == "--screenshot") next_val(screenshot_path);
        else if (a == "--tab") next_val(opt_tab);
        else if (a == "--cat") next_val(opt_cat);
        else if (a == "--vis") next_val(opt_vis);
        else if (a == "--palette") next_val(opt_palette);
        else if (a == "--amoled") opt_amoled = true;
        else if (a == "--connected") opt_connected = true;
    }

    if (!glfwInit()) {
        std::fprintf(stderr, "Failed to initialize GLFW\n");
        return 1;
    }

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_SAMPLES, 4);
    if (!screenshot_path.empty()) {
        glfwWindowHint(GLFW_VISIBLE, GLFW_FALSE);
    }

    GLFWwindow* window = glfwCreateWindow(1280, 720, "Yumi NX - Desktop UI Preview (B·B·A)", nullptr, nullptr);
    if (!window) {
        std::fprintf(stderr, "Failed to create GLFW window\n");
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSetScrollCallback(window, ScrollCallback);
    glfwSwapInterval(screenshot_path.empty() ? 1 : 0);

    glewExperimental = GL_TRUE;
    if (glewInit() != GLEW_OK) {
        std::fprintf(stderr, "Failed to initialize GLEW\n");
        glfwDestroyWindow(window);
        glfwTerminate();
        return 1;
    }

    NVGcontext* vg = nvgCreateGL3(NVG_ANTIALIAS | NVG_STENCIL_STROKES);
    if (!vg) {
        std::fprintf(stderr, "Failed to initialize NanoVG GL3\n");
        glfwDestroyWindow(window);
        glfwTerminate();
        return 1;
    }

    yumi_nx::platform::MockYumiCtlClient mock_ctl;
    if (opt_connected || !screenshot_path.empty()) {
        mock_ctl.ForceConnectedImmediate();
    }

    yumi_nx::ui::YumiUiApp app(mock_ctl, ResolveFontDirectory(), true);
    if (!screenshot_path.empty()) {
        app.SetHeadlessMode(true);
    }
    if (!app.Init(vg)) {
        std::fprintf(stderr, "Warning: one or more fonts failed to load from %s\n", ResolveFontDirectory().c_str());
    }

    if (opt_tab == "servers") app.SetTab(yumi_nx::ui::UiTab::Servers);
    else if (opt_tab == "subs") app.SetTab(yumi_nx::ui::UiTab::Subs);
    else if (opt_tab == "rules") app.SetTab(yumi_nx::ui::UiTab::Rules);
    else if (opt_tab == "settings") app.SetTab(yumi_nx::ui::UiTab::Settings);
    else app.SetTab(yumi_nx::ui::UiTab::Connect);

    if (opt_cat == "titleid") app.SetSettingsCategory(yumi_nx::ui::SettingsCategory::TitleId);
    else if (opt_cat == "dpi") app.SetSettingsCategory(yumi_nx::ui::SettingsCategory::Dpi);
    else if (opt_cat == "logrules") app.SetSettingsCategory(yumi_nx::ui::SettingsCategory::LogRules);
    else if (opt_cat == "remote") app.SetSettingsCategory(yumi_nx::ui::SettingsCategory::Remote);

    if (opt_vis == "planet") app.SetVisualizerPlanet(true);

    yumi_nx::ui::PaletteId pal = yumi_nx::ui::PaletteId::Glacier;
    if (opt_palette == "Rose") pal = yumi_nx::ui::PaletteId::Rose;
    else if (opt_palette == "Lilac") pal = yumi_nx::ui::PaletteId::Lilac;
    else if (opt_palette == "Mint") pal = yumi_nx::ui::PaletteId::Mint;
    else if (opt_palette == "Peach") pal = yumi_nx::ui::PaletteId::Peach;
    else if (opt_palette == "Sand") pal = yumi_nx::ui::PaletteId::Sand;
    else if (opt_palette == "Sea") pal = yumi_nx::ui::PaletteId::Sea;
    app.SetPalette(pal, opt_amoled);

    if (!screenshot_path.empty()) {
        int fb_w = 1280, fb_h = 720;
        glfwGetFramebufferSize(window, &fb_w, &fb_h);
        if (fb_w <= 0 || fb_h <= 0) { fb_w = 1280; fb_h = 720; }
        for (int f = 0; f < 16; ++f) {
            mock_ctl.Tick(0.033);
            app.Update(0.033, {});
            glViewport(0, 0, fb_w, fb_h);
            glClearColor(0.035f, 0.043f, 0.059f, 1.0f);
            glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT | GL_STENCIL_BUFFER_BIT);
            app.Render(vg, fb_w, fb_h);
            glFinish();
        }
        std::vector<uint8_t> pixels(static_cast<size_t>(fb_w) * static_cast<size_t>(fb_h) * 4u);
        glReadPixels(0, 0, fb_w, fb_h, GL_RGBA, GL_UNSIGNED_BYTE, pixels.data());
        for (size_t i = 3; i < pixels.size(); i += 4) pixels[i] = 255;
        const bool ok = WriteRgbaPng(screenshot_path, fb_w, fb_h, pixels);
        app.Shutdown(vg);
        nvgDeleteGL3(vg);
        glfwDestroyWindow(window);
        glfwTerminate();
        return ok ? 0 : 1;
    }

    InputEdgeTracker input_tracker;
    double prev_time = glfwGetTime();

    while (!glfwWindowShouldClose(window)) {
        const double now = glfwGetTime();
        const double dt = std::min(0.1, std::max(0.0, now - prev_time));
        prev_time = now;

        glfwPollEvents();
        if (glfwGetKey(window, GLFW_KEY_ESCAPE) == GLFW_PRESS) {
            glfwSetWindowShouldClose(window, GLFW_TRUE);
        }

        int win_w = 0, win_h = 0, fb_w = 0, fb_h = 0;
        glfwGetWindowSize(window, &win_w, &win_h);
        glfwGetFramebufferSize(window, &fb_w, &fb_h);

        mock_ctl.Tick(dt);
        const auto input = input_tracker.Poll(window, win_w, win_h);
        app.Update(dt, input);

        glViewport(0, 0, fb_w, fb_h);
        glClearColor(0.035f, 0.043f, 0.059f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT | GL_STENCIL_BUFFER_BIT);

        app.Render(vg, win_w, win_h);
        glfwSwapBuffers(window);
    }

    app.Shutdown(vg);
    nvgDeleteGL3(vg);
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
