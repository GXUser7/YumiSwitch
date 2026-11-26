#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>

#include <switch.h>
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <glad/glad.h>

#include "nanovg.h"
#define NANOVG_GL3_IMPLEMENTATION
#include "nanovg_gl.h"

#include "switch_ctl_client.hpp"
#include "ui_app.hpp"
#include "yumi_nx/crypto.hpp"
#include "yumi_nx/paths.hpp"
#include "yumi_nx/socket_io.hpp"

namespace {

EGLDisplay s_display = EGL_NO_DISPLAY;
EGLContext s_context = EGL_NO_CONTEXT;
EGLSurface s_surface = EGL_NO_SURFACE;
std::atomic<bool> s_in_focus{true};

void OnAppletHook(AppletHookType hook, void*) {
    switch (hook) {
        case AppletHookType_OnFocusState:
        case AppletHookType_OnResume:
            s_in_focus.store(appletGetFocusState() == AppletFocusState_InFocus);
            break;
        case AppletHookType_OnExitRequest:
            s_in_focus.store(false);
            break;
        default:
            break;
    }
}

bool InitEgl(NWindow* win) {
    s_display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (!s_display) return false;

    if (!eglInitialize(s_display, nullptr, nullptr)) return false;
    if (eglBindAPI(EGL_OPENGL_API) == EGL_FALSE) return false;

    static const EGLint fb_attrs[] = {
        EGL_RENDERABLE_TYPE, EGL_OPENGL_BIT,
        EGL_RED_SIZE,        8,
        EGL_GREEN_SIZE,      8,
        EGL_BLUE_SIZE,       8,
        EGL_ALPHA_SIZE,      8,
        EGL_DEPTH_SIZE,      24,
        EGL_STENCIL_SIZE,    8,
        EGL_NONE,
    };

    EGLConfig config = nullptr;
    EGLint num_configs = 0;
    eglChooseConfig(s_display, fb_attrs, &config, 1, &num_configs);
    if (num_configs == 0) return false;

    s_surface = eglCreateWindowSurface(s_display, config, win, nullptr);
    if (!s_surface) return false;

    static const EGLint ctx_attrs[] = {
        EGL_CONTEXT_OPENGL_PROFILE_MASK_KHR, EGL_CONTEXT_OPENGL_CORE_PROFILE_BIT_KHR,
        EGL_CONTEXT_MAJOR_VERSION_KHR, 3,
        EGL_CONTEXT_MINOR_VERSION_KHR, 3,
        EGL_NONE,
    };
    s_context = eglCreateContext(s_display, config, EGL_NO_CONTEXT, ctx_attrs);
    if (!s_context) return false;

    eglMakeCurrent(s_display, s_surface, s_surface, s_context);
    return true;
}

void DeinitEgl() {
    if (s_display != EGL_NO_DISPLAY) {
        eglMakeCurrent(s_display, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT);
        if (s_context != EGL_NO_CONTEXT) {
            eglDestroyContext(s_display, s_context);
            s_context = EGL_NO_CONTEXT;
        }
        if (s_surface != EGL_NO_SURFACE) {
            eglDestroySurface(s_display, s_surface);
            s_surface = EGL_NO_SURFACE;
        }
        eglTerminate(s_display);
        s_display = EGL_NO_DISPLAY;
    }
}

void InitWindowResolution(NWindow* win, u32& out_w, u32& out_h) {
    // Configure NWindow dimensions ONCE before EGL configures buffer slots;
    // vi handles dynamic docked/handheld scaling via ViScalingMode_FitToLayer.
    const AppletOperationMode mode = appletGetOperationMode();
    out_w = (mode == AppletOperationMode_Console) ? 1920u : 1280u;
    out_h = (mode == AppletOperationMode_Console) ? 1080u : 720u;
    if (R_FAILED(nwindowSetDimensions(win, out_w, out_h))) {
        nwindowGetDimensions(win, &out_w, &out_h);
    }
}

}  // namespace

extern "C" void userAppInit(void) {
    romfsInit();
    yumi_nx::net::SocketLayerInit(false);
    nifmInitialize(NifmServiceType_User);
    nsInitialize();
}

extern "C" void userAppExit(void) {
    yumi_nx::net::crypto::RandomShutdown();
    nsExit();
    nifmExit();
    yumi_nx::net::SocketLayerShutdown();
    romfsExit();
}

int main(int, char**) {
    AppletHookCookie applet_hook_cookie{};
    s_in_focus.store(appletGetFocusState() == AppletFocusState_InFocus);
    appletHook(&applet_hook_cookie, OnAppletHook, nullptr);

    NWindow* win = nwindowGetDefault();
    u32 win_w = 1280u;
    u32 win_h = 720u;
    InitWindowResolution(win, win_w, win_h);

    if (!InitEgl(win)) {
        DeinitEgl();
        appletUnhook(&applet_hook_cookie);
        return EXIT_FAILURE;
    }
    gladLoadGL();

    NVGcontext* vg = nvgCreateGL3(NVG_ANTIALIAS | NVG_STENCIL_STROKES);
    if (!vg) {
        DeinitEgl();
        appletUnhook(&applet_hook_cookie);
        return EXIT_FAILURE;
    }

    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad{};
    padInitializeDefault(&pad);
    hidInitializeTouchScreen();

    yumi_nx::platform::SwitchYumiCtlClient ctl_client;
    yumi_nx::ui::YumiUiApp app(ctl_client, yumi_nx::paths::kFontDir, false);
    app.Init(vg);

    bool prev_touch = false;
    u64 prev_tick = armGetSystemTick();

    while (appletMainLoop()) {
        // Avoid eglSwapBuffers / nwindowDequeueBuffer while unfocused (HOME menu / sleep),
        // keeping the applet message pump responsive to FocusState and ExitRequest events.
        if (!s_in_focus.load() || appletGetFocusState() != AppletFocusState_InFocus) {
            svcSleepThread(50'000'000ULL);
            prev_tick = armGetSystemTick();
            prev_touch = false;
            continue;
        }

        const u64 now_tick = armGetSystemTick();
        const double raw_dt = static_cast<double>(armTicksToNs(now_tick - prev_tick)) / 1e9;
        const double dt_sec = std::clamp(raw_dt, 0.0, 0.1);
        prev_tick = now_tick;

        padUpdate(&pad);
        const u64 k_down = padGetButtonsDown(&pad);
        if (k_down & HidNpadButton_Plus) break;

        yumi_nx::ui::UiInputState input{};
        input.up = (k_down & (HidNpadButton_Up | HidNpadButton_StickLUp)) != 0;
        input.down = (k_down & (HidNpadButton_Down | HidNpadButton_StickLDown)) != 0;
        input.left = (k_down & (HidNpadButton_Left | HidNpadButton_StickLLeft)) != 0;
        input.right = (k_down & (HidNpadButton_Right | HidNpadButton_StickLRight)) != 0;
        input.confirm = (k_down & HidNpadButton_A) != 0;
        input.back = (k_down & HidNpadButton_B) != 0;
        input.action_x = (k_down & HidNpadButton_X) != 0;
        input.action_y = (k_down & HidNpadButton_Y) != 0;
        input.shoulder_l = (k_down & HidNpadButton_L) != 0;
        input.shoulder_r = (k_down & HidNpadButton_R) != 0;

        const HidAnalogStickState r_stick = padGetStickPos(&pad, 1);
        if (r_stick.y > 10000) input.scroll_delta = 0.6f;
        else if (r_stick.y < -10000) input.scroll_delta = -0.6f;

        HidTouchScreenState touch_state{};
        const bool touch_active = hidGetTouchScreenStates(&touch_state, 1) > 0 && touch_state.count > 0;
        if (touch_active && !prev_touch) {
            input.clicked = true;
            // Touch coordinates are always reported in 1280x720 logical space
            input.pointer_x = static_cast<float>(touch_state.touches[0].x);
            input.pointer_y = static_cast<float>(touch_state.touches[0].y);
        }
        prev_touch = touch_active;

        app.Update(dt_sec, input);

        glViewport(0, 0, static_cast<GLsizei>(win_w), static_cast<GLsizei>(win_h));
        glClearColor(0.035f, 0.043f, 0.059f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT | GL_STENCIL_BUFFER_BIT);

        app.Render(vg, static_cast<int>(win_w), static_cast<int>(win_h));
        eglSwapBuffers(s_display, s_surface);
    }

    app.Shutdown(vg);
    ctl_client.Disconnect();
    nvgDeleteGL3(vg);
    DeinitEgl();
    appletUnhook(&applet_hook_cookie);
    return EXIT_SUCCESS;
}
