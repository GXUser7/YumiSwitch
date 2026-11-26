#pragma once

#include <cstdint>

#include "yumi_nx/ipc_protocol.hpp"

namespace yumi_nx::mitm {

// System applets sit in 0x0100000000001000..0x010000000000FFFF; regular user applications start at 0x0100000000010000.
inline constexpr uint64_t kMinUserApplicationProgramId = 0x0100000000010000ULL;
inline constexpr uint64_t kMinUserAppletProgramId = 0x0100000000001000ULL;
inline constexpr uint64_t kYumiAppProgramId = 0x4200000000079802ULL;

[[nodiscard]] inline constexpr bool IsWebBrowserAppletProgramId(uint64_t program_id) noexcept {
    return program_id == 0x010000000000100AULL ||  // web
           program_id == 0x010000000000100BULL ||  // shop
           program_id == 0x010000000000100FULL ||  // offlineWeb / browser
           program_id == 0x0100000000001010ULL ||  // wifiWebAuth
           program_id == 0x0100000000001011ULL;    // whitelistedWeb
}

[[nodiscard]] inline constexpr bool ShouldMitmProgramId(uint64_t program_id) noexcept {
    // Never intercept yumi-sysmodule, yumi.nro (NSP), or any custom 0x42... sysmodules (avoids recursion & system hangs).
    if (program_id == ipc::kYumiProgramId || program_id == kYumiAppProgramId) return false;
    if ((program_id & 0xFF00000000000000ULL) == 0x4200000000000000ULL) return false;

    // Allow explicit HOS Web Browser applets while skipping qlaunch (1000), overlayDisp (100C), Album (100D), etc.
    if (IsWebBrowserAppletProgramId(program_id)) return true;

    // Never intercept HOS sysmodules (< 0x0100000000001000) or non-browser system applets (< 0x0100000000010000).
    if (program_id < kMinUserApplicationProgramId) return false;
    return true;
}

}  // namespace yumi_nx::mitm
