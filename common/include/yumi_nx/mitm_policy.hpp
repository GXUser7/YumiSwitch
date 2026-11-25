#pragma once

#include <cstdint>

#include "yumi_nx/ipc_protocol.hpp"

namespace yumi_nx::mitm {

inline constexpr uint64_t kMinUserAppletProgramId = 0x0100000000001000ULL;
inline constexpr uint64_t kYumiAppProgramId = 0x4200000000079802ULL;

[[nodiscard]] inline constexpr bool ShouldMitmProgramId(uint64_t program_id) noexcept {
    // Never intercept yumi-sysmodule itself (avoids MITM recursion) or core system sysmodules.
    if (program_id == ipc::kYumiProgramId) return false;
    if (program_id < kMinUserAppletProgramId) return false;
    return true;
}

}  // namespace yumi_nx::mitm
