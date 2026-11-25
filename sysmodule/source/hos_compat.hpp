#pragma once

#include <switch.h>
#include <cstdint>

#include "yumi_nx/ipc_protocol.hpp"

namespace yumi_nx::sys {

struct HosCompatInfo {
    uint32_t packed_version = 0;
    ipc::HosGeneration generation = ipc::HosGeneration::Unknown;
    uint32_t recommended_max_heap_bytes = 5u * 1024u * 1024u;
};

inline HosCompatInfo DetectHosCompat() noexcept {
    HosCompatInfo info{};
    info.packed_version = hosversionGet();
    info.generation = ipc::ClassifyHosVersion(info.packed_version);
    // HOS 20.0+ restricts total applet pool theft across all sysmodules to ~14 MB.
    // Enforce a strict <= 5.5 MB target on HOS 20.0+, while still keeping <= 6 MB everywhere.
    info.recommended_max_heap_bytes =
        (info.generation == ipc::HosGeneration::Hos20Plus) ? (5u * 1024u * 1024u + 512u * 1024u)
                                                           : (6u * 1024u * 1024u);
    return info;
}

// Known bsd:u CMIF command IDs verified against libnx 4.12 / HOS 19.x-20.0+.
namespace bsd_cmd {
inline constexpr uint32_t kRegisterClient = 0;
inline constexpr uint32_t kStartMonitoring = 1;
inline constexpr uint32_t kSocket = 2;
inline constexpr uint32_t kSocketExempt = 3;
inline constexpr uint32_t kRecv = 8;
inline constexpr uint32_t kRecvFrom = 9;
inline constexpr uint32_t kSend = 10;
inline constexpr uint32_t kSendTo = 11;
inline constexpr uint32_t kAccept = 12;
inline constexpr uint32_t kBind = 13;
inline constexpr uint32_t kConnect = 14;
inline constexpr uint32_t kGetPeerName = 15;
inline constexpr uint32_t kGetSockName = 16;
inline constexpr uint32_t kWrite = 24;
inline constexpr uint32_t kRead = 25;
inline constexpr uint32_t kClose = 26;
inline constexpr uint32_t kDuplicateSocket = 27;
inline constexpr uint32_t kRecvMMsg = 29;
inline constexpr uint32_t kSendMMsg = 30;
inline constexpr uint32_t kRegisterClientShared = 33;
}  // namespace bsd_cmd

// Known sfdnsres CMIF command IDs (HOS 19.x-20.0+).
namespace sfdnsres_cmd {
inline constexpr uint32_t kGetHostByNameRequest = 2;
inline constexpr uint32_t kGetHostByAddrRequest = 3;
inline constexpr uint32_t kGetAddrInfoRequest = 6;
inline constexpr uint32_t kGetNameInfoRequest = 7;
inline constexpr uint32_t kGetHostByNameRequestWithOptions = 10;
inline constexpr uint32_t kGetAddrInfoRequestWithOptions = 12;
}  // namespace sfdnsres_cmd

// Atmosphère sm: MITM extension command IDs (TIPC / CMIF on Atmosphère 1.7+).
namespace sm_mitm_cmd {
inline constexpr uint32_t kAtmosphereInstallMitm = 65000;
inline constexpr uint32_t kAtmosphereUninstallMitm = 65001;
inline constexpr uint32_t kAtmosphereAcknowledgeMitmSession = 65003;
inline constexpr uint32_t kQueryShouldMitm = 65000;
}  // namespace sm_mitm_cmd

}  // namespace yumi_nx::sys
