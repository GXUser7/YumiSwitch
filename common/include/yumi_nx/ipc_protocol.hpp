#pragma once

#include <cstdint>
#include <string>
#include <type_traits>
#include <vector>

#include "yumi_nx/models.hpp"

namespace yumi_nx::ipc {

inline constexpr uint64_t kYumiProgramId = 0x4200000000079801ULL;
inline constexpr const char* kYumiCtlServiceName = "yumi:ctl";
inline constexpr uint32_t kIpcProtocolVersion = 1;

enum class HosGeneration : uint8_t {
    Unknown = 0,
    Pre19 = 1,
    Hos19 = 2,
    Hos20Plus = 3,
};

enum class YumiCtlCmd : uint32_t {
    GetVersion = 0,
    GetStatus = 1,
    Start = 2,
    Stop = 3,
    ReloadConfig = 4,
    SelectActiveNode = 5,
    SetRoutingMode = 6,
    GetTrafficStats = 7,
    GetLogs = 8,
    GetConnectionLog = 9,
    ResetConnections = 10,
    Shutdown = 11,
};

namespace mitm_flag {
inline constexpr uint8_t kBsdMitmActive      = 1u << 0;  // bsd:u MITM active
inline constexpr uint8_t kSfdnsresMitmActive = 1u << 1;  // sfdnsres MITM active
inline constexpr uint8_t kPscMonitorActive   = 1u << 2;  // psc:m Sleep/Wake hook active
inline constexpr uint8_t kNetworkOnline      = 1u << 3;  // nifm:u internet connected
}  // namespace mitm_flag

struct IpcVersionInfo {
    uint32_t protocol_version = kIpcProtocolVersion;
    uint32_t hos_version_raw = 0;  // packed HOS version from hosversionGet()
    HosGeneration hos_generation = HosGeneration::Unknown;
    uint8_t mitm_active = 0;       // bitmask of mitm_flag::*
    uint16_t reserved = 0;
};
static_assert(std::is_trivially_copyable_v<IpcVersionInfo>);
static_assert(sizeof(IpcVersionInfo) == 12);

struct IpcStatus {
    TunnelState state = TunnelState::Off;
    RoutingMode routing_mode = RoutingMode::Rules;
    Protocol active_protocol = Protocol::Vless;
    uint8_t last_error_code = 0;
    uint64_t connected_at_epoch_sec = 0;
    char active_node_id[32] = {};
    char active_node_name[64] = {};
    char status_message[96] = {};
};
static_assert(std::is_trivially_copyable_v<IpcStatus>);

struct IpcTrafficStats {
    uint64_t uplink_bytes = 0;
    uint64_t downlink_bytes = 0;
    uint64_t uplink_bps = 0;
    uint64_t downlink_bps = 0;
    uint32_t active_sockets = 0;
    uint32_t sysmodule_heap_used_bytes = 0;
    uint32_t sysmodule_heap_total_bytes = 0;
    uint32_t reserved = 0;
};
static_assert(std::is_trivially_copyable_v<IpcTrafficStats>);
static_assert(sizeof(IpcTrafficStats) == 48);

struct IpcLogLine {
    uint64_t timestamp_ms = 0;
    LogLevel level = LogLevel::Info;
    uint8_t reserved[3] = {};
    uint32_t sequence_id = 0;
    char message[160] = {};
};
static_assert(std::is_trivially_copyable_v<IpcLogLine>);

struct IpcConnectionRecord {
    uint64_t timestamp_ms = 0;
    uint64_t program_id = 0;
    uint32_t sequence_id = 0;
    uint16_t port = 0;
    uint8_t is_udp = 0;
    uint8_t route_action = 0;  // 0=Proxy, 1=Direct, 2=Block, 3=Dns
    uint8_t accepted = 1;
    uint8_t reserved[7] = {};
    char host[96] = {};
};
static_assert(std::is_trivially_copyable_v<IpcConnectionRecord>);

// Shared control interface implemented by SwitchYumiCtlClient (libnx IPC) and MockYumiCtlClient (Desktop).
class IYumiCtlClient {
public:
    virtual ~IYumiCtlClient() = default;

    [[nodiscard]] virtual bool IsConnected() = 0;
    virtual bool GetVersion(IpcVersionInfo& out) = 0;
    virtual bool GetStatus(IpcStatus& out) = 0;
    virtual bool Start() = 0;
    virtual bool Stop() = 0;
    virtual bool ReloadConfig() = 0;
    virtual bool SelectActiveNode(const std::string& node_id) = 0;
    virtual bool SetRoutingMode(RoutingMode mode) = 0;
    virtual bool GetTrafficStats(IpcTrafficStats& out) = 0;
    virtual bool GetLogs(uint32_t since_seq, std::vector<IpcLogLine>& out) = 0;
    virtual bool GetConnectionLog(uint32_t since_seq, std::vector<IpcConnectionRecord>& out) = 0;
    virtual bool ResetConnections() = 0;
};

inline HosGeneration ClassifyHosVersion(uint32_t packed_version) noexcept {
    // libnx MAKEHOSVERSION packs major in bits 16..23: (major << 16) | (minor << 8) | micro
    const uint32_t major = (packed_version >> 16) & 0xFFu;
    if (major == 0) return HosGeneration::Unknown;
    if (major < 19) return HosGeneration::Pre19;
    if (major == 19) return HosGeneration::Hos19;
    return HosGeneration::Hos20Plus;
}

}  // namespace yumi_nx::ipc
