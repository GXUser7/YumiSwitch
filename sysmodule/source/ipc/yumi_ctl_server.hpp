#pragma once

#include <switch.h>
#include <cstdint>
#include <vector>

#include "hos_compat.hpp"
#include "yumi_nx/ipc_protocol.hpp"
#include "yumi_nx/models.hpp"

namespace yumi_nx::net {
class TunnelEngine;
}

namespace yumi_nx::sys {

class NetworkMitmManager;

class YumiCtlServer {
public:
    explicit YumiCtlServer(const HosCompatInfo& hos, uint32_t heap_total_bytes);
    ~YumiCtlServer();

    void SetTunnelEngine(net::TunnelEngine* engine) noexcept { engine_ = engine; }
    void SetMitmManager(NetworkMitmManager* mitm) noexcept { mitm_ = mitm; }
    [[nodiscard]] net::TunnelEngine* GetTunnelEngine() const noexcept { return engine_; }

    bool StartService();
    void RunLoop();
    void StopService();

    void AppendLog(LogLevel level, const char* msg);

    AppSettings GetSettingsCopy();
    [[nodiscard]] bool IsTunnelActive();
    void RecordConnection(uint64_t program_id, const char* host, uint16_t port, bool is_udp, uint8_t route_action, uint8_t accepted);
    void AddTrafficBytes(uint64_t up_bytes, uint64_t down_bytes);
    void AdjustActiveSockets(int32_t delta);
    void SetMitmFlags(bool bsd_active, bool sfdnsres_active);
    void SetPowerNetFlags(bool psc_active, bool network_online);
    void TriggerAutoStart();
    void OnEnterSleep();
    void OnWakeUp();
    void OnNetworkOnlineChanged(bool online);

private:
    void LoadInitialConfig();
    bool HandleControlCommand(u32 cmd_id, u32& out_move_handle);
    Result HandleRequestCommand(u32 cmd_id, const HipcParsedRequest& parsed, u32& out_resp_size);
    void UpdateHeapStats();

    HosCompatInfo hos_{};
    Handle port_handle_ = INVALID_HANDLE;
    std::vector<Handle> sessions_;
    RMutex state_mutex_{};

    AppSettings settings_{};
    ProxyNode active_node_{};
    net::TunnelEngine* engine_ = nullptr;
    NetworkMitmManager* mitm_ = nullptr;
    ipc::IpcStatus status_{};
    ipc::IpcTrafficStats stats_{};
    std::vector<ipc::IpcLogLine> logs_;
    std::vector<ipc::IpcConnectionRecord> conn_logs_;
    uint32_t next_log_seq_ = 0;
    uint32_t next_conn_seq_ = 0;
    uint8_t mitm_flags_ = 0;
    bool was_active_before_sleep_ = false;
    uint64_t last_bps_tick_ns_ = 0;
    uint64_t window_up_bytes_ = 0;
    uint64_t window_down_bytes_ = 0;
    bool running_ = false;
};

}  // namespace yumi_nx::sys
