#pragma once

#include <switch.h>
#include <atomic>
#include <cstdint>

#include "mitm/sm_mitm.hpp"
#include "yumi_nx/net_interfaces.hpp"

namespace yumi_nx::sys {

class YumiCtlServer;

/// Intercepts `bsd:u` and `sfdnsres` via Atmosphère `sm:` MITM on HOS 19.x and 20.0+.
/// Phase 1: transparent HIPC passthrough with DNS query telemetry, QUIC blocking,
/// CustomRules routing evaluation, active socket tracking, and byte accounting.
class NetworkMitmManager {
public:
    explicit NetworkMitmManager(YumiCtlServer* ctl_server) noexcept;
    ~NetworkMitmManager();

    NetworkMitmManager(const NetworkMitmManager&) = delete;
    NetworkMitmManager& operator=(const NetworkMitmManager&) = delete;

    bool Start() noexcept;
    void Stop() noexcept;
    void ReloadRules() noexcept;

    [[nodiscard]] bool IsBsdMitmActive() const noexcept { return bsd_active_.load(); }
    [[nodiscard]] bool IsSfdnsresMitmActive() const noexcept { return dns_active_.load(); }

private:
    enum class ServiceKind : uint8_t {
        BsdU = 0,
        Sfdnsres = 1,
    };

    struct TrackedSocket {
        int32_t fd = -1;
        bool in_use = false;
        bool is_udp = false;
        bool proxied = false;
        uint32_t orig_ip_host = 0;
        uint16_t remote_port = 0;
        char remote_host[64] = {};
    };

    static constexpr size_t kMaxWorkers = 8;
    static constexpr size_t kSocketsPerWorker = 64;
    static constexpr size_t kWorkerStackSize = 0x3000;   // 12 KB
    static constexpr size_t kPointerSlotCount = 4;
    static constexpr size_t kPointerSlotSize = 0x400;    // 1 KB
    static constexpr size_t kStagingSize = 0x2000;       // 8 KB staging per active session (dyn fallback up to 512 KB)

    struct WorkerSlot {
        std::atomic<bool> stop_requested{false};
        std::atomic<bool> thread_finished{false};
        ServiceKind kind = ServiceKind::BsdU;
        NetworkMitmManager* manager = nullptr;
        Handle client_session = INVALID_HANDLE;
        Handle fwd_handle = INVALID_HANDLE;
        mitm_ipc::MitmProcessInfo proc_info{};
        Thread thread{};
        alignas(0x1000) uint8_t stack[kWorkerStackSize] = {};
        alignas(16) uint8_t ptr_rx_buf[kPointerSlotCount * kPointerSlotSize] = {};
        alignas(16) uint8_t ptr_tx_buf[kPointerSlotCount * kPointerSlotSize] = {};
        alignas(16) uint8_t staging_buf[kStagingSize] = {};
        TrackedSocket sockets[kSocketsPerWorker] = {};
        int32_t open_socket_delta = 0;
    };

    struct ServiceAcceptor {
        NetworkMitmManager* manager = nullptr;
        ServiceKind kind = ServiceKind::BsdU;
        const char* name = "";
        Handle server_port = INVALID_HANDLE;
        Handle query_session = INVALID_HANDLE;
        Thread server_thread{};
        Thread query_thread{};
        alignas(0x1000) uint8_t server_stack[0x3000] = {};
        alignas(0x1000) uint8_t query_stack[0x3000] = {};
        bool server_thread_started = false;
        bool query_thread_started = false;
        bool installed = false;
    };

    static void QueryThreadEntry(void* arg);
    static void ServerThreadEntry(void* arg);
    static void WorkerThreadEntry(void* arg);

    void RunQueryLoop(ServiceAcceptor& acc) noexcept;
    void RunServerLoop(ServiceAcceptor& acc) noexcept;
    void RunWorker(WorkerSlot& slot) noexcept;

    bool StartAcceptor(ServiceAcceptor& acc) noexcept;
    void StopAcceptor(ServiceAcceptor& acc) noexcept;
    void ReapFinishedWorkers(bool wait_all) noexcept;
    int AcquireWorkerIndex() noexcept;

    bool PreInspectBsd(WorkerSlot& slot,
                       void* tls_base,
                       const mitm_ipc::ParsedRequestInfo& parsed,
                       const AppSettings& cfg,
                       bool tunnel_active,
                       int32_t& out_track_fd,
                       bool& out_close_tracked,
                       uint32_t& out_cmif_cmd,
                       uint8_t out_override_sa[16],
                       size_t& out_override_sa_len) noexcept;

    bool PreInspectSfdnsres(WorkerSlot& slot,
                            void* tls_base,
                            const mitm_ipc::ParsedRequestInfo& parsed,
                            const AppSettings& cfg,
                            bool tunnel_active) noexcept;

    YumiCtlServer* ctl_server_ = nullptr;
    net::BasicRouter router_{};
    Mutex router_mutex_{};
    ServiceAcceptor bsd_acc_{};
    ServiceAcceptor dns_acc_{};
    WorkerSlot* workers_[kMaxWorkers] = {};
    Mutex workers_mutex_{};

    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> bsd_active_{false};
    std::atomic<bool> dns_active_{false};
};

}  // namespace yumi_nx::sys
