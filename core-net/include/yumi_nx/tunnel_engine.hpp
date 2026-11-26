#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "yumi_nx/dns_engine.hpp"
#include "yumi_nx/models.hpp"
#include "yumi_nx/net_interfaces.hpp"
#include "yumi_nx/socket_io.hpp"

#ifdef __SWITCH__
#include <switch.h>
#else
#include <mutex>
#include <thread>
#endif

namespace yumi_nx::net {

/// Non-blocking single-event-loop TCP/UDP loopback proxy engine for yumi-sysmodule & host E2E tests.
/// Receives redirected `bsd:u::Connect` loopback flows mapped by ephemeral client port.
class TunnelEngine {
public:
    using TrafficCallback = std::function<void(uint64_t up_bytes, uint64_t down_bytes)>;
    using LogCallback = std::function<void(LogLevel level, const char* msg)>;

    TunnelEngine() noexcept;
    ~TunnelEngine();

    TunnelEngine(const TunnelEngine&) = delete;
    TunnelEngine& operator=(const TunnelEngine&) = delete;

    void SetCallbacks(TrafficCallback on_traffic, LogCallback on_log) noexcept;

    /// Opens loopback relay port (if `preferred_port == 0`, OS picks ephemeral port) and starts active node tunnel.
    /// Set `spawn_thread = false` in deterministic single-threaded tests that pump `StepOnce()` manually.
    bool Start(const ProxyNode& node,
               const AppSettings& settings,
               bool spawn_thread = true,
               uint16_t preferred_port = 0) noexcept;

    void Stop() noexcept;
    void UpdateSettings(const AppSettings& settings) noexcept;
    void ResetAllFlows() noexcept;

    [[nodiscard]] bool IsRunning() const noexcept { return running_.load(); }
    [[nodiscard]] uint16_t RelayPort() const noexcept { return relay_port_.load(); }
    [[nodiscard]] uint32_t ActiveFlowCount() const noexcept { return active_flow_count_.load(); }
    [[nodiscard]] uint64_t TotalUplinkBytes() const noexcept { return total_up_.load(); }
    [[nodiscard]] uint64_t TotalDownlinkBytes() const noexcept { return total_down_.load(); }

    FakeIpPool& FakeIps() noexcept { return fake_ips_; }
    DohResolver& Resolver() noexcept { return resolver_; }

    /// Registers caller's bound loopback `src_port` -> real destination `target` before caller calls Connect(127.0.0.1:relay_port).
    void RegisterPendingTarget(uint16_t src_port, const Endpoint& target) noexcept;

    /// Pumps listener + all active flows once (non-blocking event loop tick).
    void StepOnce(int timeout_ms = 20) noexcept;

private:
    static constexpr size_t kMaxFlows = 32;
    static constexpr size_t kMaxPending = 64;
    static constexpr size_t kIoBufCap = 16384;

    struct PendingTarget {
        bool valid = false;
        uint16_t src_port = 0;
        Endpoint target{};
        uint64_t created_ms = 0;
    };

    struct RelayFlow {
        NetSocket client;
        std::unique_ptr<IOutboundStream> outbound;
        Endpoint target{};
        std::vector<uint8_t> c2s_buf;
        size_t c2s_off = 0;
        std::vector<uint8_t> s2c_buf;
        size_t s2c_off = 0;
        bool client_eof = false;
        bool remote_eof = false;
    };

    bool PopPendingTarget(uint16_t src_port, Endpoint& out_target) noexcept;
    void AcceptPendingConnections() noexcept;
    void PumpFlows(int timeout_ms) noexcept;
    void CloseAllFlows() noexcept;
    void Log(LogLevel lvl, const char* msg) noexcept;

#ifdef __SWITCH__
    static void ThreadEntry(void* arg);
    Mutex state_mutex_{};
    Thread thread_{};
    alignas(0x1000) uint8_t thread_stack_[0x8000] = {};  // 32 KB for TLS handshake + poll
    bool thread_started_ = false;
#else
    std::mutex state_mutex_;
    std::thread worker_;
#endif

    alignas(16) uint8_t io_scratch_[8192] = {};

    void Lock() noexcept;
    void Unlock() noexcept;

    ProxyNode active_node_{};
    AppSettings settings_{};
    FakeIpPool fake_ips_{};
    DohResolver resolver_{};
    NetSocket listen_sock_{};

    std::vector<PendingTarget> pending_;
    std::vector<std::unique_ptr<RelayFlow>> flows_;

    TrafficCallback on_traffic_;
    LogCallback on_log_;

    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> reset_requested_{false};
    std::atomic<uint16_t> relay_port_{0};
    std::atomic<uint32_t> active_flow_count_{0};
    std::atomic<uint64_t> total_up_{0};
    std::atomic<uint64_t> total_down_{0};
};

}  // namespace yumi_nx::net
