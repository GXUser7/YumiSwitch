#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "sync_util.hpp"
#include "yumi_nx/models.hpp"
#include "yumi_nx/net_interfaces.hpp"

namespace yumi_nx::logic {

enum class LatencyTestMethod : uint8_t {
    TcpConnect = 0,
    TlsHandshake = 1,
    UrlTest = 2,
};

struct LatencyResult {
    std::string node_id;
    int ping_ms = -1;
};

/// Executes a single probe (`TcpConnect`, `TlsHandshake`, or `UrlTest` through `node`). Returns >= 1 ms or -1 on error.
[[nodiscard]] int ProbeNodeLatency(const ProxyNode& node,
                                   const AppSettings& settings,
                                   LatencyTestMethod method,
                                   net::IDnsResolver* resolver = nullptr,
                                   int timeout_ms = 4000,
                                   std::string_view test_url = "http://cp.cloudflare.com/generate_204");

/// Runs `samples` (e.g. 1 or 3) probes and returns the median valid latency in ms (-1 if all failed).
[[nodiscard]] int ProbeNodeMedianLatency(const ProxyNode& node,
                                         const AppSettings& settings,
                                         LatencyTestMethod method,
                                         int samples = 3,
                                         net::IDnsResolver* resolver = nullptr,
                                         int timeout_ms = 4000,
                                         std::string_view test_url = "http://cp.cloudflare.com/generate_204");

/// Asynchronous bounded-concurrency latency tester for UI node lists and Yumi Remote `ping_all`.
class AsyncLatencyBatch {
public:
    AsyncLatencyBatch() noexcept = default;
    ~AsyncLatencyBatch() { Stop(); }

    AsyncLatencyBatch(const AsyncLatencyBatch&) = delete;
    AsyncLatencyBatch& operator=(const AsyncLatencyBatch&) = delete;

    bool Start(std::vector<ProxyNode> nodes,
               AppSettings settings,
               LatencyTestMethod method = LatencyTestMethod::TcpConnect,
               int samples = 1,
               int timeout_ms = 3500,
               int concurrency = 3,
               std::string test_url = "http://cp.cloudflare.com/generate_204");

    void Stop() noexcept;

    void DrainCompleted(std::vector<LatencyResult>& out);
    [[nodiscard]] bool IsRunning() const noexcept { return active_workers_.load() > 0; }
    [[nodiscard]] int CompletedCount() const noexcept { return completed_.load(); }
    [[nodiscard]] int TotalCount() const noexcept { return total_.load(); }

private:
    static void WorkerEntry(void* arg);
    void RunWorker();

    static constexpr int kMaxWorkers = 4;
    SimpleMutex mu_{};
    WorkerThread workers_[kMaxWorkers]{};
    int spawned_count_ = 0;

    std::atomic<bool> stop_requested_{false};
    std::atomic<int> active_workers_{0};
    std::atomic<int> next_index_{0};
    std::atomic<int> completed_{0};
    std::atomic<int> total_{0};

    std::vector<ProxyNode> nodes_;
    AppSettings settings_{};
    LatencyTestMethod method_ = LatencyTestMethod::TcpConnect;
    int samples_ = 1;
    int timeout_ms_ = 3500;
    std::string test_url_ = "http://cp.cloudflare.com/generate_204";
    std::vector<LatencyResult> results_;
};

}  // namespace yumi_nx::logic
