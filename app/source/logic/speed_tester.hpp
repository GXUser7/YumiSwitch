#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include "sync_util.hpp"
#include "yumi_nx/models.hpp"

namespace yumi_nx::logic {

struct SpeedTestConfig {
    std::string download_url = "https://speed.cloudflare.com/__down?bytes=2000000";
    std::string upload_url = "https://speed.cloudflare.com/__up";
    size_t upload_bytes = 512 * 1024;
    const ProxyNode* via_node = nullptr;
    AppSettings settings{};
    int timeout_ms = 12000;
};

struct SpeedTestState {
    bool running = false;
    bool finished = false;
    bool ok = false;
    double progress_0_1 = 0.0;
    double download_mbps = 0.0;
    double upload_mbps = 0.0;
    int ping_ms = -1;
    std::string summary = "Готов к замеру";
    std::string error;
};

using SpeedProgressCallback = std::function<void(const SpeedTestState&)>;

[[nodiscard]] SpeedTestState RunSpeedTestSync(const SpeedTestConfig& cfg,
                                              const SpeedProgressCallback& on_progress = {},
                                              std::atomic<bool>* cancel = nullptr);

class AsyncSpeedTestRunner {
public:
    AsyncSpeedTestRunner() noexcept = default;
    ~AsyncSpeedTestRunner() { Stop(); }

    AsyncSpeedTestRunner(const AsyncSpeedTestRunner&) = delete;
    AsyncSpeedTestRunner& operator=(const AsyncSpeedTestRunner&) = delete;

    bool Start(const SpeedTestConfig& cfg);
    void Stop() noexcept;

    [[nodiscard]] SpeedTestState Snapshot();
    [[nodiscard]] bool IsRunning() const noexcept { return running_.load(); }

private:
    static void ThreadEntry(void* arg);
    void Run();

    SimpleMutex mu_{};
    WorkerThread worker_{};
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> running_{false};

    SpeedTestConfig cfg_{};
    ProxyNode owned_via_node_{};
    bool has_via_node_ = false;
    SpeedTestState state_{};
};

}  // namespace yumi_nx::logic
