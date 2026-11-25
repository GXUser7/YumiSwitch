#pragma once

#include <switch.h>
#include <atomic>
#include <cstdint>

namespace yumi_nx::sys {

class YumiCtlServer;

/// Monitors Horizon OS `psc:m` Sleep/Wake transitions and `nifm:u` Internet status.
/// Triggers clean tunnel reconnect / boot auto-connect without busy loops or heavy allocations.
class PowerNetMonitor {
public:
    explicit PowerNetMonitor(YumiCtlServer* ctl_server) noexcept;
    ~PowerNetMonitor();

    PowerNetMonitor(const PowerNetMonitor&) = delete;
    PowerNetMonitor& operator=(const PowerNetMonitor&) = delete;

    bool Start() noexcept;
    void Stop() noexcept;

    [[nodiscard]] bool IsPscActive() const noexcept { return psc_active_.load(); }
    [[nodiscard]] bool IsNetworkOnline() const noexcept { return network_online_.load(); }

private:
    static void ThreadEntry(void* arg);
    void Run() noexcept;
    bool InitServices() noexcept;
    void PollNetworkStatus(bool force_notify) noexcept;
    void HandlePscEvent() noexcept;

    YumiCtlServer* ctl_server_ = nullptr;
    Thread thread_{};
    alignas(0x1000) uint8_t thread_stack_[0x4000] = {};
    bool thread_created_ = false;
    std::atomic<bool> stop_requested_{false};

    bool nifm_inited_ = false;
    bool pscm_inited_ = false;
    bool psc_mod_open_ = false;
    PscPmModule psc_module_{};

    std::atomic<bool> psc_active_{false};
    std::atomic<bool> network_online_{false};
    bool sleeping_ = false;
    bool initial_boot_connect_done_ = false;
};

}  // namespace yumi_nx::sys
