#include "power/power_net_monitor.hpp"

#include "ipc/yumi_ctl_server.hpp"
#include "yumi_nx/ipc_protocol.hpp"

namespace yumi_nx::sys {

namespace {
// Custom PM module ID outside Nintendo's reserved ranges (< 0x100).
constexpr PscPmModuleId kYumiPscModuleId = static_cast<PscPmModuleId>(0x198);
constexpr u64 kPollTimeoutNs = 500'000'000ULL;  // 500 ms
}  // namespace

PowerNetMonitor::PowerNetMonitor(YumiCtlServer* ctl_server) noexcept
    : ctl_server_(ctl_server) {}

PowerNetMonitor::~PowerNetMonitor() {
    Stop();
}

bool PowerNetMonitor::InitServices() noexcept {
    Result nifm_rc = nifmInitialize(NifmServiceType_User);
    nifm_inited_ = R_SUCCEEDED(nifm_rc);
    if (!nifm_inited_ && ctl_server_) {
        ctl_server_->AppendLog(LogLevel::Warn, "nifm:u unavailable for net monitor");
    }

    Result psc_rc = pscmInitialize();
    pscm_inited_ = R_SUCCEEDED(psc_rc);
    if (pscm_inited_) {
        u32 deps[] = {static_cast<u32>(PscPmModuleId_Nifm)};
        Result mod_rc = pscmGetPmModule(&psc_module_, kYumiPscModuleId, deps, 1, true);
        psc_mod_open_ = R_SUCCEEDED(mod_rc);
        psc_active_.store(psc_mod_open_);
        if (!psc_mod_open_ && ctl_server_) {
            ctl_server_->AppendLog(LogLevel::Warn, "psc:m module acquire failed; sleep hook inactive");
        }
    } else if (ctl_server_) {
        ctl_server_->AppendLog(LogLevel::Warn, "psc:m unavailable; sleep hook inactive");
    }

    return nifm_inited_ || psc_mod_open_;
}

bool PowerNetMonitor::Start() noexcept {
    if (thread_created_) {
        return true;
    }

    InitServices();
    stop_requested_.store(false);

    if (ctl_server_) {
        ctl_server_->SetPowerNetFlags(psc_active_.load(), network_online_.load());
    }

    Result rc = threadCreate(&thread_, &PowerNetMonitor::ThreadEntry, this, thread_stack_, sizeof(thread_stack_), 0x3B, -2);
    if (R_FAILED(rc)) {
        if (ctl_server_) {
            ctl_server_->AppendLog(LogLevel::Error, "PowerNetMonitor threadCreate failed");
        }
        return false;
    }

    rc = threadStart(&thread_);
    if (R_FAILED(rc)) {
        threadClose(&thread_);
        if (ctl_server_) {
            ctl_server_->AppendLog(LogLevel::Error, "PowerNetMonitor threadStart failed");
        }
        return false;
    }

    thread_created_ = true;
    return true;
}

void PowerNetMonitor::Stop() noexcept {
    if (thread_created_) {
        stop_requested_.store(true);
        threadWaitForExit(&thread_);
        threadClose(&thread_);
        thread_created_ = false;
    }

    if (psc_mod_open_) {
        pscPmModuleFinalize(&psc_module_);
        pscPmModuleClose(&psc_module_);
        psc_mod_open_ = false;
    }
    if (pscm_inited_) {
        pscmExit();
        pscm_inited_ = false;
    }
    if (nifm_inited_) {
        nifmExit();
        nifm_inited_ = false;
    }
    psc_active_.store(false);
}

void PowerNetMonitor::ThreadEntry(void* arg) {
    if (auto* self = static_cast<PowerNetMonitor*>(arg)) {
        self->Run();
    }
}

void PowerNetMonitor::PollNetworkStatus(bool force_notify) noexcept {
    bool online = false;
    if (nifm_inited_) {
        NifmInternetConnectionType conn_type{};
        u32 wifi_strength = 0;
        NifmInternetConnectionStatus conn_status{};
        const Result rc = nifmGetInternetConnectionStatus(&conn_type, &wifi_strength, &conn_status);
        online = R_SUCCEEDED(rc) && (conn_status == NifmInternetConnectionStatus_Connected);
    }

    const bool prev = network_online_.exchange(online);
    if (force_notify || prev != online) {
        if (ctl_server_) {
            ctl_server_->SetPowerNetFlags(psc_active_.load(), online);
            ctl_server_->OnNetworkOnlineChanged(online);
        }
    }

    if (online && !initial_boot_connect_done_ && !sleeping_ && ctl_server_) {
        initial_boot_connect_done_ = true;
        const auto cfg = ctl_server_->GetSettingsCopy();
        if (cfg.auto_connect_on_boot && !ctl_server_->IsTunnelActive()) {
            ctl_server_->AppendLog(LogLevel::Info, "Auto-connect on boot: network online, starting tunnel");
            ctl_server_->TriggerAutoStart();
        }
    }
}

void PowerNetMonitor::HandlePscEvent() noexcept {
    if (!psc_mod_open_) {
        return;
    }

    PscPmState state{};
    u32 flags = 0;
    const Result rc = pscPmModuleGetRequest(&psc_module_, &state, &flags);
    if (R_FAILED(rc)) {
        return;
    }

    if (state == PscPmState_ReadySleep || state == PscPmState_ReadyShutdown) {
        if (!sleeping_) {
            sleeping_ = true;
            if (ctl_server_) {
                ctl_server_->OnEnterSleep();
            }
        }
    } else if (state == PscPmState_Awake || state == PscPmState_ReadyAwaken) {
        if (sleeping_) {
            sleeping_ = false;
            if (ctl_server_) {
                ctl_server_->OnWakeUp();
            }
        }
        PollNetworkStatus(true);
    }

    // Must ALWAYS acknowledge psc:m transitions promptly or Horizon OS blocks Sleep/Wake!
    pscPmModuleAcknowledge(&psc_module_, state);
}

void PowerNetMonitor::Run() noexcept {
    PollNetworkStatus(true);

    uint32_t tick_counter = 0;
    while (!stop_requested_.load()) {
        if (psc_mod_open_) {
            const Result wait_rc = eventWait(&psc_module_.event, kPollTimeoutNs);
            if (R_SUCCEEDED(wait_rc)) {
                HandlePscEvent();
            }
        } else {
            svcSleepThread(kPollTimeoutNs);
        }

        if (++tick_counter >= 4) {  // ~2s periodic nifm poll
            tick_counter = 0;
            PollNetworkStatus(false);
        }
    }
}

}  // namespace yumi_nx::sys
