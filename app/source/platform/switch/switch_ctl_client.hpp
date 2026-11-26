#pragma once

#include <switch.h>
#include <switch/sf/tipc.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>

#include "yumi_nx/ipc_protocol.hpp"

namespace yumi_nx::platform {

class SwitchYumiCtlClient final : public ipc::IYumiCtlClient {
public:
    SwitchYumiCtlClient() { TryConnect(); }

    ~SwitchYumiCtlClient() override {
        Disconnect();
    }

    void Disconnect() noexcept {
        HandleDisconnect();
    }

    bool IsConnected() override {
        if (serviceIsActive(&ctl_)) return true;
        return TryConnect();
    }

    bool GetVersion(ipc::IpcVersionInfo& out) override {
        if (!IsConnected()) return false;
        const Result rc = serviceDispatchOut(
            &ctl_, static_cast<u32>(ipc::YumiCtlCmd::GetVersion), out);
        if (R_FAILED(rc)) {
            HandleDisconnect();
            return false;
        }
        return true;
    }

    bool GetStatus(ipc::IpcStatus& out) override {
        if (!IsConnected()) return false;
        const Result rc = serviceDispatchOut(
            &ctl_, static_cast<u32>(ipc::YumiCtlCmd::GetStatus), out);
        if (R_FAILED(rc)) {
            HandleDisconnect();
            return false;
        }
        return true;
    }

    bool Start() override {
        if (!IsConnected()) return false;
        const Result rc = serviceDispatch(&ctl_, static_cast<u32>(ipc::YumiCtlCmd::Start));
        if (R_FAILED(rc)) {
            HandleDisconnect();
            return false;
        }
        return true;
    }

    bool Stop() override {
        if (!IsConnected()) return false;
        const Result rc = serviceDispatch(&ctl_, static_cast<u32>(ipc::YumiCtlCmd::Stop));
        if (R_FAILED(rc)) {
            HandleDisconnect();
            return false;
        }
        return true;
    }

    bool ReloadConfig() override {
        if (!IsConnected()) return false;
        const Result rc = serviceDispatch(&ctl_, static_cast<u32>(ipc::YumiCtlCmd::ReloadConfig));
        if (R_FAILED(rc)) {
            HandleDisconnect();
            return false;
        }
        return true;
    }

    bool SelectActiveNode(const std::string& node_id) override {
        if (!IsConnected()) return false;
        std::array<char, 32> buf{};
        const size_t copy_len = std::min<size_t>(node_id.size(), buf.size() - 1);
        std::memcpy(buf.data(), node_id.data(), copy_len);
        const Result rc = serviceDispatchIn(
            &ctl_, static_cast<u32>(ipc::YumiCtlCmd::SelectActiveNode), buf);
        if (R_FAILED(rc)) {
            HandleDisconnect();
            return false;
        }
        return true;
    }

    bool SetRoutingMode(RoutingMode mode) override {
        if (!IsConnected()) return false;
        const uint8_t m = static_cast<uint8_t>(mode);
        const Result rc = serviceDispatchIn(
            &ctl_, static_cast<u32>(ipc::YumiCtlCmd::SetRoutingMode), m);
        if (R_FAILED(rc)) {
            HandleDisconnect();
            return false;
        }
        return true;
    }

    bool GetTrafficStats(ipc::IpcTrafficStats& out) override {
        if (!IsConnected()) return false;
        const Result rc = serviceDispatchOut(
            &ctl_, static_cast<u32>(ipc::YumiCtlCmd::GetTrafficStats), out);
        if (R_FAILED(rc)) {
            HandleDisconnect();
            return false;
        }
        return true;
    }

    bool GetLogs(uint32_t since_seq, std::vector<ipc::IpcLogLine>& out) override {
        out.clear();
        if (!IsConnected()) return false;
        std::array<ipc::IpcLogLine, 32> buf{};
        u32 count = 0;
        const Result rc = serviceDispatchInOut(
            &ctl_, static_cast<u32>(ipc::YumiCtlCmd::GetLogs), since_seq, count,
            .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
            .buffers = {{buf.data(), sizeof(buf)}});
        if (R_FAILED(rc)) {
            HandleDisconnect();
            return false;
        }
        const u32 clamped = std::min<u32>(count, static_cast<u32>(buf.size()));
        out.assign(buf.begin(), buf.begin() + clamped);
        return true;
    }

    bool GetConnectionLog(uint32_t since_seq, std::vector<ipc::IpcConnectionRecord>& out) override {
        out.clear();
        if (!IsConnected()) return false;
        std::array<ipc::IpcConnectionRecord, 32> buf{};
        u32 count = 0;
        const Result rc = serviceDispatchInOut(
            &ctl_, static_cast<u32>(ipc::YumiCtlCmd::GetConnectionLog), since_seq, count,
            .buffer_attrs = {SfBufferAttr_HipcMapAlias | SfBufferAttr_Out},
            .buffers = {{buf.data(), sizeof(buf)}});
        if (R_FAILED(rc)) {
            HandleDisconnect();
            return false;
        }
        const u32 clamped = std::min<u32>(count, static_cast<u32>(buf.size()));
        out.assign(buf.begin(), buf.begin() + clamped);
        return true;
    }

    bool ResetConnections() override {
        if (!IsConnected()) return false;
        const Result rc = serviceDispatch(&ctl_, static_cast<u32>(ipc::YumiCtlCmd::ResetConnections));
        if (R_FAILED(rc)) {
            HandleDisconnect();
            return false;
        }
        return true;
    }

private:
    static constexpr uint64_t kReconnectCooldownMs = 1000ULL;

    static uint64_t NowMs() noexcept {
        return armTicksToNs(armGetSystemTick()) / 1000000ULL;
    }

    /// Queries Atmosphère sm: AtmosphereHasService (TIPC 65100) so smGetService never blocks indefinitely
    /// when yumi-sysmodule is stopped or disabled.
    static bool SmHasService(const char* name) noexcept {
        TipcService* sm = smGetServiceSessionTipc();
        if (!sm || sm->session == INVALID_HANDLE) return false;
        const SmServiceName encoded = smEncodeName(name);
        u8 has_service = 0;
        const TipcDispatchParams params{};
        const Result rc = tipcDispatchImpl(
            sm, 65100u, &encoded, sizeof(encoded), &has_service, sizeof(has_service), params);
        return R_SUCCEEDED(rc) && (has_service & 1u) != 0;
    }

    bool TryConnect() {
        const uint64_t now = NowMs();
        if (has_attempted_connect_ && (now - last_connect_attempt_ms_) < kReconnectCooldownMs) {
            return false;
        }
        has_attempted_connect_ = true;
        last_connect_attempt_ms_ = now;

        if (!SmHasService(ipc::kYumiCtlServiceName)) {
            return false;
        }
        return R_SUCCEEDED(smGetService(&ctl_, ipc::kYumiCtlServiceName));
    }

    void HandleDisconnect() noexcept {
        if (serviceIsActive(&ctl_)) {
            serviceClose(&ctl_);
        }
        has_attempted_connect_ = true;
        last_connect_attempt_ms_ = NowMs();
    }

    Service ctl_{};
    uint64_t last_connect_attempt_ms_ = 0;
    bool has_attempted_connect_ = false;
};

}  // namespace yumi_nx::platform
