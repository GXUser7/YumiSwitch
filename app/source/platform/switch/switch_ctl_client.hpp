#pragma once

#include <switch.h>
#include <array>
#include <cstring>
#include <vector>

#include "yumi_nx/ipc_protocol.hpp"

namespace yumi_nx::platform {

class SwitchYumiCtlClient final : public ipc::IYumiCtlClient {
public:
    SwitchYumiCtlClient() { TryConnect(); }

    ~SwitchYumiCtlClient() override {
        if (serviceIsActive(&ctl_)) {
            serviceClose(&ctl_);
        }
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
        return R_SUCCEEDED(serviceDispatch(&ctl_, static_cast<u32>(ipc::YumiCtlCmd::Start)));
    }

    bool Stop() override {
        if (!IsConnected()) return false;
        return R_SUCCEEDED(serviceDispatch(&ctl_, static_cast<u32>(ipc::YumiCtlCmd::Stop)));
    }

    bool ReloadConfig() override {
        if (!IsConnected()) return false;
        return R_SUCCEEDED(serviceDispatch(&ctl_, static_cast<u32>(ipc::YumiCtlCmd::ReloadConfig)));
    }

    bool SelectActiveNode(const std::string& node_id) override {
        if (!IsConnected()) return false;
        std::array<char, 32> buf{};
        const size_t copy_len = std::min<size_t>(node_id.size(), buf.size() - 1);
        std::memcpy(buf.data(), node_id.data(), copy_len);
        return R_SUCCEEDED(serviceDispatchIn(
            &ctl_, static_cast<u32>(ipc::YumiCtlCmd::SelectActiveNode), buf));
    }

    bool SetRoutingMode(RoutingMode mode) override {
        if (!IsConnected()) return false;
        const uint8_t m = static_cast<uint8_t>(mode);
        return R_SUCCEEDED(serviceDispatchIn(
            &ctl_, static_cast<u32>(ipc::YumiCtlCmd::SetRoutingMode), m));
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
        return R_SUCCEEDED(serviceDispatch(&ctl_, static_cast<u32>(ipc::YumiCtlCmd::ResetConnections)));
    }

private:
    bool TryConnect() {
        return R_SUCCEEDED(smGetService(&ctl_, ipc::kYumiCtlServiceName));
    }

    void HandleDisconnect() {
        if (serviceIsActive(&ctl_)) {
            serviceClose(&ctl_);
        }
    }

    Service ctl_{};
};

}  // namespace yumi_nx::platform
