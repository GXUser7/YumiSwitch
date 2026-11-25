#pragma once

#include <chrono>
#include <cmath>
#include <cstdint>
#include <vector>

#include "yumi_nx/ipc_protocol.hpp"

namespace yumi_nx::platform {

class MockYumiCtlClient final : public ipc::IYumiCtlClient {
public:
    MockYumiCtlClient() {
        version_.protocol_version = ipc::kIpcProtocolVersion;
        version_.hos_version_raw = 0x00140000u;  // HOS 20.0.0
        version_.hos_generation = ipc::HosGeneration::Hos20Plus;
        version_.mitm_active = ipc::mitm_flag::kBsdMitmActive |
                               ipc::mitm_flag::kSfdnsresMitmActive |
                               ipc::mitm_flag::kPscMonitorActive |
                               ipc::mitm_flag::kNetworkOnline;

        status_.state = TunnelState::Off;
        status_.routing_mode = RoutingMode::Rules;
        status_.active_protocol = Protocol::Vless;
        CopyStr(status_.active_node_id, "fi1");
        CopyStr(status_.active_node_name, "Финляндия · Хельсинки #1");
        CopyStr(status_.status_message, "Готов · HOS 20.0+ (Mock)");

        stats_.sysmodule_heap_used_bytes = 2150u * 1024u;
        stats_.sysmodule_heap_total_bytes = 5632u * 1024u;  // 5.5 MB

        AppendLog(LogLevel::Info, "Mock yumi:ctl ready (bsd:u + sfdnsres + psc)");
        SeedConnections();
    }

    void Tick(double dt_sec) {
        if (status_.state == TunnelState::Connecting) {
            connect_elapsed_ += dt_sec;
            if (connect_elapsed_ >= 0.45) {
                status_.state = TunnelState::On;
                status_.connected_at_epoch_sec = NowSec();
                stats_.sysmodule_heap_used_bytes = 3482u * 1024u;  // ~3.4 MB
                CopyStr(status_.status_message, "Туннель активен (Mock Preview)");
                AppendLog(LogLevel::Info, "Tunnel connected (Mock)");
            }
        } else if (status_.state == TunnelState::On) {
            phase_ += dt_sec;
            const uint64_t down = static_cast<uint64_t>(14'200'000 + 2'400'000 * (0.5 + 0.5 * std::sin(phase_ * 0.7)));
            const uint64_t up = static_cast<uint64_t>(950'000 + 450'000 * (0.5 + 0.5 * std::cos(phase_ * 0.9)));
            stats_.downlink_bps = down;
            stats_.uplink_bps = up;
            stats_.downlink_bytes += static_cast<uint64_t>(down * dt_sec);
            stats_.uplink_bytes += static_cast<uint64_t>(up * dt_sec);
            stats_.active_sockets = 18;
            stats_.sysmodule_heap_used_bytes = 3482u * 1024u;
        } else {
            stats_.downlink_bps = 0;
            stats_.uplink_bps = 0;
            stats_.active_sockets = 2;
            stats_.sysmodule_heap_used_bytes = 2150u * 1024u;
        }
    }

    bool IsConnected() override { return true; }
    bool GetVersion(ipc::IpcVersionInfo& out) override { out = version_; return true; }
    bool GetStatus(ipc::IpcStatus& out) override { out = status_; return true; }

    bool Start() override {
        if (status_.state == TunnelState::On || status_.state == TunnelState::Connecting) return true;
        status_.state = TunnelState::Connecting;
        connect_elapsed_ = 0.0;
        CopyStr(status_.status_message, "Подключение (Mock)...");
        AppendLog(LogLevel::Info, "Start() requested via MockYumiCtlClient");
        return true;
    }

    void ForceConnectedImmediate() {
        status_.state = TunnelState::On;
        status_.connected_at_epoch_sec = NowSec();
        stats_.sysmodule_heap_used_bytes = 3482u * 1024u;
        stats_.active_sockets = 18;
        stats_.downlink_bps = 14800000ULL;
        stats_.uplink_bps = 1150000ULL;
    }

    bool Stop() override {
        status_.state = TunnelState::Off;
        status_.connected_at_epoch_sec = 0;
        CopyStr(status_.status_message, "Отключено");
        AppendLog(LogLevel::Info, "Stop() requested via MockYumiCtlClient");
        return true;
    }

    bool ReloadConfig() override {
        AppendLog(LogLevel::Info, "ReloadConfig() OK");
        return true;
    }

    bool SelectActiveNode(const std::string& node_id) override {
        CopyStr(status_.active_node_id, node_id.c_str());
        if (node_id == "nl1") {
            status_.active_protocol = Protocol::WireGuard;
            CopyStr(status_.active_node_name, "Нидерланды · Амстердам");
        } else if (node_id == "de1") {
            status_.active_protocol = Protocol::Hysteria2;
            CopyStr(status_.active_node_name, "Германия · Франкфурт");
        } else if (node_id == "se1") {
            status_.active_protocol = Protocol::Trojan;
            CopyStr(status_.active_node_name, "Швеция · Стокгольм");
        } else {
            status_.active_protocol = Protocol::Vless;
            CopyStr(status_.active_node_name, "Финляндия · Хельсинки #1");
        }
        AppendLog(LogLevel::Info, ("Selected node: " + node_id).c_str());
        return true;
    }

    bool SetRoutingMode(RoutingMode mode) override {
        status_.routing_mode = mode;
        AppendLog(LogLevel::Info, (std::string("Routing mode -> ") + ToString(mode)).c_str());
        return true;
    }

    bool GetTrafficStats(ipc::IpcTrafficStats& out) override {
        out = stats_;
        return true;
    }

    bool GetLogs(uint32_t since_seq, std::vector<ipc::IpcLogLine>& out) override {
        out.clear();
        for (const auto& line : logs_) {
            if (line.sequence_id > since_seq) out.push_back(line);
        }
        return true;
    }

    bool GetConnectionLog(uint32_t since_seq, std::vector<ipc::IpcConnectionRecord>& out) override {
        out.clear();
        for (const auto& r : conns_) {
            if (r.sequence_id > since_seq) out.push_back(r);
        }
        return true;
    }

    bool ResetConnections() override {
        AppendLog(LogLevel::Warn, "ResetConnections() called");
        return true;
    }

private:
    template <size_t N>
    static void CopyStr(char (&dst)[N], const char* src) {
        std::snprintf(dst, N, "%s", src ? src : "");
    }

    static uint64_t NowSec() {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count());
    }

    void AppendLog(LogLevel lvl, const char* msg) {
        ipc::IpcLogLine line{};
        line.timestamp_ms = NowSec() * 1000ULL;
        line.level = lvl;
        line.sequence_id = ++next_seq_;
        CopyStr(line.message, msg);
        logs_.push_back(line);
        if (logs_.size() > 64) logs_.erase(logs_.begin());
    }

    void SeedConnections() {
        auto add = [&](uint64_t tid, const char* host, uint16_t port, uint8_t udp, uint8_t act) {
            ipc::IpcConnectionRecord rec{};
            rec.timestamp_ms = NowSec() * 1000ULL;
            rec.program_id = tid;
            rec.sequence_id = ++next_conn_seq_;
            rec.port = port;
            rec.is_udp = udp;
            rec.route_action = act;
            rec.accepted = (act != 2) ? 1 : 0;
            CopyStr(rec.host, host);
            conns_.push_back(rec);
        };
        add(0x01003A400C3DA000ULL, "rr4---sn-n8v7kn7l.googlevideo.com", 443, 0, 0);
        add(0x01003A400C3DA000ULL, "www.youtube.com", 443, 0, 0);
        add(0x01003A400C3DA000ULL, "www.youtube.com", 443, 1, 2);
        add(0x010000000000100FULL, "api.vk.com", 443, 0, 1);
        add(0ULL, "192.168.1.1", 80, 0, 1);
    }

    ipc::IpcVersionInfo version_{};
    ipc::IpcStatus status_{};
    ipc::IpcTrafficStats stats_{};
    std::vector<ipc::IpcLogLine> logs_;
    std::vector<ipc::IpcConnectionRecord> conns_;
    uint32_t next_seq_ = 0;
    uint32_t next_conn_seq_ = 0;
    double connect_elapsed_ = 0.0;
    double phase_ = 0.0;
};

}  // namespace yumi_nx::platform
