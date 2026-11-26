#include "yumi_ctl_server.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <malloc.h>

#include "mitm/network_mitm.hpp"
#include "yumi_nx/config_store.hpp"
#include "yumi_nx/paths.hpp"
#include "yumi_nx/tunnel_engine.hpp"

namespace yumi_nx::sys {

namespace {

constexpr size_t kMaxSessions = 8;
constexpr size_t kMaxLogLines = 64;
constexpr size_t kMaxConnRecords = 64;

struct RLock {
    RMutex* m = nullptr;
    explicit RLock(RMutex* mtx) noexcept : m(mtx) { rmutexLock(m); }
    ~RLock() { rmutexUnlock(m); }
};

template <size_t N>
void CopyStr(char (&dst)[N], const char* src) noexcept {
    std::snprintf(dst, N, "%s", src ? src : "");
}

void WriteCmifResponse(void* tls_base, Result rc, const void* payload, u32 payload_size,
                       Handle move_handle = INVALID_HANDLE) {
    std::memset(tls_base, 0, 0x100);
    const bool has_move = (move_handle != INVALID_HANDLE);
    const u32 actual_size = 16u + static_cast<u32>(sizeof(CmifOutHeader)) + payload_size;
    const u32 num_data_words = (actual_size + 3u) / 4u;

    auto* hdr = reinterpret_cast<HipcHeader*>(tls_base);
    hdr->type = 0;
    hdr->num_send_statics = 0;
    hdr->num_send_buffers = 0;
    hdr->num_recv_buffers = 0;
    hdr->num_exch_buffers = 0;
    hdr->num_data_words = num_data_words;
    hdr->recv_static_mode = 0;
    hdr->has_special_header = has_move ? 1u : 0u;

    u8* cursor = reinterpret_cast<u8*>(hdr + 1);
    if (has_move) {
        auto* sp = reinterpret_cast<HipcSpecialHeader*>(cursor);
        sp->send_pid = 0;
        sp->num_copy_handles = 0;
        sp->num_move_handles = 1;
        cursor += sizeof(HipcSpecialHeader);
        *reinterpret_cast<Handle*>(cursor) = move_handle;
        cursor += sizeof(Handle);
    }

    auto* data_words = reinterpret_cast<u32*>(cursor);
    auto* out_hdr = reinterpret_cast<CmifOutHeader*>(cmifGetAlignedDataStart(data_words, tls_base));
    out_hdr->magic = CMIF_OUT_HEADER_MAGIC;
    out_hdr->version = 0;
    out_hdr->result = rc;
    out_hdr->token = 0;

    if (payload && payload_size > 0) {
        std::memcpy(out_hdr + 1, payload, payload_size);
    }
}

}  // namespace

YumiCtlServer::YumiCtlServer(const HosCompatInfo& hos, uint32_t heap_total_bytes) : hos_(hos) {
    rmutexInit(&state_mutex_);
    last_bps_tick_ns_ = armTicksToNs(armGetSystemTick());
    stats_.sysmodule_heap_total_bytes = heap_total_bytes;
    status_.state = TunnelState::Off;
    status_.routing_mode = RoutingMode::Rules;
    status_.active_protocol = Protocol::Vless;
    CopyStr(status_.active_node_name, "Не выбран");
    CopyStr(status_.status_message, "yumi-sysmodule готов (Phase 2 Core)");
}

YumiCtlServer::~YumiCtlServer() { StopService(); }

void YumiCtlServer::AppendLog(LogLevel level, const char* msg) {
    RLock lock(&state_mutex_);
    ipc::IpcLogLine line{};
    line.timestamp_ms = armTicksToNs(armGetSystemTick()) / 1000000ULL;
    line.level = level;
    line.sequence_id = ++next_log_seq_;
    CopyStr(line.message, msg);
    logs_.push_back(line);
    if (logs_.size() > kMaxLogLines) {
        logs_.erase(logs_.begin());
    }
}

void YumiCtlServer::UpdateHeapStats() {
    struct mallinfo mi = mallinfo();
    stats_.sysmodule_heap_used_bytes = static_cast<uint32_t>(mi.uordblks);
}

void YumiCtlServer::LoadInitialConfig() {
    RLock lock(&state_mutex_);
    if (auto txt = store::ReadTextFile(paths::SettingsFile())) {
        if (auto parsed = store::DeserializeSettingsJson(*txt)) {
            settings_ = *parsed;
            status_.routing_mode = settings_.routing_mode;
            AppendLog(LogLevel::Info, "Loaded settings.json");
        }
    }
    if (auto bin = store::ReadBinaryFile(paths::ActiveNodeFile())) {
        if (auto node = store::DecodeActiveNodeBinary(*bin)) {
            active_node_ = *node;
            status_.active_protocol = node->protocol;
            CopyStr(status_.active_node_id, node->id.c_str());
            CopyStr(status_.active_node_name, node->name.c_str());
            AppendLog(LogLevel::Info, "Loaded active_node.bin");
        }
    }
    if (engine_) {
        engine_->UpdateSettings(settings_);
    }
    UpdateHeapStats();
}

bool YumiCtlServer::StartService() {
    LoadInitialConfig();
    const Result rc = smRegisterService(&port_handle_, smEncodeName(ipc::kYumiCtlServiceName),
                                        false, static_cast<s32>(kMaxSessions));
    if (R_FAILED(rc)) {
        AppendLog(LogLevel::Error, "smRegisterService(yumi:ctl) failed");
        return false;
    }
    running_.store(true);
    char msg[128];
    std::snprintf(msg, sizeof(msg), "yumi:ctl started (HOS=0x%06x gen=%u)",
                  hos_.packed_version, static_cast<unsigned>(hos_.generation));
    AppendLog(LogLevel::Info, msg);
    return true;
}

void YumiCtlServer::StopService() {
    running_.store(false);
    for (Handle h : sessions_) {
        if (h != INVALID_HANDLE) svcCloseHandle(h);
    }
    sessions_.clear();
    if (port_handle_ != INVALID_HANDLE) {
        smUnregisterService(smEncodeName(ipc::kYumiCtlServiceName));
        svcCloseHandle(port_handle_);
        port_handle_ = INVALID_HANDLE;
    }
}

bool YumiCtlServer::HandleControlCommand(u32 cmd_id, u32& out_move_handle) {
    out_move_handle = INVALID_HANDLE;
    void* tls = armGetTls();
    if (cmd_id == 3) {
        // cmifQueryPointerBufferSize
        u16 ptr_size = 0;
        WriteCmifResponse(tls, 0, &ptr_size, sizeof(ptr_size));
        return true;
    }
    if (cmd_id == 2 || cmd_id == 4) {
        // cmifCloneCurrentObject / cmifCloneCurrentObjectEx
        if (sessions_.size() >= kMaxSessions) {
            WriteCmifResponse(tls, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory), nullptr, 0);
            return true;
        }
        Handle srv = INVALID_HANDLE;
        Handle cli = INVALID_HANDLE;
        const Result rc = svcCreateSession(&srv, &cli, 0, 0);
        if (R_FAILED(rc)) {
            WriteCmifResponse(tls, rc, nullptr, 0);
            return true;
        }
        sessions_.push_back(srv);
        out_move_handle = cli;
        WriteCmifResponse(tls, 0, nullptr, 0, cli);
        return true;
    }
    WriteCmifResponse(tls, MAKERESULT(Module_Libnx, LibnxError_ShouldNotHappen), nullptr, 0);
    return true;
}

Result YumiCtlServer::HandleRequestCommand(u32 cmd_id, const HipcParsedRequest& parsed, u32& out_resp_size) {
    void* tls = armGetTls();
    auto* hdr = reinterpret_cast<CmifInHeader*>(cmifGetAlignedDataStart(parsed.data.data_words, tls));
    const u8* req_data = reinterpret_cast<const u8*>(hdr + 1);
    const auto cmd = static_cast<ipc::YumiCtlCmd>(cmd_id);

    out_resp_size = 0;

    switch (cmd) {
        case ipc::YumiCtlCmd::GetVersion: {
            RLock lock(&state_mutex_);
            UpdateHeapStats();
            ipc::IpcVersionInfo info{};
            info.protocol_version = ipc::kIpcProtocolVersion;
            info.hos_version_raw = hos_.packed_version;
            info.hos_generation = hos_.generation;
            info.mitm_active = mitm_flags_;
            WriteCmifResponse(tls, 0, &info, sizeof(info));
            return 0;
        }
        case ipc::YumiCtlCmd::GetStatus: {
            RLock lock(&state_mutex_);
            WriteCmifResponse(tls, 0, &status_, sizeof(status_));
            return 0;
        }
        case ipc::YumiCtlCmd::Start: {
            ProxyNode node_copy{};
            AppSettings cfg_copy{};
            net::TunnelEngine* eng = nullptr;
            {
                RLock lock(&state_mutex_);
                UpdateHeapStats();
                status_.state = TunnelState::On;
                was_active_before_sleep_ = true;
                status_.connected_at_epoch_sec = armTicksToNs(armGetSystemTick()) / 1000000000ULL;
                CopyStr(status_.status_message, "Туннель активен (Core)");
                node_copy = active_node_;
                cfg_copy = settings_;
                eng = engine_;
                AppendLog(LogLevel::Info, "Start() called via yumi:ctl");
            }
            if (eng && !eng->Start(node_copy, cfg_copy)) {
                RLock lock(&state_mutex_);
                status_.state = TunnelState::Error;
                CopyStr(status_.status_message, "Ошибка запуска TunnelEngine");
            }
            WriteCmifResponse(tls, 0, nullptr, 0);
            return 0;
        }
        case ipc::YumiCtlCmd::Stop: {
            net::TunnelEngine* eng = nullptr;
            {
                RLock lock(&state_mutex_);
                UpdateHeapStats();
                status_.state = TunnelState::Off;
                was_active_before_sleep_ = false;
                status_.connected_at_epoch_sec = 0;
                CopyStr(status_.status_message, "Отключено");
                eng = engine_;
                AppendLog(LogLevel::Info, "Stop() called via yumi:ctl");
            }
            if (eng) eng->Stop();
            WriteCmifResponse(tls, 0, nullptr, 0);
            return 0;
        }
        case ipc::YumiCtlCmd::ReloadConfig: {
            LoadInitialConfig();
            if (mitm_) mitm_->ReloadRules();
            AppendLog(LogLevel::Info, "ReloadConfig() completed");
            WriteCmifResponse(tls, 0, nullptr, 0);
            return 0;
        }
        case ipc::YumiCtlCmd::SelectActiveNode: {
            RLock lock(&state_mutex_);
            char id_buf[32]{};
            std::memcpy(id_buf, req_data, sizeof(id_buf));
            id_buf[31] = '\0';
            CopyStr(status_.active_node_id, id_buf);
            if (auto bin = store::ReadBinaryFile(paths::ActiveNodeFile())) {
                if (auto node = store::DecodeActiveNodeBinary(*bin)) {
                    active_node_ = *node;
                    status_.active_protocol = node->protocol;
                    CopyStr(status_.active_node_name, node->name.c_str());
                }
            }
            AppendLog(LogLevel::Info, "SelectActiveNode() updated");
            WriteCmifResponse(tls, 0, nullptr, 0);
            return 0;
        }
        case ipc::YumiCtlCmd::SetRoutingMode: {
            RLock lock(&state_mutex_);
            const uint8_t mode_val = req_data[0];
            if (mode_val <= static_cast<uint8_t>(RoutingMode::Direct)) {
                status_.routing_mode = static_cast<RoutingMode>(mode_val);
                settings_.routing_mode = status_.routing_mode;
                if (engine_) engine_->UpdateSettings(settings_);
                AppendLog(LogLevel::Info, ToString(status_.routing_mode));
                WriteCmifResponse(tls, 0, nullptr, 0);
            } else {
                WriteCmifResponse(tls, MAKERESULT(Module_Libnx, LibnxError_BadInput), nullptr, 0);
            }
            return 0;
        }
        case ipc::YumiCtlCmd::GetTrafficStats: {
            RLock lock(&state_mutex_);
            UpdateHeapStats();
            const uint64_t now_ns = armTicksToNs(armGetSystemTick());
            const uint64_t dt_ns = (now_ns > last_bps_tick_ns_) ? (now_ns - last_bps_tick_ns_) : 0;
            if (dt_ns >= 250'000'000ULL) {
                stats_.uplink_bps = (window_up_bytes_ * 1'000'000'000ULL) / dt_ns;
                stats_.downlink_bps = (window_down_bytes_ * 1'000'000'000ULL) / dt_ns;
                window_up_bytes_ = 0;
                window_down_bytes_ = 0;
                last_bps_tick_ns_ = now_ns;
            }
            WriteCmifResponse(tls, 0, &stats_, sizeof(stats_));
            return 0;
        }
        case ipc::YumiCtlCmd::GetLogs: {
            RLock lock(&state_mutex_);
            uint32_t since_seq = 0;
            std::memcpy(&since_seq, req_data, sizeof(since_seq));
            uint32_t copied = 0;
            if (parsed.meta.num_recv_buffers > 0) {
                void* out_buf = hipcGetBufferAddress(&parsed.data.recv_buffers[0]);
                const size_t out_cap = hipcGetBufferSize(&parsed.data.recv_buffers[0]);
                const size_t max_entries = out_cap / sizeof(ipc::IpcLogLine);
                auto* dst = reinterpret_cast<ipc::IpcLogLine*>(out_buf);
                for (const auto& entry : logs_) {
                    if (copied >= max_entries) break;
                    if (entry.sequence_id > since_seq) {
                        dst[copied++] = entry;
                    }
                }
            }
            WriteCmifResponse(tls, 0, &copied, sizeof(copied));
            return 0;
        }
        case ipc::YumiCtlCmd::GetConnectionLog: {
            RLock lock(&state_mutex_);
            uint32_t since_seq = 0;
            std::memcpy(&since_seq, req_data, sizeof(since_seq));
            uint32_t copied = 0;
            if (parsed.meta.num_recv_buffers > 0) {
                void* out_buf = hipcGetBufferAddress(&parsed.data.recv_buffers[0]);
                const size_t out_cap = hipcGetBufferSize(&parsed.data.recv_buffers[0]);
                const size_t max_entries = out_cap / sizeof(ipc::IpcConnectionRecord);
                auto* dst = reinterpret_cast<ipc::IpcConnectionRecord*>(out_buf);
                for (const auto& entry : conn_logs_) {
                    if (copied >= max_entries) break;
                    if (entry.sequence_id > since_seq) {
                        dst[copied++] = entry;
                    }
                }
            }
            WriteCmifResponse(tls, 0, &copied, sizeof(copied));
            return 0;
        }
        case ipc::YumiCtlCmd::ResetConnections: {
            RLock lock(&state_mutex_);
            conn_logs_.clear();
            stats_.active_sockets = 0;
            if (engine_) engine_->ResetAllFlows();
            AppendLog(LogLevel::Warn, "ResetConnections() called");
            WriteCmifResponse(tls, 0, nullptr, 0);
            return 0;
        }
        case ipc::YumiCtlCmd::Shutdown: {
            AppendLog(LogLevel::Info, "Graceful Shutdown() requested via yumi:ctl");
            running_.store(false);
            WriteCmifResponse(tls, 0, nullptr, 0);
            return 0;
        }
        default:
            WriteCmifResponse(tls, MAKERESULT(Module_Libnx, LibnxError_ShouldNotHappen), nullptr, 0);
            return 0;
    }
}

void YumiCtlServer::RunLoop() {
    Handle reply_target = 0;
    std::vector<Handle> wait_handles;
    wait_handles.reserve(1 + kMaxSessions);

    while (running_.load()) {
        wait_handles.clear();
        wait_handles.push_back(port_handle_);
        for (Handle h : sessions_) wait_handles.push_back(h);

        s32 idx = -1;
        const Result rc = svcReplyAndReceive(
            &idx, wait_handles.data(), static_cast<s32>(wait_handles.size()),
            reply_target, UINT64_MAX);
        reply_target = 0;

        if (R_FAILED(rc)) {
            if (idx > 0 && static_cast<size_t>(idx - 1) < sessions_.size()) {
                svcCloseHandle(sessions_[idx - 1]);
                sessions_.erase(sessions_.begin() + (idx - 1));
            }
            continue;
        }

        if (idx == 0) {
            Handle new_session = INVALID_HANDLE;
            if (R_SUCCEEDED(svcAcceptSession(&new_session, port_handle_))) {
                if (sessions_.size() < kMaxSessions) {
                    sessions_.push_back(new_session);
                } else {
                    svcCloseHandle(new_session);
                }
            }
            continue;
        }

        if (idx > 0 && static_cast<size_t>(idx - 1) < sessions_.size()) {
            const Handle session = sessions_[idx - 1];
            void* tls = armGetTls();
            const HipcParsedRequest parsed = hipcParseRequest(tls);

            if (parsed.meta.type == CmifCommandType_Close) {
                svcCloseHandle(session);
                sessions_.erase(sessions_.begin() + (idx - 1));
                continue;
            }

            if (parsed.meta.type == CmifCommandType_Control ||
                parsed.meta.type == CmifCommandType_ControlWithContext) {
                auto* hdr = reinterpret_cast<CmifInHeader*>(
                    cmifGetAlignedDataStart(parsed.data.data_words, tls));
                u32 move_h = INVALID_HANDLE;
                HandleControlCommand(hdr->command_id, move_h);
                reply_target = session;
                continue;
            }

            if (parsed.meta.type == CmifCommandType_Request ||
                parsed.meta.type == CmifCommandType_RequestWithContext) {
                auto* hdr = reinterpret_cast<CmifInHeader*>(
                    cmifGetAlignedDataStart(parsed.data.data_words, tls));
                if (hdr->magic != CMIF_IN_HEADER_MAGIC) {
                    WriteCmifResponse(tls, MAKERESULT(Module_Libnx, LibnxError_BadInput),
                                      nullptr, 0);
                } else {
                    u32 resp_size = 0;
                    HandleRequestCommand(hdr->command_id, parsed, resp_size);
                }
                if (!running_.load()) {
                    // Flush the Shutdown reply before breaking so Ultrahand receives Result = 0 cleanly.
                    s32 flush_idx = -1;
                    (void)svcReplyAndReceive(&flush_idx, nullptr, 0, session, 0);
                    break;
                }
                reply_target = session;
                continue;
            }

            WriteCmifResponse(tls, MAKERESULT(Module_Libnx, LibnxError_ShouldNotHappen), nullptr, 0);
            reply_target = session;
        }
    }
}

AppSettings YumiCtlServer::GetSettingsCopy() {
    RLock lock(&state_mutex_);
    return settings_;
}

bool YumiCtlServer::IsTunnelActive() {
    RLock lock(&state_mutex_);
    return status_.state == TunnelState::On;
}

void YumiCtlServer::RecordConnection(uint64_t program_id, const char* host, uint16_t port,
                                     bool is_udp, uint8_t route_action, uint8_t accepted) {
    RLock lock(&state_mutex_);
    ipc::IpcConnectionRecord rec{};
    rec.timestamp_ms = armTicksToNs(armGetSystemTick()) / 1000000ULL;
    rec.program_id = program_id;
    rec.sequence_id = ++next_conn_seq_;
    rec.port = port;
    rec.is_udp = is_udp ? 1u : 0u;
    rec.route_action = route_action;
    rec.accepted = accepted;
    CopyStr(rec.host, host ? host : "");
    conn_logs_.push_back(rec);
    if (conn_logs_.size() > kMaxConnRecords) {
        conn_logs_.erase(conn_logs_.begin());
    }
}

void YumiCtlServer::AddTrafficBytes(uint64_t up_bytes, uint64_t down_bytes) {
    RLock lock(&state_mutex_);
    stats_.uplink_bytes += up_bytes;
    stats_.downlink_bytes += down_bytes;
    window_up_bytes_ += up_bytes;
    window_down_bytes_ += down_bytes;
}

void YumiCtlServer::AdjustActiveSockets(int32_t delta) {
    RLock lock(&state_mutex_);
    const int64_t next = static_cast<int64_t>(stats_.active_sockets) + delta;
    stats_.active_sockets = (next > 0) ? static_cast<uint32_t>(next) : 0u;
}

void YumiCtlServer::SetMitmFlags(bool bsd_active, bool sfdnsres_active) {
    RLock lock(&state_mutex_);
    if (bsd_active) mitm_flags_ |= ipc::mitm_flag::kBsdMitmActive;
    else mitm_flags_ &= static_cast<uint8_t>(~ipc::mitm_flag::kBsdMitmActive);

    if (sfdnsres_active) mitm_flags_ |= ipc::mitm_flag::kSfdnsresMitmActive;
    else mitm_flags_ &= static_cast<uint8_t>(~ipc::mitm_flag::kSfdnsresMitmActive);
}

void YumiCtlServer::SetPowerNetFlags(bool psc_active, bool network_online) {
    RLock lock(&state_mutex_);
    if (psc_active) mitm_flags_ |= ipc::mitm_flag::kPscMonitorActive;
    else mitm_flags_ &= static_cast<uint8_t>(~ipc::mitm_flag::kPscMonitorActive);

    if (network_online) mitm_flags_ |= ipc::mitm_flag::kNetworkOnline;
    else mitm_flags_ &= static_cast<uint8_t>(~ipc::mitm_flag::kNetworkOnline);
}

void YumiCtlServer::TriggerAutoStart() {
    ProxyNode node_copy{};
    AppSettings cfg_copy{};
    net::TunnelEngine* eng = nullptr;
    {
        RLock lock(&state_mutex_);
        status_.state = TunnelState::On;
        was_active_before_sleep_ = true;
        status_.connected_at_epoch_sec = armTicksToNs(armGetSystemTick()) / 1000000000ULL;
        CopyStr(status_.status_message, "Туннель активен (Auto-connect)");
        node_copy = active_node_;
        cfg_copy = settings_;
        eng = engine_;
    }
    if (eng) eng->Start(node_copy, cfg_copy);
}

void YumiCtlServer::OnEnterSleep() {
    net::TunnelEngine* eng = nullptr;
    {
        RLock lock(&state_mutex_);
        was_active_before_sleep_ = (status_.state == TunnelState::On);
        if (was_active_before_sleep_) {
            status_.state = TunnelState::Connecting;
            CopyStr(status_.status_message, "Сон консоли — пауза туннеля");
            AppendLog(LogLevel::Info, "psc:m ReadySleep -> tunnel paused");
            eng = engine_;
        }
    }
    if (eng) eng->Stop();
}

void YumiCtlServer::OnWakeUp() {
    ProxyNode node_copy{};
    AppSettings cfg_copy{};
    net::TunnelEngine* eng = nullptr;
    {
        RLock lock(&state_mutex_);
        if (was_active_before_sleep_) {
            status_.state = TunnelState::On;
            status_.connected_at_epoch_sec = armTicksToNs(armGetSystemTick()) / 1000000000ULL;
            CopyStr(status_.status_message, "Туннель восстановлен после сна");
            AppendLog(LogLevel::Info, "psc:m Awake -> tunnel restored");
            node_copy = active_node_;
            cfg_copy = settings_;
            eng = engine_;
        }
    }
    if (eng) eng->Start(node_copy, cfg_copy);
}

void YumiCtlServer::OnNetworkOnlineChanged(bool online) {
    ProxyNode node_copy{};
    AppSettings cfg_copy{};
    net::TunnelEngine* eng_to_start = nullptr;
    net::TunnelEngine* eng_to_stop = nullptr;
    {
        RLock lock(&state_mutex_);
        AppendLog(LogLevel::Info, online ? "nifm:u internet connected" : "nifm:u internet offline");
        if (!online && status_.state == TunnelState::On) {
            status_.state = TunnelState::Connecting;
            CopyStr(status_.status_message, "Ожидание Wi-Fi / сети...");
            eng_to_stop = engine_;
        } else if (online && status_.state == TunnelState::Connecting && was_active_before_sleep_) {
            status_.state = TunnelState::On;
            CopyStr(status_.status_message, "Туннель активен (Phase 2 Core)");
            node_copy = active_node_;
            cfg_copy = settings_;
            eng_to_start = engine_;
        }
    }
    if (eng_to_stop) eng_to_stop->Stop();
    if (eng_to_start && !eng_to_start->IsRunning()) eng_to_start->Start(node_copy, cfg_copy);
}

}  // namespace yumi_nx::sys
