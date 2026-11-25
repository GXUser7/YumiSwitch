#include "mitm/network_mitm.hpp"

#include <switch/sf/cmif.h>
#include <algorithm>
#include <cstdio>
#include <cstring>

#include "hos_compat.hpp"
#include "ipc/yumi_ctl_server.hpp"
#include "yumi_nx/dns_engine.hpp"
#include "yumi_nx/paths.hpp"
#include "yumi_nx/socket_io.hpp"
#include "yumi_nx/tunnel_engine.hpp"

namespace yumi_nx::sys {

namespace {

bool ExtractSockaddrHostPort(const uint8_t* sa, size_t sa_len, std::string& out_host, uint16_t& out_port) noexcept {
    out_host.clear();
    out_port = 0;
    if (!sa || sa_len < 8) {
        return false;
    }

    // Horizon BSD uses FreeBSD sockaddr (byte 0 = sin_len, byte 1 = sin_family).
    // Accept both BSD (byte 1 == AF_INET/AF_INET6) and POSIX little-endian (byte 0 == AF_INET).
    uint8_t family = sa[1];
    if (family == 0 && (sa[0] == 2 || sa[0] == 10)) {
        family = sa[0];
    }

    out_port = static_cast<uint16_t>((static_cast<uint16_t>(sa[2]) << 8) | sa[3]);
    if (family == 2 && sa_len >= 8) {  // AF_INET
        char buf[24]{};
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", sa[4], sa[5], sa[6], sa[7]);
        out_host = buf;
        return true;
    }
    if ((family == 28 || family == 10) && sa_len >= 24) {  // AF_INET6 (BSD=28, Linux=10)
        char buf[48]{};
        std::snprintf(buf, sizeof(buf), "%02x%02x:%02x%02x::%02x%02x", sa[8], sa[9], sa[10], sa[11], sa[22], sa[23]);
        out_host = buf;
        return true;
    }
    return false;
}

const uint8_t* PickFirstNonEmptyInput(const mitm_ipc::ParsedRequestInfo& parsed, uint32_t idx, size_t& out_size) noexcept {
    if (idx < parsed.send_ptr_count && parsed.send_ptr[idx] != nullptr && parsed.send_ptr_size[idx] > 0) {
        out_size = parsed.send_ptr_size[idx];
        return parsed.send_ptr[idx];
    }
    if (idx < parsed.send_buf_count && parsed.send_buf_copy[idx] != nullptr && parsed.send_buf_size[idx] > 0) {
        out_size = parsed.send_buf_size[idx];
        return parsed.send_buf_copy[idx];
    }
    out_size = 0;
    return nullptr;
}

bool ExtractBoundedHostString(const uint8_t* buf, size_t size, std::string& out_host) noexcept {
    out_host.clear();
    if (!buf || size == 0) {
        return false;
    }
    const size_t max_len = std::min<size_t>(size, 95);
    size_t len = 0;
    while (len < max_len && buf[len] != '\0') {
        const uint8_t ch = buf[len];
        if (ch < 0x20 || ch > 0x7E) {
            return false;
        }
        ++len;
    }
    if (len == 0) {
        return false;
    }
    out_host.assign(reinterpret_cast<const char*>(buf), len);
    return true;
}

void WriteBsdErrorReply(void* tls_base, int32_t ret_val, int32_t err_val) noexcept {
    int32_t words[2] = {ret_val, err_val};
    mitm_ipc::WriteSimpleCmifResponse(tls_base, 0, words, sizeof(words));
}

}  // namespace

NetworkMitmManager::NetworkMitmManager(YumiCtlServer* ctl_server) noexcept
    : ctl_server_(ctl_server) {
    mutexInit(&workers_mutex_);
    mutexInit(&router_mutex_);
    bsd_acc_.manager = this;
    bsd_acc_.kind = ServiceKind::BsdU;
    bsd_acc_.name = "bsd:u";

    dns_acc_.manager = this;
    dns_acc_.kind = ServiceKind::Sfdnsres;
    dns_acc_.name = "sfdnsres";
}

NetworkMitmManager::~NetworkMitmManager() {
    Stop();
}

bool NetworkMitmManager::StartAcceptor(ServiceAcceptor& acc) noexcept {
    const Result rc = mitm_ipc::SmInstallMitm(acc.name, acc.server_port, acc.query_session);
    if (R_FAILED(rc)) {
        if (ctl_server_) {
            char msg[128]{};
            std::snprintf(msg, sizeof(msg), "%s InstallMitm failed: 0x%x", acc.name, rc);
            ctl_server_->AppendLog(LogLevel::Warn, msg);
        }
        return false;
    }
    acc.installed = true;

    if (R_FAILED(threadCreate(&acc.query_thread, &NetworkMitmManager::QueryThreadEntry, &acc, acc.query_stack,
                              sizeof(acc.query_stack), 0x3B, -2)) ||
        R_FAILED(threadStart(&acc.query_thread))) {
        StopAcceptor(acc);
        return false;
    }
    acc.query_thread_started = true;

    if (R_FAILED(threadCreate(&acc.server_thread, &NetworkMitmManager::ServerThreadEntry, &acc, acc.server_stack,
                              sizeof(acc.server_stack), 0x3B, -2)) ||
        R_FAILED(threadStart(&acc.server_thread))) {
        StopAcceptor(acc);
        return false;
    }
    acc.server_thread_started = true;

    if (ctl_server_) {
        char msg[96]{};
        std::snprintf(msg, sizeof(msg), "MITM installed on %s (HOS 19/20 compatible)", acc.name);
        ctl_server_->AppendLog(LogLevel::Info, msg);
    }
    return true;
}

void NetworkMitmManager::StopAcceptor(ServiceAcceptor& acc) noexcept {
    if (acc.query_session != INVALID_HANDLE) {
        svcCancelSynchronization(acc.query_session);
    }
    if (acc.server_port != INVALID_HANDLE) {
        svcCancelSynchronization(acc.server_port);
    }
    if (acc.server_thread_started) {
        threadWaitForExit(&acc.server_thread);
        threadClose(&acc.server_thread);
        acc.server_thread_started = false;
    }
    if (acc.query_thread_started) {
        threadWaitForExit(&acc.query_thread);
        threadClose(&acc.query_thread);
        acc.query_thread_started = false;
    }
    if (acc.installed) {
        mitm_ipc::SmUninstallMitm(acc.name);
        acc.installed = false;
    }
    if (acc.query_session != INVALID_HANDLE) {
        svcCloseHandle(acc.query_session);
        acc.query_session = INVALID_HANDLE;
    }
    if (acc.server_port != INVALID_HANDLE) {
        svcCloseHandle(acc.server_port);
        acc.server_port = INVALID_HANDLE;
    }
}

void NetworkMitmManager::ReloadRules() noexcept {
    net::BasicRouter fresh;
    fresh.LoadRulesBin(paths::RulesBinFile());
    mutexLock(&router_mutex_);
    router_ = std::move(fresh);
    mutexUnlock(&router_mutex_);
}

bool NetworkMitmManager::Start() noexcept {
    stop_requested_.store(false);
    ReloadRules();

    const bool bsd_ok = StartAcceptor(bsd_acc_);
    const bool dns_ok = StartAcceptor(dns_acc_);
    bsd_active_.store(bsd_ok);
    dns_active_.store(dns_ok);

    if (ctl_server_) {
        ctl_server_->SetMitmFlags(bsd_ok, dns_ok);
    }
    return bsd_ok || dns_ok;
}

void NetworkMitmManager::Stop() noexcept {
    stop_requested_.store(true);
    bsd_active_.store(false);
    dns_active_.store(false);

    StopAcceptor(bsd_acc_);
    StopAcceptor(dns_acc_);

    mutexLock(&workers_mutex_);
    for (size_t i = 0; i < kMaxWorkers; ++i) {
        if (workers_[i]) {
            workers_[i]->stop_requested.store(true);
            if (workers_[i]->client_session != INVALID_HANDLE) {
                svcCancelSynchronization(workers_[i]->client_session);
            }
        }
    }
    mutexUnlock(&workers_mutex_);

    ReapFinishedWorkers(true);
    if (ctl_server_) {
        ctl_server_->SetMitmFlags(false, false);
    }
}

void NetworkMitmManager::ReapFinishedWorkers(bool wait_all) noexcept {
    for (size_t i = 0; i < kMaxWorkers; ++i) {
        WorkerSlot* slot = nullptr;
        mutexLock(&workers_mutex_);
        slot = workers_[i];
        if (slot && (wait_all || slot->thread_finished.load())) {
            workers_[i] = nullptr;
        } else {
            slot = nullptr;
        }
        mutexUnlock(&workers_mutex_);

        if (slot) {
            threadWaitForExit(&slot->thread);
            threadClose(&slot->thread);
            if (slot->fwd_handle != INVALID_HANDLE) {
                svcCloseHandle(slot->fwd_handle);
            }
            if (slot->client_session != INVALID_HANDLE) {
                svcCloseHandle(slot->client_session);
            }
            if (slot->open_socket_delta > 0 && ctl_server_) {
                ctl_server_->AdjustActiveSockets(-slot->open_socket_delta);
            }
            delete slot;
        }
    }
}

int NetworkMitmManager::AcquireWorkerIndex() noexcept {
    ReapFinishedWorkers(false);
    mutexLock(&workers_mutex_);
    int idx = -1;
    for (size_t i = 0; i < kMaxWorkers; ++i) {
        if (workers_[i] == nullptr) {
            idx = static_cast<int>(i);
            break;
        }
    }
    mutexUnlock(&workers_mutex_);
    return idx;
}

void NetworkMitmManager::QueryThreadEntry(void* arg) {
    if (auto* acc = static_cast<ServiceAcceptor*>(arg); acc && acc->manager) {
        acc->manager->RunQueryLoop(*acc);
    }
}

void NetworkMitmManager::ServerThreadEntry(void* arg) {
    if (auto* acc = static_cast<ServiceAcceptor*>(arg); acc && acc->manager) {
        acc->manager->RunServerLoop(*acc);
    }
}

void NetworkMitmManager::WorkerThreadEntry(void* arg) {
    if (auto* slot = static_cast<WorkerSlot*>(arg); slot && slot->manager) {
        slot->manager->RunWorker(*slot);
    }
}

void NetworkMitmManager::RunQueryLoop(ServiceAcceptor& acc) noexcept {
    Handle reply_target = 0;
    while (!stop_requested_.load()) {
        if (!mitm_ipc::ServeQueryIteration(acc.query_session, reply_target, nullptr, 0)) {
            if (stop_requested_.load()) {
                break;
            }
            svcSleepThread(5'000'000ULL);
        }
    }
}

void NetworkMitmManager::RunServerLoop(ServiceAcceptor& acc) noexcept {
    while (!stop_requested_.load()) {
        s32 idx = -1;
        const Result wait_rc = svcReplyAndReceive(&idx, &acc.server_port, 1, 0, 200'000'000ULL);
        if (wait_rc == 0xEA01) {
            ReapFinishedWorkers(false);
            continue;
        }
        if (R_FAILED(wait_rc)) {
            if (stop_requested_.load()) {
                break;
            }
            svcSleepThread(10'000'000ULL);
            continue;
        }

        Handle client_sess = INVALID_HANDLE;
        if (R_FAILED(svcAcceptSession(&client_sess, acc.server_port))) {
            continue;
        }

        mitm_ipc::MitmProcessInfo info{};
        Handle fwd_h = INVALID_HANDLE;
        const Result ack_rc = mitm_ipc::SmAcknowledgeMitmSession(acc.name, info, fwd_h);
        if (R_FAILED(ack_rc) || fwd_h == INVALID_HANDLE) {
            svcCloseHandle(client_sess);
            if (fwd_h != INVALID_HANDLE) svcCloseHandle(fwd_h);
            continue;
        }

        const int slot_idx = AcquireWorkerIndex();
        if (slot_idx < 0) {
            if (ctl_server_) {
                ctl_server_->AppendLog(LogLevel::Warn, "MITM worker pool full; closing session");
            }
            svcCloseHandle(client_sess);
            svcCloseHandle(fwd_h);
            continue;
        }

        auto* slot = new (std::nothrow) WorkerSlot();
        if (!slot) {
            svcCloseHandle(client_sess);
            svcCloseHandle(fwd_h);
            continue;
        }
        slot->kind = acc.kind;
        slot->manager = this;
        slot->client_session = client_sess;
        slot->fwd_handle = fwd_h;
        slot->proc_info = info;
        slot->thread_finished.store(false);
        slot->stop_requested.store(false);

        if (R_FAILED(threadCreate(&slot->thread, &NetworkMitmManager::WorkerThreadEntry, slot, slot->stack,
                                  sizeof(slot->stack), 0x3B, -2))) {
            svcCloseHandle(client_sess);
            svcCloseHandle(fwd_h);
            delete slot;
            continue;
        }

        mutexLock(&workers_mutex_);
        workers_[slot_idx] = slot;
        mutexUnlock(&workers_mutex_);

        if (R_FAILED(threadStart(&slot->thread))) {
            mutexLock(&workers_mutex_);
            workers_[slot_idx] = nullptr;
            mutexUnlock(&workers_mutex_);
            threadClose(&slot->thread);
            svcCloseHandle(client_sess);
            svcCloseHandle(fwd_h);
            delete slot;
        }
    }
}

bool NetworkMitmManager::PreInspectBsd(WorkerSlot& slot,
                                       void* tls_base,
                                       const mitm_ipc::ParsedRequestInfo& parsed,
                                       const AppSettings& cfg,
                                       bool tunnel_active,
                                       int32_t& out_track_fd,
                                       bool& out_close_tracked,
                                       uint32_t& out_cmif_cmd,
                                       uint8_t out_override_sa[16],
                                       size_t& out_override_sa_len) noexcept {
    out_track_fd = -1;
    out_close_tracked = false;
    out_cmif_cmd = parsed.cmif_cmd_id;
    out_override_sa_len = 0;

    if (!parsed.has_cmif_in_header) {
        return false;
    }

    if (parsed.hipc_type == CmifCommandType_Control || parsed.hipc_type == CmifCommandType_ControlWithContext) {
        if (parsed.cmif_cmd_id == 3) {
            const uint16_t max_ptr = static_cast<uint16_t>(kPointerSlotSize);
            mitm_ipc::WriteSimpleCmifResponse(tls_base, 0, &max_ptr, sizeof(max_ptr));
            return true;
        }
        return false;
    }

    const uint32_t cmd = parsed.cmif_cmd_id;
    const auto* payload = parsed.cmif_payload;
    const uint32_t payload_sz = parsed.cmif_payload_size;

    if ((cmd == bsd_cmd::kConnect || cmd == bsd_cmd::kSendTo || cmd == bsd_cmd::kBind ||
         cmd == bsd_cmd::kGetPeerName || cmd == bsd_cmd::kClose ||
         cmd == bsd_cmd::kSend || cmd == bsd_cmd::kRecv || cmd == bsd_cmd::kRecvFrom) &&
        payload && payload_sz >= 4) {
        std::memcpy(&out_track_fd, payload, sizeof(int32_t));
    }

    if (cmd == bsd_cmd::kClose && out_track_fd >= 0) {
        for (auto& sock : slot.sockets) {
            if (sock.in_use && sock.fd == out_track_fd) {
                sock.in_use = false;
                sock.proxied = false;
                sock.fd = -1;
                out_close_tracked = true;
                break;
            }
        }
        return false;
    }

    // Synthesize GetPeerName(15) for proxied loopback sockets so callers see the original remote endpoint.
    if (cmd == bsd_cmd::kGetPeerName && out_track_fd >= 0) {
        for (const auto& sock : slot.sockets) {
            if (sock.in_use && sock.fd == out_track_fd && sock.proxied) {
                alignas(16) uint8_t sa_reply[16]{};
                net::EncodePlatformSockaddrIn(sock.orig_ip_host ? sock.orig_ip_host : 0xC6120001u,
                                              sock.remote_port, sa_reply);
                const HipcParsedRequest raw_req = hipcParseRequest(tls_base);
                int32_t words[3] = {0, 0, 16};
                if (raw_req.meta.num_recv_buffers > 0) {
                    void* dst = hipcGetBufferAddress(&raw_req.data.recv_buffers[0]);
                    const size_t cap = hipcGetBufferSize(&raw_req.data.recv_buffers[0]);
                    if (dst && cap >= 16) {
                        std::memcpy(dst, sa_reply, 16);
                        mitm_ipc::WriteSimpleCmifResponse(tls_base, 0, words, sizeof(words));
                        return true;
                    }
                }
                std::memcpy(slot.ptr_tx_buf, sa_reply, 16);
                mitm_ipc::WriteSimpleCmifResponse(tls_base, 0, words, sizeof(words), INVALID_HANDLE, slot.ptr_tx_buf, 16);
                return true;
            }
        }
        return false;
    }

    if (cmd == bsd_cmd::kConnect || cmd == bsd_cmd::kSendTo) {
        const uint32_t sa_idx = (cmd == bsd_cmd::kSendTo) ? 1u : 0u;
        size_t sa_len = 0;
        const uint8_t* sa = PickFirstNonEmptyInput(parsed, sa_idx, sa_len);
        std::string host;
        uint16_t port = 0;
        if (ExtractSockaddrHostPort(sa, sa_len, host, port)) {
            uint32_t ip_host = 0;
            uint16_t port_tmp = 0;
            net::DecodePlatformSockaddrIn(sa, sa_len, ip_host, port_tmp);

            auto* engine = ctl_server_ ? ctl_server_->GetTunnelEngine() : nullptr;
            if (ip_host != 0 && net::FakeIpPool::IsFakeIp(ip_host) && engine) {
                std::string mapped;
                if (engine->FakeIps().Lookup(ip_host, mapped) && !mapped.empty()) {
                    host = std::move(mapped);
                }
            }

            bool is_udp = (cmd == bsd_cmd::kSendTo);
            TrackedSocket* tracked = nullptr;
            if (out_track_fd >= 0) {
                for (auto& sock : slot.sockets) {
                    if (sock.in_use && sock.fd == out_track_fd) {
                        tracked = &sock;
                        if (!is_udp) is_udp = sock.is_udp;
                        sock.orig_ip_host = ip_host;
                        sock.remote_port = port;
                        std::strncpy(sock.remote_host, host.c_str(), sizeof(sock.remote_host) - 1);
                        sock.remote_host[sizeof(sock.remote_host) - 1] = '\0';
                        break;
                    }
                }
            }

            if (tunnel_active && ctl_server_) {
                if (cfg.block_quic && is_udp && port == 443) {
                    ctl_server_->RecordConnection(slot.proc_info.program_id, host.c_str(), port, true, 2 /*Block*/, 0);
                    WriteBsdErrorReply(tls_base, -1, 13 /* EACCES */);
                    return true;
                }
                mutexLock(&router_mutex_);
                const auto action = router_.Decide({host, port, is_udp, slot.proc_info.program_id}, cfg);
                mutexUnlock(&router_mutex_);
                const uint8_t act_u8 = static_cast<uint8_t>(action);
                if (action == net::RouteAction::Block) {
                    ctl_server_->RecordConnection(slot.proc_info.program_id, host.c_str(), port, is_udp, act_u8, 0);
                    WriteBsdErrorReply(tls_base, -1, 111 /* ECONNREFUSED */);
                    return true;
                }

                // Redirect TCP Proxy connections to TunnelEngine loopback listener (127.0.0.1:relay_port).
                if (cmd == bsd_cmd::kConnect && !is_udp && action == net::RouteAction::Proxy &&
                    engine && engine->IsRunning() && engine->RelayPort() != 0 && ip_host != 0x7F000001u) {
                    uint16_t eph_port = 0;
                    if (mitm_ipc::MitmCallBsdBindLoopback(slot.fwd_handle, out_track_fd, eph_port)) {
                        engine->RegisterPendingTarget(eph_port, {host, port, false, slot.proc_info.program_id});
                        net::EncodePlatformSockaddrIn(0x7F000001u, engine->RelayPort(), out_override_sa);
                        out_override_sa_len = 16;
                        if (tracked) tracked->proxied = true;
                        ctl_server_->RecordConnection(slot.proc_info.program_id, host.c_str(), port, false, 0 /*Proxy*/, 1);
                        return false;
                    }
                }

                ctl_server_->RecordConnection(slot.proc_info.program_id, host.c_str(), port, is_udp, act_u8, 1);
            }
        }
    }

    return false;
}

bool NetworkMitmManager::PreInspectSfdnsres(WorkerSlot& slot,
                                            void* tls_base,
                                            const mitm_ipc::ParsedRequestInfo& parsed,
                                            const AppSettings& cfg,
                                            bool tunnel_active) noexcept {
    if (!parsed.has_cmif_in_header) {
        return false;
    }

    if (parsed.hipc_type == CmifCommandType_Control || parsed.hipc_type == CmifCommandType_ControlWithContext) {
        if (parsed.cmif_cmd_id == 3) {
            const uint16_t max_ptr = static_cast<uint16_t>(kPointerSlotSize);
            mitm_ipc::WriteSimpleCmifResponse(tls_base, 0, &max_ptr, sizeof(max_ptr));
            return true;
        }
        return false;
    }

    const uint32_t cmd = parsed.cmif_cmd_id;
    if (cmd == sfdnsres_cmd::kGetAddrInfoRequest || cmd == sfdnsres_cmd::kGetAddrInfoRequestWithOptions ||
        cmd == sfdnsres_cmd::kGetHostByNameRequest || cmd == sfdnsres_cmd::kGetHostByNameRequestWithOptions) {
        size_t len = 0;
        const uint8_t* raw = PickFirstNonEmptyInput(parsed, 0, len);
        std::string host;
        if (ExtractBoundedHostString(raw, len, host) && tunnel_active && ctl_server_) {
            // Use TCP:80 probe for domain routing so block_quic (UDP:443) never suppresses hostname DNS resolution.
            mutexLock(&router_mutex_);
            const auto action = router_.Decide({host, 80, false, slot.proc_info.program_id}, cfg);
            mutexUnlock(&router_mutex_);
            if (action == net::RouteAction::Block) {
                ctl_server_->RecordConnection(slot.proc_info.program_id, host.c_str(), 53, true, 2 /*Block*/, 0);
                int32_t err_words[3] = {2 /*errno*/, -8 /*EAI_FAIL*/, 0 /*size*/};
                mitm_ipc::WriteSimpleCmifResponse(tls_base, 0, err_words, sizeof(err_words));
                return true;
            }

            auto* engine = ctl_server_->GetTunnelEngine();
            if (cfg.hijack_dns && action == net::RouteAction::Proxy && engine && engine->IsRunning() &&
                !net::IsLanOrSpecialHost(host)) {
                uint32_t ip_h = 0;
                if (!net::ParseIPv4Be(host, ip_h)) {
                    ip_h = engine->FakeIps().Allocate(host);
                }
                const HipcParsedRequest raw_req = hipcParseRequest(tls_base);
                if (ip_h != 0 && raw_req.meta.num_recv_buffers > 0) {
                    auto* out_buf = static_cast<uint8_t*>(hipcGetBufferAddress(&raw_req.data.recv_buffers[0]));
                    const size_t out_cap = hipcGetBufferSize(&raw_req.data.recv_buffers[0]);
                    size_t written = 0;
                    if (cmd == sfdnsres_cmd::kGetHostByNameRequest || cmd == sfdnsres_cmd::kGetHostByNameRequestWithOptions) {
                        written = net::SerializeSfdnsresHostentIPv4(host, ip_h, out_buf, out_cap);
                    } else {
                        written = net::SerializeSfdnsresAddrInfoIPv4(ip_h, 0, 1 /*SOCK_STREAM*/, 6 /*IPPROTO_TCP*/,
                                                                     host, out_buf, out_cap);
                    }
                    if (written > 0) {
                        ctl_server_->RecordConnection(slot.proc_info.program_id, host.c_str(), 53, true, 3 /*Dns*/, 1);
                        int32_t ok_words[3] = {0 /*errno*/, 0 /*ret*/, static_cast<int32_t>(written)};
                        mitm_ipc::WriteSimpleCmifResponse(tls_base, 0, ok_words, sizeof(ok_words));
                        return true;
                    }
                }
            }

            ctl_server_->RecordConnection(slot.proc_info.program_id, host.c_str(), 53, true, 3 /*Dns*/, 1);
        }
    }

    return false;
}

void NetworkMitmManager::RunWorker(WorkerSlot& slot) noexcept {
    Handle reply_target = 0;
    while (!stop_requested_.load() && !slot.stop_requested.load()) {
        if (reply_target == 0) {
            mitm_ipc::PrepareTlsRecvList(armGetTls(), slot.ptr_rx_buf, kPointerSlotCount, kPointerSlotSize);
        }

        s32 idx = -1;
        const Result wait_rc = svcReplyAndReceive(&idx, &slot.client_session, 1, reply_target, 150'000'000ULL);
        if (wait_rc == 0xEA01) {  // TimedOut
            reply_target = 0;
            continue;
        }
        if (R_FAILED(wait_rc)) {
            break;
        }

        void* tls = armGetTls();
        const u16 hipc_type = *static_cast<const u16*>(tls);
        if (hipc_type == CmifCommandType_Close || hipc_type == CmifCommandType_Invalid) {
            mitm_ipc::WriteSimpleCmifResponse(tls, 0, nullptr, 0);
            svcReplyAndReceive(&idx, &slot.client_session, 1, slot.client_session, 0);
            break;
        }

        mitm_ipc::ParsedRequestInfo parsed{};
        mitm_ipc::ParseIncomingHipc(tls, parsed);

        AppSettings cfg{};
        bool tunnel_active = false;
        if (ctl_server_) {
            cfg = ctl_server_->GetSettingsCopy();
            tunnel_active = ctl_server_->IsTunnelActive();
        }

        bool handled_directly = false;
        int32_t track_fd = -1;
        bool close_tracked = false;
        uint32_t cmd_id = parsed.cmif_cmd_id;
        alignas(16) uint8_t override_sa[16] = {};
        size_t override_sa_len = 0;

        if (slot.kind == ServiceKind::BsdU) {
            handled_directly = PreInspectBsd(slot, tls, parsed, cfg, tunnel_active, track_fd, close_tracked, cmd_id,
                                             override_sa, override_sa_len);
        } else {
            handled_directly = PreInspectSfdnsres(slot, tls, parsed, cfg, tunnel_active);
        }

        if (close_tracked && ctl_server_) {
            slot.open_socket_delta = std::max(0, slot.open_socket_delta - 1);
            ctl_server_->AdjustActiveSockets(-1);
        }

        Handle close_handles[8] = {};
        u32 close_count = 0;

        if (!handled_directly) {
            Result cmif_rc = 0;
            int32_t bsd_ret = 0;
            int32_t bsd_errno = 0;
            const Result fwd_rc = mitm_ipc::ForwardParsedHipc(
                tls, slot.fwd_handle, parsed, slot.ptr_tx_buf, kPointerSlotSize, slot.staging_buf, kStagingSize,
                close_handles, 8, &close_count, &cmif_rc, &bsd_ret, &bsd_errno,
                override_sa_len > 0 ? override_sa : nullptr, override_sa_len);

            if (R_SUCCEEDED(fwd_rc) && R_SUCCEEDED(cmif_rc) && slot.kind == ServiceKind::BsdU) {
                if ((cmd_id == bsd_cmd::kSocket || cmd_id == bsd_cmd::kSocketExempt) && bsd_ret >= 0) {
                    uint32_t sock_type = 1;
                    if (parsed.cmif_payload && parsed.cmif_payload_size >= 8) {
                        std::memcpy(&sock_type, parsed.cmif_payload + 4, sizeof(uint32_t));
                    }
                    for (auto& sock : slot.sockets) {
                        if (!sock.in_use) {
                            sock.in_use = true;
                            sock.fd = bsd_ret;
                            sock.is_udp = ((sock_type & 0xFu) == 2u);  // SOCK_DGRAM == 2
                            sock.remote_port = 0;
                            sock.remote_host[0] = '\0';
                            break;
                        }
                    }
                    ++slot.open_socket_delta;
                    if (ctl_server_) ctl_server_->AdjustActiveSockets(1);
                } else if (bsd_ret > 0 && ctl_server_) {
                    if (cmd_id == bsd_cmd::kSend || cmd_id == bsd_cmd::kSendTo || cmd_id == bsd_cmd::kWrite) {
                        ctl_server_->AddTrafficBytes(static_cast<uint64_t>(bsd_ret), 0);
                    } else if (cmd_id == bsd_cmd::kRecv || cmd_id == bsd_cmd::kRecvFrom || cmd_id == bsd_cmd::kRead) {
                        ctl_server_->AddTrafficBytes(0, static_cast<uint64_t>(bsd_ret));
                    }
                }
            }
        }

        const Result rep_rc = svcReplyAndReceive(&idx, nullptr, 0, slot.client_session, 0);
        for (u32 i = 0; i < close_count; ++i) {
            if (close_handles[i] != INVALID_HANDLE) {
                svcCloseHandle(close_handles[i]);
            }
        }
        if (R_FAILED(rep_rc) && rep_rc != 0xEA01) {
            break;
        }
        reply_target = 0;
    }

    slot.thread_finished.store(true);
}

}  // namespace yumi_nx::sys
