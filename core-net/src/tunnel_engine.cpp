#include "yumi_nx/tunnel_engine.hpp"

#include <algorithm>
#include <cstring>
#include <new>

namespace yumi_nx::net {

namespace {

struct ScopedLock {
    TunnelEngine* self;
    void (TunnelEngine::*lock_fn)() noexcept;
    void (TunnelEngine::*unlock_fn)() noexcept;
    // Simpler inline wrapper via public/friend lambda omitted — call directly via helper functions below.
};

}  // namespace

void TunnelEngine::Lock() noexcept {
#ifdef __SWITCH__
    mutexLock(&state_mutex_);
#else
    state_mutex_.lock();
#endif
}

void TunnelEngine::Unlock() noexcept {
#ifdef __SWITCH__
    mutexUnlock(&state_mutex_);
#else
    state_mutex_.unlock();
#endif
}

TunnelEngine::TunnelEngine() noexcept {
#ifdef __SWITCH__
    mutexInit(&state_mutex_);
#endif
}

TunnelEngine::~TunnelEngine() {
    Stop();
}

void TunnelEngine::SetCallbacks(TrafficCallback on_traffic, LogCallback on_log) noexcept {
    Lock();
    on_traffic_ = std::move(on_traffic);
    on_log_ = std::move(on_log);
    Unlock();
}

void TunnelEngine::Log(LogLevel lvl, const char* msg) noexcept {
    LogCallback cb;
    Lock();
    cb = on_log_;
    Unlock();
    if (cb) cb(lvl, msg);
}

#ifdef __SWITCH__
void TunnelEngine::ThreadEntry(void* arg) {
    if (auto* self = static_cast<TunnelEngine*>(arg)) {
        while (!self->stop_requested_.load()) {
            self->StepOnce(25);
        }
    }
}
#endif

bool TunnelEngine::Start(const ProxyNode& node,
                         const AppSettings& settings,
                         bool spawn_thread,
                         uint16_t preferred_port) noexcept {
    Stop();
    SocketLayerInit();

    uint16_t port = preferred_port;
    NetSocket listener = NetSocket::TcpListenLoopback(port);
    if (!listener.IsValid() || port == 0) {
        Log(LogLevel::Error, "TunnelEngine: TcpListenLoopback failed");
        return false;
    }

    Lock();
    active_node_ = node;
    settings_ = settings;
    resolver_.UpdateSettings(settings);
    listen_sock_ = std::move(listener);
    pending_.clear();
    flows_.clear();
    relay_port_.store(port);
    stop_requested_.store(false);
    reset_requested_.store(false);
    running_.store(true);
    Unlock();

    if (spawn_thread) {
#ifdef __SWITCH__
        if (R_FAILED(threadCreate(&thread_, &TunnelEngine::ThreadEntry, this, thread_stack_, sizeof(thread_stack_), 0x3B, -2))) {
            Stop();
            Log(LogLevel::Error, "TunnelEngine: threadCreate failed");
            return false;
        }
        if (R_FAILED(threadStart(&thread_))) {
            threadClose(&thread_);
            Stop();
            Log(LogLevel::Error, "TunnelEngine: threadStart failed");
            return false;
        }
        thread_started_ = true;
#else
        worker_ = std::thread([this]() {
            while (!stop_requested_.load()) {
                StepOnce(25);
            }
        });
#endif
    }

    Log(LogLevel::Info, "TunnelEngine started");
    return true;
}

void TunnelEngine::Stop() noexcept {
    stop_requested_.store(true);
#ifdef __SWITCH__
    if (thread_started_) {
        svcCancelSynchronization(thread_.handle);
        threadWaitForExit(&thread_);
        threadClose(&thread_);
        thread_started_ = false;
    }
#else
    if (worker_.joinable()) {
        worker_.join();
    }
#endif
    Lock();
    listen_sock_.Close();
    CloseAllFlows();
    pending_.clear();
    fake_ips_.Clear();
    relay_port_.store(0);
    active_flow_count_.store(0);
    running_.store(false);
    Unlock();
}

void TunnelEngine::UpdateSettings(const AppSettings& settings) noexcept {
    Lock();
    settings_ = settings;
    resolver_.UpdateSettings(settings);
    Unlock();
}

void TunnelEngine::ResetAllFlows() noexcept {
    reset_requested_.store(true);
}

void TunnelEngine::RegisterPendingTarget(uint16_t src_port, const Endpoint& target) noexcept {
    Lock();
    const uint64_t now = MonotonicMs();
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (!it->valid || (now - it->created_ms) > 10'000ULL || it->src_port == src_port) {
            it = pending_.erase(it);
        } else {
            ++it;
        }
    }
    if (pending_.size() >= kMaxPending) {
        pending_.erase(pending_.begin());
    }
    pending_.push_back({true, src_port, target, now});
    Unlock();
}

bool TunnelEngine::PopPendingTarget(uint16_t src_port, Endpoint& out_target) noexcept {
    Lock();
    const uint64_t now = MonotonicMs();
    bool found = false;
    for (auto it = pending_.begin(); it != pending_.end();) {
        if (!it->valid || (now - it->created_ms) > 10'000ULL) {
            it = pending_.erase(it);
            continue;
        }
        if (it->src_port == src_port) {
            out_target = it->target;
            pending_.erase(it);
            found = true;
            break;
        }
        ++it;
    }
    Unlock();
    return found;
}

void TunnelEngine::CloseAllFlows() noexcept {
    for (auto& f : flows_) {
        if (f) {
            if (f->outbound) f->outbound->Close();
            f->client.Close();
        }
    }
    flows_.clear();
    active_flow_count_.store(0);
}

void TunnelEngine::AcceptPendingConnections() noexcept {
    for (int k = 0; k < 8; ++k) {
        if (flows_.size() >= kMaxFlows || !listen_sock_.IsValid()) break;

        uint32_t peer_ip = 0;
        uint16_t peer_port = 0;
        NetSocket cli = listen_sock_.Accept(peer_ip, peer_port);
        if (!cli.IsValid()) break;

        Endpoint target{};
        if (!PopPendingTarget(peer_port, target)) {
            Log(LogLevel::Warn, "TunnelEngine: orphan loopback connection without target");
            continue;
        }

        ProxyNode node_copy;
        AppSettings cfg_copy;
        Lock();
        node_copy = active_node_;
        cfg_copy = settings_;
        Unlock();

        auto stream = CreateOutboundStream(node_copy, cfg_copy);
        if (!stream) continue;

        if (!stream->Connect(target, resolver_, 5000)) {
            Log(LogLevel::Warn, "TunnelEngine: outbound connect failed");
            continue;
        }

        auto flow = std::unique_ptr<RelayFlow>(new (std::nothrow) RelayFlow());
        if (!flow) {
            stream->Close();
            continue;
        }
        flow->client = std::move(cli);
        flow->outbound = std::move(stream);
        flow->target = std::move(target);
        flows_.push_back(std::move(flow));
        active_flow_count_.store(static_cast<uint32_t>(flows_.size()));
    }
}

void TunnelEngine::PumpFlows(int timeout_ms) noexcept {
    if (reset_requested_.exchange(false)) {
        CloseAllFlows();
    }

    std::vector<PollItem> items;
    items.reserve(1 + flows_.size() * 2);

    PollItem listen_p{};
    listen_p.fd = listen_sock_.Fd();
    listen_p.want_read = listen_sock_.IsValid();
    items.push_back(listen_p);

    struct FlowIdxMap {
        size_t flow_idx;
        int client_poll_idx;
        int out_poll_idx;
    };
    std::vector<FlowIdxMap> map;
    map.reserve(flows_.size());

    for (size_t i = 0; i < flows_.size(); ++i) {
        auto* f = flows_[i].get();
        if (!f || !f->client.IsValid() || !f->outbound) continue;

        PollItem cp{};
        cp.fd = f->client.Fd();
        cp.want_read = !f->client_eof && (f->c2s_buf.size() - f->c2s_off < kIoBufCap);
        cp.want_write = (f->s2c_off < f->s2c_buf.size());
        const int c_idx = static_cast<int>(items.size());
        items.push_back(cp);

        int o_idx = -1;
        const SocketFd ofd = f->outbound->NativeFd();
        if (ofd != kInvalidSocket) {
            PollItem op{};
            op.fd = ofd;
            op.want_read = !f->remote_eof && (f->s2c_buf.size() - f->s2c_off < kIoBufCap);
            op.want_write = (f->c2s_off < f->c2s_buf.size()) || f->outbound->HasPendingWrite();
            o_idx = static_cast<int>(items.size());
            items.push_back(op);
        }
        map.push_back({i, c_idx, o_idx});
    }

    PollSockets(items.data(), items.size(), timeout_ms);

    if (!items.empty() && items[0].rev_read) {
        AcceptPendingConnections();
    }

    uint64_t delta_up = 0;
    uint64_t delta_down = 0;
    std::vector<bool> drop(flows_.size(), false);

    for (const auto& m : map) {
        auto* f = flows_[m.flow_idx].get();
        if (!f) continue;

        // 1. Read client -> c2s_buf
        if (!f->client_eof && (f->c2s_buf.size() - f->c2s_off < kIoBufCap)) {
            const auto r = f->client.RecvSome(io_scratch_, std::min<size_t>(sizeof(io_scratch_), kIoBufCap - (f->c2s_buf.size() - f->c2s_off)));
            if (r.status == IoStatus::Ok && r.bytes > 0) {
                f->c2s_buf.insert(f->c2s_buf.end(), io_scratch_, io_scratch_ + r.bytes);
            } else if (r.status == IoStatus::Eof) {
                f->client_eof = true;
            } else if (r.status == IoStatus::Error) {
                drop[m.flow_idx] = true;
            }
        }

        // 2. Write c2s_buf -> outbound
        if (!drop[m.flow_idx] && f->outbound) {
            if (!f->outbound->FlushPending()) {
                drop[m.flow_idx] = true;
            } else if (f->c2s_off < f->c2s_buf.size()) {
                const auto w = f->outbound->WriteNonBlocking(f->c2s_buf.data() + f->c2s_off, f->c2s_buf.size() - f->c2s_off);
                if (w.status == IoStatus::Ok && w.bytes > 0) {
                    f->c2s_off += w.bytes;
                    delta_up += w.bytes;
                    if (f->c2s_off >= f->c2s_buf.size()) {
                        f->c2s_buf.clear();
                        f->c2s_off = 0;
                    }
                } else if (w.status == IoStatus::Error) {
                    drop[m.flow_idx] = true;
                }
            }
        }

        // 3. Read outbound -> s2c_buf
        if (!drop[m.flow_idx] && f->outbound && !f->remote_eof && (f->s2c_buf.size() - f->s2c_off < kIoBufCap)) {
            const auto r = f->outbound->ReadNonBlocking(io_scratch_, std::min<size_t>(sizeof(io_scratch_), kIoBufCap - (f->s2c_buf.size() - f->s2c_off)));
            if (r.status == IoStatus::Ok && r.bytes > 0) {
                f->s2c_buf.insert(f->s2c_buf.end(), io_scratch_, io_scratch_ + r.bytes);
            } else if (r.status == IoStatus::Eof) {
                f->remote_eof = true;
            } else if (r.status == IoStatus::Error) {
                drop[m.flow_idx] = true;
            }
        }

        // 4. Write s2c_buf -> client
        if (!drop[m.flow_idx] && f->s2c_off < f->s2c_buf.size()) {
            const auto w = f->client.SendSome(f->s2c_buf.data() + f->s2c_off, f->s2c_buf.size() - f->s2c_off);
            if (w.status == IoStatus::Ok && w.bytes > 0) {
                f->s2c_off += w.bytes;
                delta_down += w.bytes;
                if (f->s2c_off >= f->s2c_buf.size()) {
                    f->s2c_buf.clear();
                    f->s2c_off = 0;
                }
            } else if (w.status == IoStatus::Error || w.status == IoStatus::Eof) {
                drop[m.flow_idx] = true;
            }
        }

        const bool tx_drained = (f->c2s_off >= f->c2s_buf.size()) && !f->outbound->HasPendingWrite();
        const bool rx_drained = (f->s2c_off >= f->s2c_buf.size());
        if ((f->client_eof && tx_drained) || (f->remote_eof && rx_drained)) {
            drop[m.flow_idx] = true;
        }
    }

    if (delta_up > 0 || delta_down > 0) {
        total_up_.fetch_add(delta_up);
        total_down_.fetch_add(delta_down);
        TrafficCallback cb;
        Lock();
        cb = on_traffic_;
        Unlock();
        if (cb) cb(delta_up, delta_down);
    }

    for (size_t i = flows_.size(); i > 0; --i) {
        const size_t idx = i - 1;
        if (idx < drop.size() && drop[idx]) {
            if (flows_[idx] && flows_[idx]->outbound) flows_[idx]->outbound->Close();
            if (flows_[idx]) flows_[idx]->client.Close();
            flows_.erase(flows_.begin() + static_cast<ptrdiff_t>(idx));
        }
    }
    active_flow_count_.store(static_cast<uint32_t>(flows_.size()));
}

void TunnelEngine::StepOnce(int timeout_ms) noexcept {
    if (!running_.load()) return;
    AcceptPendingConnections();
    PumpFlows(timeout_ms);
}

}  // namespace yumi_nx::net
