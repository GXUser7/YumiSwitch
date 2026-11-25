#include "speed_tester.hpp"

#include <algorithm>
#include <cstdio>

#include "http_client.hpp"
#include "yumi_nx/socket_io.hpp"

namespace yumi_nx::logic {

namespace {

double ComputeMbps(size_t bytes, uint64_t elapsed_ms) noexcept {
    if (bytes == 0) return 0.0;
    const double sec = std::max<double>(0.001, static_cast<double>(elapsed_ms) / 1000.0);
    return (static_cast<double>(bytes) * 8.0) / (sec * 1'000'000.0);
}

std::string FormatSpeedSummary(double down_mbps, double up_mbps, int ping_ms) {
    char buf[96];
    if (ping_ms >= 0) {
        std::snprintf(buf, sizeof(buf), "%.1f↓ / %.1f↑ Mbps · %d ms", down_mbps, up_mbps, ping_ms);
    } else {
        std::snprintf(buf, sizeof(buf), "%.1f↓ / %.1f↑ Mbps", down_mbps, up_mbps);
    }
    return std::string(buf);
}

}  // namespace

SpeedTestState RunSpeedTestSync(const SpeedTestConfig& cfg,
                                  const SpeedProgressCallback& on_progress,
                                  std::atomic<bool>* cancel) {
    SpeedTestState st;
    st.running = true;
    st.progress_0_1 = 0.08;
    st.summary = "Замер Download…";
    if (on_progress) on_progress(st);

    if (cancel && cancel->load()) {
        st.running = false;
        st.finished = true;
        st.error = "Отменено";
        st.summary = "Отменено";
        return st;
    }

    // Step 1: Download throughput probe
    HttpRequest dl_req;
    dl_req.method = "GET";
    dl_req.url = cfg.download_url;
    dl_req.timeout_ms = cfg.timeout_ms;
    dl_req.max_response_bytes = 32 * 1024 * 1024;
    dl_req.via_node = cfg.via_node;
    dl_req.settings = cfg.settings;

    const uint64_t dl_t0 = net::MonotonicMs();
    const HttpResponse dl_resp = ExecuteHttpRequest(dl_req);
    const uint64_t dl_dt = std::max<uint64_t>(1, net::MonotonicMs() - dl_t0);

    if (!dl_resp.ok || dl_resp.status_code < 200 || dl_resp.status_code >= 400) {
        st.running = false;
        st.finished = true;
        st.ok = false;
        st.error = dl_resp.error.empty() ? ("HTTP " + std::to_string(dl_resp.status_code)) : dl_resp.error;
        st.summary = "Ошибка Download: " + st.error;
        return st;
    }

    st.download_mbps = ComputeMbps(dl_resp.body.size(), dl_dt);
    st.ping_ms = std::min(dl_resp.elapsed_ms, 999);
    st.progress_0_1 = 0.55;
    st.summary = "Замер Upload…";
    if (on_progress) on_progress(st);

    if (cancel && cancel->load()) {
        st.running = false;
        st.finished = true;
        st.error = "Отменено";
        st.summary = "Отменено";
        return st;
    }

    // Step 2: Upload throughput probe (optional if upload_url is non-empty)
    if (!cfg.upload_url.empty() && cfg.upload_bytes > 0) {
        HttpRequest ul_req;
        ul_req.method = "POST";
        ul_req.url = cfg.upload_url;
        ul_req.timeout_ms = cfg.timeout_ms;
        ul_req.headers.emplace_back("Content-Type", "application/octet-stream");
        ul_req.body.assign(cfg.upload_bytes, 'Y');
        ul_req.via_node = cfg.via_node;
        ul_req.settings = cfg.settings;

        const uint64_t ul_t0 = net::MonotonicMs();
        const HttpResponse ul_resp = ExecuteHttpRequest(ul_req);
        const uint64_t ul_dt = std::max<uint64_t>(1, net::MonotonicMs() - ul_t0);
        if (ul_resp.ok && ul_resp.status_code >= 200 && ul_resp.status_code < 400) {
            st.upload_mbps = ComputeMbps(ul_req.body.size(), ul_dt);
        }
    }

    st.running = false;
    st.finished = true;
    st.ok = true;
    st.progress_0_1 = 1.0;
    st.summary = FormatSpeedSummary(st.download_mbps, st.upload_mbps, st.ping_ms);
    if (on_progress) on_progress(st);
    return st;
}

bool AsyncSpeedTestRunner::Start(const SpeedTestConfig& cfg) {
    Stop();
    {
        SimpleLock lk(mu_);
        cfg_ = cfg;
        has_via_node_ = (cfg.via_node != nullptr);
        if (has_via_node_) {
            owned_via_node_ = *cfg.via_node;
            cfg_.via_node = &owned_via_node_;
        } else {
            cfg_.via_node = nullptr;
        }
        state_ = {};
        state_.running = true;
        state_.progress_0_1 = 0.05;
        state_.summary = "Запуск замера…";
    }
    stop_requested_.store(false);
    running_.store(true);
    if (!worker_.Start(&AsyncSpeedTestRunner::ThreadEntry, this, 0x10000)) {
        running_.store(false);
        SimpleLock lk(mu_);
        state_.running = false;
        state_.finished = true;
        state_.summary = "Ошибка запуска потока";
        return false;
    }
    return true;
}

void AsyncSpeedTestRunner::Stop() noexcept {
    stop_requested_.store(true);
    worker_.Join();
    running_.store(false);
}

SpeedTestState AsyncSpeedTestRunner::Snapshot() {
    SimpleLock lk(mu_);
    return state_;
}

void AsyncSpeedTestRunner::ThreadEntry(void* arg) {
    if (auto* self = static_cast<AsyncSpeedTestRunner*>(arg)) {
        self->Run();
    }
}

void AsyncSpeedTestRunner::Run() {
    SpeedTestConfig local_cfg;
    {
        SimpleLock lk(mu_);
        local_cfg = cfg_;
        local_cfg.via_node = has_via_node_ ? &owned_via_node_ : nullptr;
    }
    SpeedTestState final_st = RunSpeedTestSync(
        local_cfg,
        [this](const SpeedTestState& s) {
            SimpleLock lk(mu_);
            state_ = s;
        },
        &stop_requested_);
    {
        SimpleLock lk(mu_);
        state_ = final_st;
    }
    running_.store(false);
}

}  // namespace yumi_nx::logic
