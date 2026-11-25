#include "latency_tester.hpp"

#include <algorithm>

#include "http_client.hpp"
#include "yumi_nx/dns_engine.hpp"
#include "yumi_nx/socket_io.hpp"
#include "yumi_nx/subscription_parser.hpp"
#include "yumi_nx/tls13_reality.hpp"

namespace yumi_nx::logic {

namespace {

int ProbeTcpOnce(const ProxyNode& node,
                 const AppSettings& settings,
                 net::IDnsResolver* resolver,
                 int timeout_ms) {
    net::SocketLayerInit();
    net::DohResolver fallback_dns(settings);
    net::IDnsResolver* dns = resolver ? resolver : &fallback_dns;

    uint32_t ip_host = 0;
    if (!ResolveHostIpv4Order(node.server, dns, ip_host)) return -1;

    const uint64_t t0 = net::MonotonicMs();
    net::NetSocket sock;
    if (!sock.ConnectExactBlocking(ip_host, node.port, timeout_ms)) return -1;
    const int ms = static_cast<int>(net::MonotonicMs() - t0);
    sock.Close();
    return std::max(1, ms);
}

int ProbeTlsOnce(const ProxyNode& node,
                 const AppSettings& settings,
                 net::IDnsResolver* resolver,
                 int timeout_ms) {
    net::SocketLayerInit();
    net::DohResolver fallback_dns(settings);
    net::IDnsResolver* dns = resolver ? resolver : &fallback_dns;

    if (node.protocol == Protocol::Hysteria2) {
        auto stream = net::CreateOutboundStream(node, settings);
        if (!stream) return -1;
        net::Endpoint ep{node.server, node.port, false, 0};
        const uint64_t t0 = net::MonotonicMs();
        const bool ok = stream->Connect(ep, *dns, timeout_ms);
        const int ms = static_cast<int>(net::MonotonicMs() - t0);
        stream->Close();
        return ok ? std::max(1, ms) : -1;
    }

    if (!node.tls.enabled && !node.tls.reality.enabled) {
        return ProbeTcpOnce(node, settings, dns, timeout_ms);
    }

    uint32_t ip_host = 0;
    if (!ResolveHostIpv4Order(node.server, dns, ip_host)) return -1;

    const uint64_t t0 = net::MonotonicMs();
    net::NetSocket sock;
    if (!sock.ConnectExactBlocking(ip_host, node.port, timeout_ms)) return -1;

    const std::string sni = !node.tls.server_name.empty() ? node.tls.server_name : node.server;
    const RealityOptions* reality = node.tls.reality.enabled ? &node.tls.reality : nullptr;
    const auto fp = net::ResolveEffectiveFingerprint(settings.tls_fingerprint, node.tls.fingerprint);
    const auto frag = net::MakeFragmentConfig(settings);

    net::Tls13Client tls;
    const bool ok = tls.Handshake(sock, sni, node.tls.alpn, reality,
                                  CurrentEpochSec(), timeout_ms, fp, &frag);
    const int ms = static_cast<int>(net::MonotonicMs() - t0);
    if (ok) tls.SendCloseNotify(sock);
    sock.Close();
    return ok ? std::max(1, ms) : -1;
}

int ProbeUrlOnce(const ProxyNode& node,
                 const AppSettings& settings,
                 net::IDnsResolver* resolver,
                 int timeout_ms,
                 std::string_view test_url) {
    HttpRequest req;
    req.method = "GET";
    req.url = test_url.empty() ? std::string("http://cp.cloudflare.com/generate_204") : std::string(test_url);
    req.follow_redirects = false;
    req.timeout_ms = timeout_ms;
    req.via_node = &node;
    req.settings = settings;
    req.resolver = resolver;
    const HttpResponse resp = ExecuteHttpRequest(req);
    if (!resp.ok || resp.status_code < 200 || resp.status_code >= 400) return -1;
    return std::max(1, resp.elapsed_ms);
}

}  // namespace

int ProbeNodeLatency(const ProxyNode& node,
                     const AppSettings& settings,
                     LatencyTestMethod method,
                     net::IDnsResolver* resolver,
                     int timeout_ms,
                     std::string_view test_url) {
    if (parse::IsPlaceholderNode(node) || node.server.empty() || node.port == 0) return -1;
    switch (method) {
        case LatencyTestMethod::TcpConnect:
            return ProbeTcpOnce(node, settings, resolver, timeout_ms);
        case LatencyTestMethod::TlsHandshake:
            return ProbeTlsOnce(node, settings, resolver, timeout_ms);
        case LatencyTestMethod::UrlTest:
            return ProbeUrlOnce(node, settings, resolver, timeout_ms, test_url);
    }
    return -1;
}

int ProbeNodeMedianLatency(const ProxyNode& node,
                           const AppSettings& settings,
                           LatencyTestMethod method,
                           int samples,
                           net::IDnsResolver* resolver,
                           int timeout_ms,
                           std::string_view test_url) {
    const int count = std::clamp(samples, 1, 5);
    std::vector<int> valid;
    valid.reserve(static_cast<size_t>(count));
    for (int i = 0; i < count; ++i) {
        const int r = ProbeNodeLatency(node, settings, method, resolver, timeout_ms, test_url);
        if (r >= 0) valid.push_back(r);
    }
    if (valid.empty()) return -1;
    std::sort(valid.begin(), valid.end());
    return valid[valid.size() / 2];
}

bool AsyncLatencyBatch::Start(std::vector<ProxyNode> nodes,
                              AppSettings settings,
                              LatencyTestMethod method,
                              int samples,
                              int timeout_ms,
                              int concurrency,
                              std::string test_url) {
    Stop();
    if (nodes.empty()) return true;

    nodes_ = std::move(nodes);
    settings_ = std::move(settings);
    method_ = method;
    samples_ = std::clamp(samples, 1, 3);
    timeout_ms_ = std::clamp(timeout_ms, 500, 15000);
    test_url_ = test_url.empty() ? std::string("http://cp.cloudflare.com/generate_204") : std::move(test_url);
    {
        SimpleLock lk(mu_);
        results_.clear();
    }

    total_.store(static_cast<int>(nodes_.size()));
    completed_.store(0);
    next_index_.store(0);
    stop_requested_.store(false);

    const int n_workers = std::clamp<int>(concurrency, 1, std::min<int>(kMaxWorkers, static_cast<int>(nodes_.size())));
    active_workers_.store(n_workers);
    spawned_count_ = 0;
    for (int i = 0; i < n_workers; ++i) {
        if (workers_[i].Start(&AsyncLatencyBatch::WorkerEntry, this, 0x10000)) {
            ++spawned_count_;
        } else {
            active_workers_.fetch_sub(1);
        }
    }
    return spawned_count_ > 0;
}

void AsyncLatencyBatch::Stop() noexcept {
    stop_requested_.store(true);
    for (int i = 0; i < spawned_count_; ++i) {
        workers_[i].Join();
    }
    spawned_count_ = 0;
    active_workers_.store(0);
}

void AsyncLatencyBatch::DrainCompleted(std::vector<LatencyResult>& out) {
    SimpleLock lk(mu_);
    if (results_.empty()) return;
    out.insert(out.end(),
               std::make_move_iterator(results_.begin()),
               std::make_move_iterator(results_.end()));
    results_.clear();
}

void AsyncLatencyBatch::WorkerEntry(void* arg) {
    if (auto* self = static_cast<AsyncLatencyBatch*>(arg)) {
        self->RunWorker();
    }
}

void AsyncLatencyBatch::RunWorker() {
    net::DohResolver local_dns(settings_);
    while (!stop_requested_.load()) {
        const int idx = next_index_.fetch_add(1);
        if (idx >= static_cast<int>(nodes_.size())) break;

        const ProxyNode& node = nodes_[static_cast<size_t>(idx)];
        const int ms = ProbeNodeMedianLatency(node, settings_, method_, samples_, &local_dns, timeout_ms_, test_url_);
        {
            SimpleLock lk(mu_);
            results_.push_back({node.id, ms});
        }
        completed_.fetch_add(1);
    }
    active_workers_.fetch_sub(1);
}

}  // namespace yumi_nx::logic
