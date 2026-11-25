#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "yumi_nx/models.hpp"
#include "yumi_nx/net_interfaces.hpp"

namespace yumi_nx::logic {

struct ParsedUrl {
    bool valid = false;
    bool is_https = false;
    std::string host;
    uint16_t port = 0;
    std::string path_and_query = "/";
};

struct HttpRequest {
    std::string method = "GET";
    std::string url;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::string user_agent = "YumiSwitch/1.0";
    bool follow_redirects = true;
    int max_redirects = 5;
    int timeout_ms = 10000;
    size_t max_response_bytes = 8 * 1024 * 1024;
    const ProxyNode* via_node = nullptr;
    AppSettings settings{};
    net::IDnsResolver* resolver = nullptr;
};

struct HttpResponse {
    bool ok = false;
    int status_code = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::string final_url;
    std::string error;
    int elapsed_ms = 0;

    [[nodiscard]] std::string Header(std::string_view name_ci) const;
};

using DownloadProgressCallback = std::function<void(uint64_t received_bytes, int64_t total_bytes)>;

/// Parses `http://host[:port]/path?query` or `https://host[:port]/path?query`.
[[nodiscard]] ParsedUrl ParseHttpUrl(std::string_view url);

/// Resolves relative `location` against `base_url` (supporting absolute URLs, `//proto`, and `/path`).
[[nodiscard]] std::string ResolveRedirectUrl(std::string_view base_url, std::string_view location);

/// Executes HTTP/1.1 (+ optional TLS 1.3 with uTLS & FragmentMode) either directly or via `req.via_node`.
[[nodiscard]] HttpResponse ExecuteHttpRequest(const HttpRequest& req);

/// Streams response body to `<dest_path>.part` and atomically renames on HTTP 2xx completion.
[[nodiscard]] HttpResponse DownloadHttpFileAtomic(const HttpRequest& req,
                                                  const std::string& dest_path,
                                                  const DownloadProgressCallback& on_progress = {},
                                                  std::atomic<bool>* cancel = nullptr);

}  // namespace yumi_nx::logic
