#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "yumi_nx/models.hpp"

namespace yumi_nx::parse {

struct SubscriptionUserInfo {
    bool has_upload = false;
    uint64_t upload_bytes = 0;
    bool has_download = false;
    uint64_t download_bytes = 0;
    bool has_total = false;
    uint64_t total_bytes = 0;
    bool has_expire = false;
    int64_t expires_at_epoch_sec = 0;
};

struct SubscriptionRecord {
    std::string id;
    std::string name;
    std::string remote_title;
    std::string url;
    std::string user_agent_override;
    std::vector<std::pair<std::string, std::string>> headers;
    bool enabled = true;
    int32_t node_count = 0;
    int64_t last_updated_epoch_ms = 0;
    std::string last_error;
    std::optional<SubscriptionUserInfo> user_info;
};

struct SubscriptionParseResult {
    enum class Status : uint8_t {
        Ok = 0,
        Empty = 1,
        NotBase64 = 2,
        UnsupportedFormat = 3,
        NoSupportedServers = 4,
    };

    Status status = Status::Empty;
    std::string format_label;
    std::vector<ProxyNode> nodes;
    std::string placeholder_notice;
};

/// Stable 16-hex deterministic node identifier (matching server, port, protocol, transport & creds).
[[nodiscard]] std::string ComputeNodeId(const ProxyNode& node);

/// Placeholder notice rows sent by panels (server == "0.0.0.0" or port <= 1).
[[nodiscard]] bool IsPlaceholderNode(const ProxyNode& node) noexcept;

/// Parses one proxy share URI (`vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`/`hy2://`,
/// `wireguard://`/`wg://`, `socks://`/`socks5://`/`socks4://`, `http://`/`https://`).
[[nodiscard]] std::optional<ProxyNode> ParseProxyUri(std::string_view uri, std::string_view subscription_id = "");

/// Parses all valid proxy share URIs in multi-line text.
[[nodiscard]] std::vector<ProxyNode> ParseProxyUris(std::string_view text, std::string_view subscription_id = "");

/// Parses a full subscription body: plain share links, Base64 links, Xray/v2ray JSON, SIP008 JSON, or Clash YAML.
[[nodiscard]] SubscriptionParseResult ParseSubscriptionBody(std::string_view body, std::string_view subscription_id = "");

/// Parses HTTP header or comment `subscription-userinfo: upload=...; download=...; total=...; expire=...`.
[[nodiscard]] std::optional<SubscriptionUserInfo> ParseSubscriptionUserInfo(std::string_view header);

/// Scans `# key: value` / `// key: value` metadata lines from the top of plain or base64 subscription bodies.
[[nodiscard]] std::vector<std::pair<std::string, std::string>> ParseMetadataComments(std::string_view body);

/// Decodes `base64:<...>` profile-title headers if encoded.
[[nodiscard]] std::string DecodeProfileTitle(std::string_view raw);

}  // namespace yumi_nx::parse
