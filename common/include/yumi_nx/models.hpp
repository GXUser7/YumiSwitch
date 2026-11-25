#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yumi_nx {

enum class Protocol : uint8_t {
    Vless = 0,
    Vmess = 1,
    Trojan = 2,
    Shadowsocks = 3,
    Hysteria2 = 4,
    WireGuard = 5,
    Socks5 = 6,
    Http = 7,
    Direct = 8,
};

enum class TransportKind : uint8_t {
    Raw = 0,
    WebSocket = 1,
    HttpUpgrade = 2,
    Grpc = 3,
    Xhttp = 4,
};

enum class RoutingMode : uint8_t {
    Global = 0,
    Rules = 1,
    Direct = 2,
};

enum class TlsFingerprint : uint8_t {
    Auto = 0,
    Chrome = 1,
    Firefox = 2,
    Safari = 3,
    Ios = 4,
    Android = 5,
    Edge = 6,
    Qq = 7,
    Browser360 = 8,
    Random = 9,
    Randomized = 10,
};

enum class FragmentMode : uint8_t {
    Off = 0,
    TlsHello = 1,
    TcpSegments = 2,
};

enum class FragmentScope : uint8_t {
    TlsOnly = 0,
    TlsAndReality = 1,
    AllTcp = 2,
};

enum class SplitTunnelMode : uint8_t {
    Off = 0,
    AllowList = 1,
    BlockList = 2,
};

enum class TunnelState : uint8_t {
    Off = 0,
    Connecting = 1,
    On = 2,
    Stopping = 3,
    Error = 4,
};

enum class LogLevel : uint8_t {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
};

struct RealityOptions {
    bool enabled = false;
    std::string public_key;
    std::string short_id;
    std::string spider_x = "/";
};

struct TlsOptions {
    bool enabled = false;
    std::string server_name;
    bool insecure = false;
    std::vector<std::string> alpn;
    std::string fingerprint;
    std::string pinned_cert_sha256;
    std::string verify_peer_cert_by_name;
    RealityOptions reality;
};

struct TransportOptions {
    TransportKind kind = TransportKind::Raw;
    std::string path = "/";
    std::string host;
    std::string service_name;
    bool grpc_multi_mode = false;
    std::string grpc_authority;
    std::string xhttp_mode = "auto";
};

struct WireGuardOptions {
    std::string private_key;
    std::string peer_public_key;
    std::string pre_shared_key;
    std::vector<std::string> local_addresses;
    uint16_t mtu = 1408;
    uint8_t reserved[3] = {0, 0, 0};
    bool has_reserved = false;
};

struct Hysteria2Options {
    std::string obfs_type;
    std::string obfs_password;
    uint32_t up_mbps = 0;
    uint32_t down_mbps = 0;
};

struct ProxyNode {
    std::string id;
    std::string name;
    std::string server;
    uint16_t port = 443;
    Protocol protocol = Protocol::Vless;

    // Credentials / protocol-specific parameters
    std::string uuid_or_user;
    std::string password_or_key;
    std::string method;  // Shadowsocks cipher / VMess security
    std::string flow;    // e.g. xtls-rprx-vision
    std::string packet_encoding = "xudp";

    TlsOptions tls;
    TransportOptions transport;
    WireGuardOptions wireguard;
    Hysteria2Options hysteria2;
    std::string subscription_id;
};

struct CustomRules {
    enum class Action : uint8_t { Proxy = 0, Direct = 1, Block = 2 };

    std::vector<std::string> proxy;
    std::vector<std::string> direct;
    std::vector<std::string> block;

    [[nodiscard]] bool Empty() const noexcept {
        return proxy.empty() && direct.empty() && block.empty();
    }

    // Normalizes URLs, host:port, IPv4/IPv6, CIDRs, or matcher prefixes (domain:, full:, keyword:, geosite:, geoip:).
    [[nodiscard]] static std::optional<std::string> Normalize(std::string_view raw);
};

// Settings for yumi-nx (intentionally omits FailoverWatchdog, cellular pools, and GeoZones).
struct AppSettings {
    RoutingMode routing_mode = RoutingMode::Rules;
    bool bypass_lan = true;
    bool block_ads = false;
    bool block_quic = true;
    bool enable_ipv6 = false;

    // DNS & Server Address Resolution
    std::string remote_dns = "https://1.1.1.1/dns-query";
    std::string direct_dns = "8.8.8.8";
    bool hijack_dns = true;
    bool dns_fallback = true;
    bool resolve_server_address = true;
    std::string resolve_doh_url = "https://1.1.1.1/dns-query";

    // DPI Circumvention
    TlsFingerprint tls_fingerprint = TlsFingerprint::Auto;
    FragmentMode fragment_mode = FragmentMode::Off;
    FragmentScope fragment_scope = FragmentScope::TlsAndReality;
    std::string fragment_length = "20-50";
    std::string fragment_interval = "2-5";
    std::string fragment_max_chunks;

    // Horizon OS Behavior & Split Tunneling (TitleID / ProgramID)
    bool auto_connect_on_boot = false;
    SplitTunnelMode split_tunnel_mode = SplitTunnelMode::Off;
    std::vector<uint64_t> split_tunnel_title_ids;

    // Subscriptions & Diagnostics
    std::string device_id;  // random x-hwid generated once
    bool subscription_auto_update = true;
    uint32_t subscription_update_minutes = 360;
    LogLevel log_level = LogLevel::Info;

    CustomRules custom_rules;
};

const char* ToString(Protocol p) noexcept;
const char* ToString(TransportKind t) noexcept;
const char* ToString(RoutingMode m) noexcept;
const char* ToString(TunnelState s) noexcept;

}  // namespace yumi_nx
