#include "yumi_nx/models.hpp"

#include <algorithm>
#include <cctype>
#include <array>

namespace yumi_nx {

namespace {

bool IsDigit(char c) noexcept { return c >= '0' && c <= '9'; }

bool IsNumericAddress(std::string_view host) noexcept {
    if (host.empty()) return false;
    if (host.find(':') != std::string_view::npos) {
        // Basic IPv6 literal check (hex digits and colons)
        return std::all_of(host.begin(), host.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                   (c >= 'A' && c <= 'F') || c == ':';
        });
    }
    int dots = 0;
    size_t part_start = 0;
    for (size_t i = 0; i <= host.size(); ++i) {
        if (i == host.size() || host[i] == '.') {
            if (i == part_start || i - part_start > 3) return false;
            int val = 0;
            for (size_t j = part_start; j < i; ++j) {
                if (!IsDigit(host[j])) return false;
                val = val * 10 + (host[j] - '0');
            }
            if (val > 255) return false;
            if (i < host.size()) ++dots;
            part_start = i + 1;
        }
    }
    return dots == 3;
}

std::string ToLowerAscii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

std::string_view TrimAscii(std::string_view s) noexcept {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
    return s;
}

bool IsValidDomain(std::string_view host) noexcept {
    if (host.empty() || host.size() > 253) return false;
    bool all_digits = true;
    size_t label_start = 0;
    for (size_t i = 0; i <= host.size(); ++i) {
        if (i == host.size() || host[i] == '.') {
            const size_t len = i - label_start;
            if (len == 0 || len > 63) return false;
            const char first = host[label_start];
            const char last = host[i - 1];
            if (first == '-' || last == '-') return false;
            label_start = i + 1;
        } else {
            const char c = host[i];
            const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!ok) return false;
            if (!IsDigit(c)) all_digits = false;
        }
    }
    return !all_digits;
}

std::optional<std::string_view> ExtractHostFromHostPort(std::string_view hp) noexcept {
    if (hp.empty()) return std::nullopt;
    if (hp.front() == '[') {
        const size_t close = hp.find(']');
        if (close == std::string_view::npos || close <= 1) return std::nullopt;
        if (close + 1 < hp.size()) {
            if (hp[close + 1] != ':') return std::nullopt;
            for (char c : hp.substr(close + 2)) {
                if (!IsDigit(c)) return std::nullopt;
            }
        }
        return hp.substr(1, close - 1);
    }
    const size_t first_colon = hp.find(':');
    const size_t last_colon = hp.rfind(':');
    if (first_colon != std::string_view::npos && first_colon == last_colon) {
        const std::string_view port_str = hp.substr(last_colon + 1);
        if (!port_str.empty() && std::all_of(port_str.begin(), port_str.end(), IsDigit)) {
            return hp.substr(0, last_colon);
        }
        return std::nullopt;
    }
    return hp;
}

}  // namespace

std::optional<std::string> CustomRules::Normalize(std::string_view raw) {
    std::string_view value = TrimAscii(raw);
    while (!value.empty() && value.back() == '/') value.remove_suffix(1);
    if (value.empty()) return std::nullopt;
    for (char c : value) {
        if (std::isspace(static_cast<unsigned char>(c))) return std::nullopt;
    }

    static constexpr std::array<std::string_view, 6> kKeptPrefixes = {
        "domain", "full", "keyword", "regexp", "geosite", "geoip",
    };
    const size_t colon = value.find(':');
    if (colon != std::string_view::npos && colon > 0 && value.find("://") == std::string_view::npos) {
        const std::string prefix = ToLowerAscii(value.substr(0, colon));
        if (std::find(kKeptPrefixes.begin(), kKeptPrefixes.end(), prefix) != kKeptPrefixes.end()) {
            const std::string_view rest = TrimAscii(value.substr(colon + 1));
            if (rest.empty()) return std::nullopt;
            return prefix + ":" + std::string(rest);
        }
    }

    // Parse IPv4/IPv6 CIDR before stripping URL paths
    const size_t slash = value.find('/');
    if (slash != std::string_view::npos && slash > 0 && value.find("://") == std::string_view::npos) {
        std::string_view addr = value.substr(0, slash);
        if (addr.size() >= 2 && addr.front() == '[' && addr.back() == ']') {
            addr = addr.substr(1, addr.size() - 2);
        }
        const std::string_view bits_str = value.substr(slash + 1);
        if (IsNumericAddress(addr) && !bits_str.empty() && bits_str.size() <= 3 &&
            std::all_of(bits_str.begin(), bits_str.end(), IsDigit)) {
            int bits = 0;
            for (char c : bits_str) bits = bits * 10 + (c - '0');
            const int widest = (addr.find(':') != std::string_view::npos) ? 128 : 32;
            if (bits >= 0 && bits <= widest) {
                return std::string(addr) + "/" + std::to_string(bits);
            }
            return std::nullopt;
        }
    }

    const size_t scheme_pos = value.find("://");
    if (scheme_pos != std::string_view::npos) {
        value = value.substr(scheme_pos + 3);
    }
    const size_t path_end = value.find_first_of("/?#");
    if (path_end != std::string_view::npos) {
        value = value.substr(0, path_end);
    }
    const size_t at_pos = value.rfind('@');
    if (at_pos != std::string_view::npos) {
        value = value.substr(at_pos + 1);
    }
    if (value.empty()) return std::nullopt;

    const auto host_opt = ExtractHostFromHostPort(value);
    if (!host_opt.has_value()) return std::nullopt;
    std::string_view host = *host_opt;

    if (IsNumericAddress(host)) return std::string(host);

    std::string lower_host = ToLowerAscii(host);
    while (!lower_host.empty() && lower_host.back() == '.') lower_host.pop_back();
    if (!IsValidDomain(lower_host)) return std::nullopt;
    return "domain:" + lower_host;
}

const char* ToString(Protocol p) noexcept {
    switch (p) {
        case Protocol::Vless: return "VLESS";
        case Protocol::Vmess: return "VMess";
        case Protocol::Trojan: return "Trojan";
        case Protocol::Shadowsocks: return "Shadowsocks";
        case Protocol::Hysteria2: return "Hysteria2";
        case Protocol::WireGuard: return "WireGuard";
        case Protocol::Socks5: return "SOCKS5";
        case Protocol::Http: return "HTTP";
        case Protocol::Direct: return "Direct";
    }
    return "Unknown";
}

const char* ToString(TransportKind t) noexcept {
    switch (t) {
        case TransportKind::Raw: return "RAW";
        case TransportKind::WebSocket: return "WS";
        case TransportKind::HttpUpgrade: return "HTTPUpgrade";
        case TransportKind::Grpc: return "gRPC";
        case TransportKind::Xhttp: return "XHTTP";
    }
    return "RAW";
}

const char* ToString(RoutingMode m) noexcept {
    switch (m) {
        case RoutingMode::Global: return "Global";
        case RoutingMode::Rules: return "Rules";
        case RoutingMode::Direct: return "Direct";
    }
    return "Rules";
}

const char* ToString(TunnelState s) noexcept {
    switch (s) {
        case TunnelState::Off: return "Off";
        case TunnelState::Connecting: return "Connecting";
        case TunnelState::On: return "On";
        case TunnelState::Stopping: return "Stopping";
        case TunnelState::Error: return "Error";
    }
    return "Off";
}

}  // namespace yumi_nx
