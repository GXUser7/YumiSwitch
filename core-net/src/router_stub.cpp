#include "yumi_nx/net_interfaces.hpp"

#include <algorithm>
#include <cctype>

#include "yumi_nx/config_store.hpp"

namespace yumi_nx::net {

namespace {

bool ParseOctet(std::string_view part, uint8_t& out) noexcept {
    if (part.empty() || part.size() > 3) return false;
    uint32_t val = 0;
    for (char c : part) {
        if (c < '0' || c > '9') return false;
        val = val * 10u + static_cast<uint32_t>(c - '0');
    }
    if (val > 255u) return false;
    out = static_cast<uint8_t>(val);
    return true;
}

bool MatchRuleToken(std::string_view rule_raw, std::string_view host_lower,
                    uint32_t ipv4_be, bool has_ipv4, bool is_udp, uint16_t port) noexcept {
    std::string low;
    low.reserve(rule_raw.size());
    for (char c : rule_raw) low.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));

    if (low == "udp:443") return is_udp && port == 443;
    if (low.starts_with("full:")) {
        return host_lower == low.substr(5);
    }
    if (low.starts_with("domain:")) {
        const std::string_view dom = std::string_view(low).substr(7);
        if (dom.empty()) return false;
        if (host_lower == dom) return true;
        return host_lower.size() > dom.size() + 1 &&
               host_lower[host_lower.size() - dom.size() - 1] == '.' &&
               host_lower.ends_with(dom);
    }
    if (low.starts_with("keyword:")) {
        const std::string_view kw = std::string_view(low).substr(8);
        return !kw.empty() && host_lower.find(kw) != std::string_view::npos;
    }
    if (has_ipv4) {
        if (auto cidr = rules::ParseIPv4Cidr(low)) {
            return (ipv4_be & cidr->mask_be) == cidr->net_be;
        }
    }
    if (!low.empty() && low.find(':') == std::string::npos && !rules::ParseIPv4Cidr(low).has_value()) {
        if (host_lower == low) return true;
        return host_lower.size() > low.size() + 1 &&
               host_lower[host_lower.size() - low.size() - 1] == '.' &&
               host_lower.ends_with(low);
    }
    return false;
}

}  // namespace

bool ParseIPv4Be(std::string_view text, uint32_t& out_be) noexcept {
    if (text.empty()) return false;
    uint8_t octets[4]{};
    size_t start = 0;
    for (int i = 0; i < 4; ++i) {
        const size_t dot = text.find('.', start);
        if (i < 3 && dot == std::string_view::npos) return false;
        if (i == 3 && dot != std::string_view::npos) return false;
        const size_t end = (i < 3) ? dot : text.size();
        if (!ParseOctet(text.substr(start, end - start), octets[i])) return false;
        start = end + 1;
    }
    out_be = (static_cast<uint32_t>(octets[0]) << 24) |
             (static_cast<uint32_t>(octets[1]) << 16) |
             (static_cast<uint32_t>(octets[2]) << 8) |
             static_cast<uint32_t>(octets[3]);
    return true;
}

bool IsLanOrSpecialIPv4(uint32_t ip) noexcept {
    const uint8_t a = static_cast<uint8_t>((ip >> 24) & 0xFFu);
    const uint8_t b = static_cast<uint8_t>((ip >> 16) & 0xFFu);
    if (a == 0) return true;                          // 0.0.0.0/8
    if (a == 10) return true;                         // 10.0.0.0/8
    if (a == 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
    if (a == 127) return true;                        // 127.0.0.0/8 loopback
    if (a == 169 && b == 254) return true;            // 169.254.0.0/16 link-local
    if (a == 172 && b >= 16 && b <= 31) return true;  // 172.16.0.0/12
    if (a == 192 && b == 168) return true;            // 192.168.0.0/16
    if (a >= 224) return true;                        // multicast & reserved
    return false;
}

bool IsLanOrSpecialHost(std::string_view host) noexcept {
    if (host.empty()) return false;
    uint32_t ip = 0;
    if (ParseIPv4Be(host, ip)) {
        return IsLanOrSpecialIPv4(ip);
    }
    std::string lower;
    lower.reserve(host.size());
    for (char c : host) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lower == "localhost" || lower == "::1") return true;
    if (lower.ends_with(".local") || lower.ends_with(".lan")) return true;
    return false;
}

bool BasicRouter::LoadRulesBin(const std::string& path) {
    auto bytes = store::ReadBinaryFile(path);
    if (!bytes) return false;
    auto parsed = rules::DeserializeRulesBin(*bytes);
    if (!parsed) return false;
    rules_ = std::move(*parsed);
    return true;
}

RouteAction BasicRouter::Decide(const Endpoint& ep, const AppSettings& settings) const {
    if (settings.block_quic && ep.is_udp && ep.port == 443) {
        return RouteAction::Block;
    }

    if (settings.bypass_lan && IsLanOrSpecialHost(ep.host)) {
        return RouteAction::Direct;
    }

    if (settings.split_tunnel_mode != SplitTunnelMode::Off && ep.program_id != 0) {
        const bool listed = std::find(settings.split_tunnel_title_ids.begin(),
                                      settings.split_tunnel_title_ids.end(),
                                      ep.program_id) != settings.split_tunnel_title_ids.end();
        if (settings.split_tunnel_mode == SplitTunnelMode::AllowList && !listed) {
            return RouteAction::Direct;
        }
        if (settings.split_tunnel_mode == SplitTunnelMode::BlockList && listed) {
            return RouteAction::Direct;
        }
    }

    if (settings.routing_mode == RoutingMode::Direct) {
        return RouteAction::Direct;
    }
    if (settings.routing_mode == RoutingMode::Global) {
        return RouteAction::Proxy;
    }

    // RoutingMode::Rules: evaluate live custom rules first, then compiled rules.bin index
    std::string host_lower;
    host_lower.reserve(ep.host.size());
    for (char c : ep.host) host_lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    while (!host_lower.empty() && host_lower.back() == '.') host_lower.pop_back();

    uint32_t ip_be = 0;
    const bool has_ip = ParseIPv4Be(host_lower, ip_be);

    for (const auto& r : settings.custom_rules.block) {
        if (MatchRuleToken(r, host_lower, ip_be, has_ip, ep.is_udp, ep.port)) return RouteAction::Block;
    }
    for (const auto& r : settings.custom_rules.direct) {
        if (MatchRuleToken(r, host_lower, ip_be, has_ip, ep.is_udp, ep.port)) return RouteAction::Direct;
    }
    for (const auto& r : settings.custom_rules.proxy) {
        if (MatchRuleToken(r, host_lower, ip_be, has_ip, ep.is_udp, ep.port)) return RouteAction::Proxy;
    }

    if (!rules_.Empty()) {
        if (auto act = rules_.Match(host_lower, ip_be, has_ip, ep.is_udp, ep.port)) {
            if (*act == CustomRules::Action::Block) return RouteAction::Block;
            if (*act == CustomRules::Action::Direct) return RouteAction::Direct;
            return RouteAction::Proxy;
        }
    }

    return RouteAction::Proxy;
}

}  // namespace yumi_nx::net
