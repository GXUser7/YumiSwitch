#include "yumi_nx/subscription_parser.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <nlohmann/json.hpp>

namespace yumi_nx::parse {

namespace {

std::string_view TrimSv(std::string_view s) noexcept {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
    return s;
}

std::string ToLowerAscii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

bool EqualsIgnoreCase(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

bool StartsWithIgnoreCase(std::string_view s, std::string_view prefix) noexcept {
    if (s.size() < prefix.size()) return false;
    return EqualsIgnoreCase(s.substr(0, prefix.size()), prefix);
}

std::string UrlDecode(std::string_view in) {
    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            const int hi = hex_val(in[i + 1]);
            const int lo = hex_val(in[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(in[i]);
    }
    return out;
}

std::optional<std::string> Base64DecodeString(std::string_view in) {
    auto b64_val = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+' || c == '-') return 62;
        if (c == '/' || c == '_') return 63;
        return -1;
    };
    std::string out;
    out.reserve((in.size() * 3) / 4 + 4);
    uint32_t acc = 0;
    int bits = 0;
    bool pad_seen = false;
    for (unsigned char uc : in) {
        if (uc == ' ' || uc == '\t' || uc == '\r' || uc == '\n') continue;
        if (uc == '=') {
            pad_seen = true;
            continue;
        }
        if (pad_seen) return std::nullopt;
        const int v = b64_val(uc);
        if (v < 0) return std::nullopt;
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((acc >> bits) & 0xFFu));
        }
    }
    if (bits >= 6) return std::nullopt;
    if (bits > 0 && ((acc & ((1u << bits) - 1u)) != 0u)) return std::nullopt;
    return out;
}

std::optional<int> ParseIntBounded(std::string_view s, int min_v, int max_v) noexcept {
    s = TrimSv(s);
    if (s.empty() || s.size() > 12) return std::nullopt;
    bool neg = false;
    if (s.front() == '-') {
        neg = true;
        s.remove_prefix(1);
    } else if (s.front() == '+') {
        s.remove_prefix(1);
    }
    if (s.empty()) return std::nullopt;
    int64_t val = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
        val = val * 10 + (c - '0');
        if (val > 2'000'000'000LL) return std::nullopt;
    }
    if (neg) val = -val;
    if (val < min_v || val > max_v) return std::nullopt;
    return static_cast<int>(val);
}

std::optional<uint64_t> ParseU64(std::string_view s) noexcept {
    s = TrimSv(s);
    if (s.empty()) return std::nullopt;
    uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return std::nullopt;
        if (v > (UINT64_MAX - 9) / 10) return std::nullopt;
        v = v * 10 + static_cast<uint64_t>(c - '0');
    }
    return v;
}

std::vector<std::string> SplitCsv(std::string_view raw) {
    std::vector<std::string> out;
    size_t pos = 0;
    while (pos <= raw.size()) {
        const size_t comma = raw.find(',', pos);
        const std::string_view part = TrimSv((comma == std::string_view::npos) ? raw.substr(pos) : raw.substr(pos, comma - pos));
        if (!part.empty()) out.emplace_back(part);
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return out;
}

bool ParseBoolStr(std::string_view s) noexcept {
    s = TrimSv(s);
    return s == "1" || EqualsIgnoreCase(s, "true") || EqualsIgnoreCase(s, "yes");
}

bool SplitHostAndPort(std::string_view hp, std::string& out_host, uint16_t& out_port) {
    hp = TrimSv(hp);
    if (hp.empty()) return false;
    if (hp.front() == '[') {
        const size_t close = hp.find(']');
        if (close == std::string_view::npos || close <= 1) return false;
        if (close + 1 >= hp.size() || hp[close + 1] != ':') return false;
        const auto port_opt = ParseIntBounded(hp.substr(close + 2), 1, 65535);
        if (!port_opt) return false;
        out_host.assign(hp.substr(1, close - 1));
        out_port = static_cast<uint16_t>(*port_opt);
        return !out_host.empty();
    }
    const size_t colon = hp.rfind(':');
    if (colon == std::string_view::npos || colon == 0) return false;
    const auto port_opt = ParseIntBounded(hp.substr(colon + 1), 1, 65535);
    if (!port_opt) return false;
    out_host.assign(hp.substr(0, colon));
    out_port = static_cast<uint16_t>(*port_opt);
    return !out_host.empty();
}

struct ParsedUri {
    std::string scheme;
    std::string user_info;
    std::string host;
    uint16_t port = 0;
    std::string path;
    std::vector<std::pair<std::string, std::string>> query;
    std::string fragment;

    [[nodiscard]] std::optional<std::string> Q(std::initializer_list<std::string_view> keys) const {
        for (const auto k : keys) {
            for (const auto& kv : query) {
                if (EqualsIgnoreCase(kv.first, k) && !kv.second.empty()) {
                    return kv.second;
                }
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] std::optional<int> QInt(std::initializer_list<std::string_view> keys) const {
        if (auto v = Q(keys)) {
            return ParseIntBounded(*v, 0, 1000000);
        }
        return std::nullopt;
    }

    [[nodiscard]] bool QBool(std::initializer_list<std::string_view> keys) const {
        if (auto v = Q(keys)) {
            return ParseBoolStr(*v);
        }
        return false;
    }
};

std::optional<ParsedUri> SplitUri(std::string_view raw) {
    raw = TrimSv(raw);
    const size_t scheme_pos = raw.find("://");
    if (scheme_pos == std::string_view::npos || scheme_pos == 0) return std::nullopt;

    ParsedUri out;
    out.scheme = ToLowerAscii(raw.substr(0, scheme_pos));
    std::string_view rest = raw.substr(scheme_pos + 3);

    const size_t hash_pos = rest.find('#');
    if (hash_pos != std::string_view::npos) {
        out.fragment = UrlDecode(rest.substr(hash_pos + 1));
        rest = rest.substr(0, hash_pos);
    }

    const size_t q_pos = rest.find('?');
    if (q_pos != std::string_view::npos) {
        std::string_view qraw = rest.substr(q_pos + 1);
        rest = rest.substr(0, q_pos);
        size_t p = 0;
        while (p <= qraw.size()) {
            const size_t amp = qraw.find('&', p);
            const std::string_view part = (amp == std::string_view::npos) ? qraw.substr(p) : qraw.substr(p, amp - p);
            const size_t eq = part.find('=');
            if (eq != std::string_view::npos && eq > 0) {
                out.query.emplace_back(ToLowerAscii(part.substr(0, eq)), UrlDecode(part.substr(eq + 1)));
            }
            if (amp == std::string_view::npos) break;
            p = amp + 1;
        }
    }

    const size_t slash_pos = rest.find('/');
    if (slash_pos != std::string_view::npos) {
        out.path = std::string(rest.substr(slash_pos));
        rest = rest.substr(0, slash_pos);
    }

    const size_t at_pos = rest.rfind('@');
    if (at_pos != std::string_view::npos) {
        out.user_info = std::string(rest.substr(0, at_pos));
        rest = rest.substr(at_pos + 1);
    }

    if (!SplitHostAndPort(rest, out.host, out.port)) {
        // Fallback default ports for http/https without explicit port
        if ((out.scheme == "http" || out.scheme == "https") && !rest.empty() && rest.find(':') == std::string_view::npos) {
            out.host = std::string(rest);
            out.port = (out.scheme == "https") ? 443 : 80;
        } else {
            return std::nullopt;
        }
    }
    return out;
}

std::string NormalizeRealityKey(std::string_view raw) {
    std::string trimmed(TrimSv(raw));
    // Strip trailing '=' if already URL-safe base64, or normalize standard base64 if needed
    return trimmed;
}

std::string NormalizeSpiderX(std::string_view raw) {
    std::string trimmed(TrimSv(raw));
    if (trimmed.empty()) return "/";
    if (trimmed.front() == '/') return trimmed;
    return "/" + trimmed;
}

bool IsSupportedOrPlainNetwork(std::string_view net_raw, bool& out_supported) noexcept {
    const std::string net = ToLowerAscii(TrimSv(net_raw));
    if (net.empty() || net == "tcp" || net == "raw" || net == "none" || net == "original" || net == "hysteria") {
        out_supported = true;
        return false;  // plain / implicit
    }
    if (net == "ws" || net == "websocket" || net == "grpc" || net == "httpupgrade" ||
        net == "xhttp" || net == "splithttp") {
        out_supported = true;
        return true;
    }
    out_supported = false;
    return false;
}

bool ApplyUriTransportAndTls(const ParsedUri& p, ProxyNode& node, bool tls_default_on) {
    if (auto decl = p.Q({"type", "net"})) {
        bool ok = true;
        IsSupportedOrPlainNetwork(*decl, ok);
        if (!ok) return false;
    }

    const std::string host_hdr = p.Q({"host"}).value_or("");
    const std::string path = p.Q({"path"}).value_or("/");
    const std::string net = ToLowerAscii(p.Q({"type", "net"}).value_or("raw"));

    if (net == "ws" || net == "websocket") {
        node.transport.kind = TransportKind::WebSocket;
        node.transport.path = path.empty() ? "/" : path;
        node.transport.host = host_hdr;
    } else if (net == "grpc") {
        node.transport.kind = TransportKind::Grpc;
        node.transport.service_name = p.Q({"servicename", "service_name", "service-name", "path"}).value_or("");
        node.transport.grpc_multi_mode = EqualsIgnoreCase(p.Q({"mode"}).value_or(""), "multi");
        node.transport.grpc_authority = p.Q({"authority"}).value_or("");
    } else if (net == "httpupgrade") {
        node.transport.kind = TransportKind::HttpUpgrade;
        node.transport.path = path.empty() ? "/" : path;
        node.transport.host = host_hdr;
    } else if (net == "xhttp" || net == "splithttp") {
        node.transport.kind = TransportKind::Xhttp;
        node.transport.path = path.empty() ? "/" : path;
        node.transport.host = host_hdr;
        node.transport.xhttp_mode = p.Q({"mode"}).value_or("auto");
    } else {
        node.transport.kind = TransportKind::Raw;
    }

    const std::string sec = ToLowerAscii(p.Q({"security"}).value_or(""));
    const auto reality_key = p.Q({"pbk", "public-key", "publickey", "public_key", "pubkey", "key"});
    bool tls_on = tls_default_on;
    if (sec == "reality" || reality_key.has_value() || sec == "tls" || sec == "xtls") {
        tls_on = true;
    } else if (sec == "none") {
        tls_on = false;
    }

    if (tls_on) {
        node.tls.enabled = true;
        std::string sni_fallback = !node.transport.host.empty() ? node.transport.host : node.server;
        node.tls.server_name = p.Q({"sni", "peer", "servername", "server_name"}).value_or(sni_fallback);
        node.tls.insecure = p.QBool({"insecure", "allowinsecure", "allow_insecure", "skip-cert-verify", "skip_cert_verify"});
        if (auto alpn = p.Q({"alpn"})) {
            node.tls.alpn = SplitCsv(*alpn);
        }
        node.tls.fingerprint = p.Q({"fp", "fingerprint", "client-fingerprint", "client_fingerprint"}).value_or("");
        node.tls.pinned_cert_sha256 = p.Q({"pcs", "pinnedpeercertsha256", "pinned_peer_cert_sha256"}).value_or("");
        node.tls.verify_peer_cert_by_name = p.Q({"vcn", "verifypeercertbyname", "verify_peer_cert_by_name"}).value_or("");
        if (reality_key.has_value()) {
            node.tls.reality.enabled = true;
            node.tls.reality.public_key = NormalizeRealityKey(*reality_key);
            node.tls.reality.short_id = p.Q({"sid", "short-id", "shortid", "short_id"}).value_or("");
            node.tls.reality.spider_x = NormalizeSpiderX(p.Q({"spx", "spider-x", "spiderx", "spider_x"}).value_or("/"));
        }
    }
    return true;
}

bool LooksLikeCredentials(std::string_view decoded) noexcept {
    if (decoded.find(':') == std::string_view::npos) return false;
    for (unsigned char ch : decoded) {
        if ((ch < 0x20 && ch != '\t') || ch == 0x7f) return false;
    }
    return true;
}

std::pair<std::string, std::string> SplitCredPair(std::string_view user_info) {
    std::string chosen;
    if (auto dec = Base64DecodeString(user_info); dec && LooksLikeCredentials(*dec)) {
        chosen = *dec;
    } else {
        chosen = UrlDecode(user_info);
    }
    const size_t colon = chosen.find(':');
    if (colon == std::string::npos) return {chosen, ""};
    return {chosen.substr(0, colon), chosen.substr(colon + 1)};
}

std::string JsonStr(const nlohmann::json& obj, std::initializer_list<const char*> keys) {
    if (!obj.is_object()) return "";
    for (const char* k : keys) {
        if (!obj.contains(k)) continue;
        const auto& v = obj[k];
        if (v.is_string()) {
            const auto s = v.get<std::string>();
            if (!s.empty() && s != "null") return s;
        } else if (v.is_number_integer()) {
            return std::to_string(v.get<int64_t>());
        } else if (v.is_number_unsigned()) {
            return std::to_string(v.get<uint64_t>());
        }
    }
    return "";
}

bool JsonBool(const nlohmann::json& obj, std::initializer_list<const char*> keys) {
    if (!obj.is_object()) return false;
    for (const char* k : keys) {
        if (!obj.contains(k)) continue;
        const auto& v = obj[k];
        if (v.is_boolean()) return v.get<bool>();
        if (v.is_number_integer()) return v.get<int64_t>() != 0;
        if (v.is_string()) return ParseBoolStr(v.get<std::string>());
    }
    return false;
}

int JsonPort(const nlohmann::json& obj, const char* key) {
    if (!obj.is_object() || !obj.contains(key)) return 0;
    const auto& v = obj[key];
    if (v.is_number_integer()) {
        const int64_t p = v.get<int64_t>();
        return (p >= 1 && p <= 65535) ? static_cast<int>(p) : 0;
    }
    if (v.is_string()) {
        return ParseIntBounded(v.get<std::string>(), 1, 65535).value_or(0);
    }
    return 0;
}

// ---------------- URI Scheme Parsers ----------------

std::optional<ProxyNode> ParseVmessUri(std::string_view uri, std::string_view sub_id) {
    const std::string_view without = uri.substr(8);
    const size_t hash_pos = without.find('#');
    const std::string_view b64_part = (hash_pos == std::string_view::npos) ? without : without.substr(0, hash_pos);

    if (auto dec = Base64DecodeString(b64_part)) {
        auto j = nlohmann::json::parse(*dec, nullptr, false);
        if (j.is_object()) {
            const std::string host = JsonStr(j, {"add"});
            const int port = JsonPort(j, "port");
            const std::string uuid = JsonStr(j, {"id"});
            if (host.empty() || port == 0 || uuid.empty()) return std::nullopt;

            const std::string net = ToLowerAscii(JsonStr(j, {"net"}));
            bool net_ok = true;
            IsSupportedOrPlainNetwork(net, net_ok);
            if (!net_ok) return std::nullopt;

            ProxyNode node;
            node.protocol = Protocol::Vmess;
            node.server = host;
            node.port = static_cast<uint16_t>(port);
            node.uuid_or_user = uuid;
            node.method = JsonStr(j, {"scy"});
            if (node.method.empty()) node.method = "auto";
            node.name = JsonStr(j, {"ps"});
            if (node.name.empty()) node.name = host + ":" + std::to_string(port);
            node.subscription_id = std::string(sub_id);

            const std::string hdr_host = JsonStr(j, {"host"});
            const std::string path = JsonStr(j, {"path"});
            if (net == "ws" || net == "websocket") {
                node.transport.kind = TransportKind::WebSocket;
                node.transport.host = hdr_host;
                node.transport.path = path.empty() ? "/" : path;
            } else if (net == "grpc") {
                node.transport.kind = TransportKind::Grpc;
                node.transport.service_name = path;
                node.transport.grpc_multi_mode = EqualsIgnoreCase(JsonStr(j, {"type"}), "multi");
                node.transport.grpc_authority = JsonStr(j, {"authority"});
            } else if (net == "httpupgrade") {
                node.transport.kind = TransportKind::HttpUpgrade;
                node.transport.host = hdr_host;
                node.transport.path = path.empty() ? "/" : path;
            } else if (net == "xhttp" || net == "splithttp") {
                node.transport.kind = TransportKind::Xhttp;
                node.transport.host = hdr_host;
                node.transport.path = path.empty() ? "/" : path;
                node.transport.xhttp_mode = JsonStr(j, {"mode"});
                if (node.transport.xhttp_mode.empty()) node.transport.xhttp_mode = "auto";
            }

            const std::string tls_mode = ToLowerAscii(JsonStr(j, {"tls"}));
            if (tls_mode == "tls" || tls_mode == "reality") {
                node.tls.enabled = true;
                node.tls.server_name = JsonStr(j, {"sni"});
                if (node.tls.server_name.empty()) node.tls.server_name = !hdr_host.empty() ? hdr_host : host;
                node.tls.alpn = SplitCsv(JsonStr(j, {"alpn"}));
                node.tls.fingerprint = JsonStr(j, {"fp"});
                node.tls.insecure = JsonBool(j, {"allowinsecure", "allow_insecure", "insecure", "skip-cert-verify"});
            }
            node.id = ComputeNodeId(node);
            return node;
        }
    }

    auto p = SplitUri(uri);
    if (!p || p->user_info.empty()) return std::nullopt;
    ProxyNode node;
    node.protocol = Protocol::Vmess;
    node.server = p->host;
    node.port = p->port;
    const std::string dec_u = UrlDecode(p->user_info);
    node.uuid_or_user = dec_u.substr(0, dec_u.find(':'));
    if (node.uuid_or_user.empty()) return std::nullopt;
    node.method = p->Q({"security", "scy", "encryption"}).value_or("auto");
    node.name = !p->fragment.empty() ? p->fragment : (p->host + ":" + std::to_string(p->port));
    node.subscription_id = std::string(sub_id);
    if (!ApplyUriTransportAndTls(*p, node, false)) return std::nullopt;
    node.id = ComputeNodeId(node);
    return node;
}

std::optional<ProxyNode> ParseVlessUri(std::string_view uri, std::string_view sub_id) {
    auto p = SplitUri(uri);
    if (!p) return std::nullopt;
    const std::string uuid = UrlDecode(p->user_info);
    if (uuid.empty()) return std::nullopt;

    ProxyNode node;
    node.protocol = Protocol::Vless;
    node.server = p->host;
    node.port = p->port;
    node.uuid_or_user = uuid;
    node.flow = p->Q({"flow"}).value_or("");
    node.packet_encoding = p->Q({"packetencoding", "packet-encoding", "packet_encoding"}).value_or("xudp");
    node.name = !p->fragment.empty() ? p->fragment : (p->host + ":" + std::to_string(p->port));
    node.subscription_id = std::string(sub_id);
    if (!ApplyUriTransportAndTls(*p, node, false)) return std::nullopt;
    node.id = ComputeNodeId(node);
    return node;
}

std::optional<ProxyNode> ParseTrojanUri(std::string_view uri, std::string_view sub_id) {
    auto p = SplitUri(uri);
    if (!p) return std::nullopt;
    const std::string pwd = UrlDecode(p->user_info);
    if (pwd.empty()) return std::nullopt;

    ProxyNode node;
    node.protocol = Protocol::Trojan;
    node.server = p->host;
    node.port = p->port;
    node.password_or_key = pwd;
    node.name = !p->fragment.empty() ? p->fragment : (p->host + ":" + std::to_string(p->port));
    node.subscription_id = std::string(sub_id);
    if (!ApplyUriTransportAndTls(*p, node, true)) return std::nullopt;
    node.id = ComputeNodeId(node);
    return node;
}

std::optional<ProxyNode> ParseShadowsocksUri(std::string_view uri, std::string_view sub_id) {
    std::string_view without = uri.substr(5);
    const size_t hash_pos = without.find('#');
    const std::string name = (hash_pos == std::string_view::npos) ? "" : UrlDecode(without.substr(hash_pos + 1));
    const std::string_view body = (hash_pos == std::string_view::npos) ? without : without.substr(0, hash_pos);

    if (body.find('@') == std::string_view::npos) {
        const size_t q_pos = body.find('?');
        auto decoded = Base64DecodeString(body.substr(0, q_pos));
        if (!decoded) return std::nullopt;
        const size_t at = decoded->rfind('@');
        if (at == std::string::npos) return std::nullopt;
        const std::string creds = decoded->substr(0, at);
        const size_t colon = creds.find(':');
        if (colon == std::string::npos) return std::nullopt;
        std::string host;
        uint16_t port = 0;
        if (!SplitHostAndPort(std::string_view(*decoded).substr(at + 1), host, port)) return std::nullopt;
        ProxyNode node;
        node.protocol = Protocol::Shadowsocks;
        node.server = host;
        node.port = port;
        node.method = creds.substr(0, colon);
        node.password_or_key = creds.substr(colon + 1);
        node.name = !name.empty() ? name : (host + ":" + std::to_string(port));
        node.subscription_id = std::string(sub_id);
        node.id = ComputeNodeId(node);
        return node;
    }

    auto p = SplitUri(uri);
    if (!p || p->user_info.empty()) return std::nullopt;
    auto [method, pwd] = SplitCredPair(p->user_info);
    if (method.empty() || pwd.empty()) return std::nullopt;

    ProxyNode node;
    node.protocol = Protocol::Shadowsocks;
    node.server = p->host;
    node.port = p->port;
    node.method = method;
    node.password_or_key = pwd;
    node.name = !p->fragment.empty() ? p->fragment : (p->host + ":" + std::to_string(p->port));
    node.subscription_id = std::string(sub_id);
    node.id = ComputeNodeId(node);
    return node;
}

std::optional<ProxyNode> ParseHysteria2Uri(std::string_view uri, std::string_view sub_id) {
    auto p = SplitUri(uri);
    if (!p) return std::nullopt;
    const std::string pwd = UrlDecode(p->user_info);
    if (pwd.empty()) return std::nullopt;

    ProxyNode node;
    node.protocol = Protocol::Hysteria2;
    node.server = p->host;
    node.port = p->port;
    node.password_or_key = pwd;
    node.hysteria2.obfs_type = p->Q({"obfs", "obfs-type", "obfs_type"}).value_or("");
    node.hysteria2.obfs_password = p->Q({"obfs-password", "obfspassword", "obfs_password"}).value_or("");
    node.hysteria2.up_mbps = static_cast<uint32_t>(p->QInt({"upmbps", "up", "up_mbps", "up-mbps"}).value_or(0));
    node.hysteria2.down_mbps = static_cast<uint32_t>(p->QInt({"downmbps", "down", "down_mbps", "down-mbps"}).value_or(0));
    node.name = !p->fragment.empty() ? p->fragment : (p->host + ":" + std::to_string(p->port));
    node.subscription_id = std::string(sub_id);
    if (!ApplyUriTransportAndTls(*p, node, true)) return std::nullopt;
    node.id = ComputeNodeId(node);
    return node;
}

std::optional<ProxyNode> ParseWireGuardUri(std::string_view uri, std::string_view sub_id) {
    auto p = SplitUri(uri);
    if (!p) return std::nullopt;
    const auto peer_pub = p->Q({"publickey", "public-key"});
    if (!peer_pub) return std::nullopt;

    ProxyNode node;
    node.protocol = Protocol::WireGuard;
    node.server = p->host;
    node.port = p->port;
    node.wireguard.private_key = !p->user_info.empty() ? UrlDecode(p->user_info) : p->Q({"privatekey"}).value_or("");
    node.wireguard.peer_public_key = *peer_pub;
    node.wireguard.pre_shared_key = p->Q({"presharedkey", "pre-shared-key"}).value_or("");
    if (auto addrs = p->Q({"address", "ip"})) {
        node.wireguard.local_addresses = SplitCsv(*addrs);
    }
    node.wireguard.mtu = static_cast<uint16_t>(p->QInt({"mtu"}).value_or(1408));
    if (auto res_str = p->Q({"reserved"})) {
        const auto parts = SplitCsv(*res_str);
        if (parts.size() >= 3) {
            node.wireguard.has_reserved = true;
            for (size_t i = 0; i < 3; ++i) {
                node.wireguard.reserved[i] = static_cast<uint8_t>(ParseIntBounded(parts[i], 0, 255).value_or(0));
            }
        }
    }
    node.name = !p->fragment.empty() ? p->fragment : (p->host + ":" + std::to_string(p->port));
    node.subscription_id = std::string(sub_id);
    node.id = ComputeNodeId(node);
    return node;
}

std::optional<ProxyNode> ParseSocksOrHttpUri(std::string_view uri, std::string_view sub_id, bool is_http) {
    auto p = SplitUri(uri);
    if (!p) return std::nullopt;
    ProxyNode node;
    node.protocol = is_http ? Protocol::Http : Protocol::Socks5;
    node.server = p->host;
    node.port = p->port;
    if (!p->user_info.empty()) {
        auto [u, pw] = SplitCredPair(p->user_info);
        node.uuid_or_user = u;
        node.password_or_key = pw;
    }
    node.name = !p->fragment.empty() ? p->fragment : (p->host + ":" + std::to_string(p->port));
    node.subscription_id = std::string(sub_id);
    if (!ApplyUriTransportAndTls(*p, node, p->scheme == "https")) return std::nullopt;
    node.id = ComputeNodeId(node);
    return node;
}

// ---------------- Structured JSON (Xray / SIP008) ----------------

std::optional<ProxyNode> ParseXrayOutboundJson(const nlohmann::json& out, std::string_view label, std::string_view sub_id) {
    if (!out.is_object()) return std::nullopt;
    const std::string proto_s = ToLowerAscii(JsonStr(out, {"protocol"}));
    if (proto_s.empty() || proto_s == "direct" || proto_s == "freedom" || proto_s == "blackhole" ||
        proto_s == "dns" || proto_s == "block") {
        return std::nullopt;
    }
    if (!out.contains("settings") || !out["settings"].is_object()) return std::nullopt;
    const auto& settings = out["settings"];

    const nlohmann::json* ep = &settings;
    if (settings.contains("vnext") && settings["vnext"].is_array() && !settings["vnext"].empty() && settings["vnext"][0].is_object()) {
        ep = &settings["vnext"][0];
    } else if (settings.contains("servers") && settings["servers"].is_array() && !settings["servers"].empty() && settings["servers"][0].is_object()) {
        ep = &settings["servers"][0];
    }

    const std::string server = JsonStr(*ep, {"address"});
    const int port = JsonPort(*ep, "port");
    if (server.empty() || port == 0) return std::nullopt;

    const nlohmann::json* user = nullptr;
    if (ep->contains("users") && (*ep)["users"].is_array() && !(*ep)["users"].empty() && (*ep)["users"][0].is_object()) {
        user = &(*ep)["users"][0];
    }

    const nlohmann::json* stream = nullptr;
    if (out.contains("streamSettings") && out["streamSettings"].is_object()) stream = &out["streamSettings"];
    else if (out.contains("stream_settings") && out["stream_settings"].is_object()) stream = &out["stream_settings"];

    ProxyNode node;
    node.server = server;
    node.port = static_cast<uint16_t>(port);
    node.subscription_id = std::string(sub_id);
    const std::string tag = JsonStr(out, {"tag"});
    node.name = !label.empty() ? std::string(label) : (!tag.empty() ? tag : (server + ":" + std::to_string(port)));

    if (proto_s == "vless") {
        if (!user) return std::nullopt;
        node.protocol = Protocol::Vless;
        node.uuid_or_user = JsonStr(*user, {"id", "uuid"});
        if (node.uuid_or_user.empty()) return std::nullopt;
        node.flow = JsonStr(*user, {"flow"});
        node.packet_encoding = JsonStr(*user, {"packetEncoding", "packet_encoding", "packetencoding"});
        if (node.packet_encoding.empty()) node.packet_encoding = "xudp";
    } else if (proto_s == "vmess") {
        if (!user) return std::nullopt;
        node.protocol = Protocol::Vmess;
        node.uuid_or_user = JsonStr(*user, {"id", "uuid"});
        if (node.uuid_or_user.empty()) return std::nullopt;
        node.method = JsonStr(*user, {"security", "scy", "encryption"});
        if (node.method.empty()) node.method = "auto";
    } else if (proto_s == "trojan") {
        node.protocol = Protocol::Trojan;
        node.password_or_key = JsonStr(*ep, {"password"});
        if (node.password_or_key.empty()) return std::nullopt;
    } else if (proto_s == "shadowsocks") {
        node.protocol = Protocol::Shadowsocks;
        node.method = JsonStr(*ep, {"method", "cipher"});
        node.password_or_key = JsonStr(*ep, {"password"});
        if (node.method.empty() || node.password_or_key.empty()) return std::nullopt;
    } else if (proto_s == "hysteria" || proto_s == "hysteria2") {
        node.protocol = Protocol::Hysteria2;
        if (stream && stream->contains("hysteriaSettings") && (*stream)["hysteriaSettings"].is_object()) {
            node.password_or_key = JsonStr((*stream)["hysteriaSettings"], {"auth", "password"});
        }
        if (node.password_or_key.empty()) node.password_or_key = JsonStr(settings, {"auth", "password"});
        if (node.password_or_key.empty()) return std::nullopt;
        node.tls.enabled = true;
    } else {
        return std::nullopt;
    }

    if (stream) {
        const std::string net = ToLowerAscii(JsonStr(*stream, {"network", "net"}));
        bool net_ok = true;
        IsSupportedOrPlainNetwork(net, net_ok);
        if (!net_ok) return std::nullopt;

        if (net == "ws" && stream->contains("wsSettings") && (*stream)["wsSettings"].is_object()) {
            const auto& ws = (*stream)["wsSettings"];
            node.transport.kind = TransportKind::WebSocket;
            node.transport.path = JsonStr(ws, {"path"});
            if (node.transport.path.empty()) node.transport.path = "/";
            node.transport.host = JsonStr(ws, {"host"});
            if (node.transport.host.empty() && ws.contains("headers") && ws["headers"].is_object()) {
                node.transport.host = JsonStr(ws["headers"], {"Host", "host"});
            }
        } else if (net == "grpc" && stream->contains("grpcSettings") && (*stream)["grpcSettings"].is_object()) {
            const auto& g = (*stream)["grpcSettings"];
            node.transport.kind = TransportKind::Grpc;
            node.transport.service_name = JsonStr(g, {"serviceName", "service_name", "service-name"});
            node.transport.grpc_multi_mode = JsonBool(g, {"multiMode", "multi_mode"}) ||
                                             EqualsIgnoreCase(JsonStr(g, {"mode"}), "multi");
            node.transport.grpc_authority = JsonStr(g, {"authority"});
        } else if (net == "httpupgrade" && stream->contains("httpupgradeSettings") && (*stream)["httpupgradeSettings"].is_object()) {
            const auto& hu = (*stream)["httpupgradeSettings"];
            node.transport.kind = TransportKind::HttpUpgrade;
            node.transport.host = JsonStr(hu, {"host"});
            node.transport.path = JsonStr(hu, {"path"});
            if (node.transport.path.empty()) node.transport.path = "/";
        } else if (net == "xhttp" || net == "splithttp") {
            node.transport.kind = TransportKind::Xhttp;
            const nlohmann::json* xh = nullptr;
            if (stream->contains("xhttpSettings") && (*stream)["xhttpSettings"].is_object()) xh = &(*stream)["xhttpSettings"];
            else if (stream->contains("splithttpSettings") && (*stream)["splithttpSettings"].is_object()) xh = &(*stream)["splithttpSettings"];
            if (xh) {
                node.transport.host = JsonStr(*xh, {"host"});
                node.transport.path = JsonStr(*xh, {"path"});
                node.transport.xhttp_mode = JsonStr(*xh, {"mode"});
            }
            if (node.transport.path.empty()) node.transport.path = "/";
            if (node.transport.xhttp_mode.empty()) node.transport.xhttp_mode = "auto";
        }

        const std::string sec = ToLowerAscii(JsonStr(*stream, {"security"}));
        if (!sec.empty() && sec != "none") {
            node.tls.enabled = true;
            const nlohmann::json* tls_s = (stream->contains("tlsSettings") && (*stream)["tlsSettings"].is_object())
                ? &(*stream)["tlsSettings"] : nullptr;
            const nlohmann::json* real_s = (stream->contains("realitySettings") && (*stream)["realitySettings"].is_object())
                ? &(*stream)["realitySettings"] : nullptr;
            const nlohmann::json* active = real_s ? real_s : tls_s;
            if (active) {
                node.tls.server_name = JsonStr(*active, {"serverName", "server_name", "server-name", "servername", "sni"});
                node.tls.fingerprint = JsonStr(*active, {"fingerprint", "client_fingerprint", "client-fingerprint", "fp"});
            }
            if (tls_s) {
                node.tls.insecure = JsonBool(*tls_s, {"allowInsecure", "allow_insecure", "allowinsecure", "insecure"});
                node.tls.pinned_cert_sha256 = JsonStr(*tls_s, {"pinnedPeerCertSha256", "pinned_peer_cert_sha256", "pcs"});
                node.tls.verify_peer_cert_by_name = JsonStr(*tls_s, {"verifyPeerCertByName", "verify_peer_cert_by_name", "vcn"});
                if (tls_s->contains("alpn") && (*tls_s)["alpn"].is_array()) {
                    for (const auto& a : (*tls_s)["alpn"]) {
                        if (a.is_string()) node.tls.alpn.push_back(a.get<std::string>());
                    }
                }
            }
            if (real_s) {
                const std::string pk = JsonStr(*real_s, {"publicKey", "public_key", "public-key", "pbk", "pubkey", "key"});
                if (!pk.empty()) {
                    node.tls.reality.enabled = true;
                    node.tls.reality.public_key = pk;
                    node.tls.reality.short_id = JsonStr(*real_s, {"shortId", "short_id", "short-id", "sid"});
                    node.tls.reality.spider_x = NormalizeSpiderX(JsonStr(*real_s, {"spiderX", "spider_x", "spider-x", "spx", "path"}));
                }
            }
        }
    }

    node.id = ComputeNodeId(node);
    return node;
}

std::vector<ProxyNode> ParseJsonDocument(std::string_view text, std::string_view sub_id) {
    auto root = nlohmann::json::parse(text, nullptr, false);
    if (root.is_discarded()) return {};

    std::vector<ProxyNode> nodes;
    auto parse_doc = [&](const nlohmann::json& doc) {
        if (!doc.is_object()) return;
        if (doc.contains("servers") && doc["servers"].is_array()) {
            for (const auto& e : doc["servers"]) {
                if (!e.is_object() || !e.contains("method")) continue;
                const std::string srv = JsonStr(e, {"server"});
                const int port = JsonPort(e, "server_port");
                const std::string meth = JsonStr(e, {"method"});
                const std::string pwd = JsonStr(e, {"password"});
                if (srv.empty() || port == 0 || meth.empty() || pwd.empty()) continue;
                ProxyNode n;
                n.protocol = Protocol::Shadowsocks;
                n.server = srv;
                n.port = static_cast<uint16_t>(port);
                n.method = meth;
                n.password_or_key = pwd;
                n.name = JsonStr(e, {"remarks"});
                if (n.name.empty()) n.name = srv + ":" + std::to_string(port);
                n.subscription_id = std::string(sub_id);
                n.id = ComputeNodeId(n);
                nodes.push_back(std::move(n));
            }
            return;
        }
        if (doc.contains("outbounds") && doc["outbounds"].is_array()) {
            const std::string remarks = JsonStr(doc, {"remarks"});
            for (const auto& ob : doc["outbounds"]) {
                if (auto n = ParseXrayOutboundJson(ob, remarks, sub_id)) {
                    nodes.push_back(std::move(*n));
                }
            }
        }
    };

    if (root.is_array()) {
        for (const auto& el : root) {
            if (!el.is_object()) continue;
            if (el.contains("outbounds") || el.contains("servers")) {
                parse_doc(el);
            } else if (auto n = ParseXrayOutboundJson(el, "", sub_id)) {
                nodes.push_back(std::move(*n));
            }
        }
    } else if (root.is_object()) {
        parse_doc(root);
    }
    return nodes;
}

// ---------------- Clash YAML Parser ----------------

std::string StripYamlCommentAndQuotes(std::string_view raw) {
    char quote = 0;
    size_t cut = raw.size();
    for (size_t i = 0; i < raw.size(); ++i) {
        const char ch = raw[i];
        if (quote != 0) {
            if (ch == quote) quote = 0;
        } else if (ch == '"' || ch == '\'') {
            quote = ch;
        } else if (ch == '#' && (i == 0 || std::isspace(static_cast<unsigned char>(raw[i - 1])))) {
            cut = i;
            break;
        }
    }
    std::string_view trimmed = TrimSv(raw.substr(0, cut));
    if (trimmed.size() >= 2 &&
        ((trimmed.front() == '"' && trimmed.back() == '"') ||
         (trimmed.front() == '\'' && trimmed.back() == '\''))) {
        trimmed = trimmed.substr(1, trimmed.size() - 2);
    }
    return std::string(TrimSv(trimmed));
}

using YamlMap = std::vector<std::pair<std::string, std::string>>;

void SetMapField(YamlMap& m, std::string key, std::string val) {
    for (auto& kv : m) {
        if (kv.first == key) {
            kv.second = std::move(val);
            return;
        }
    }
    m.emplace_back(std::move(key), std::move(val));
}

std::optional<std::pair<std::string, std::string>> SplitYamlPair(std::string_view s) {
    const size_t colon = s.find(':');
    if (colon == std::string_view::npos || colon == 0) return std::nullopt;
    std::string key(TrimSv(s.substr(0, colon)));
    if (key.size() >= 2 && ((key.front() == '"' && key.back() == '"') || (key.front() == '\'' && key.back() == '\''))) {
        key = key.substr(1, key.size() - 2);
    }
    if (key.empty()) return std::nullopt;
    std::string val = StripYamlCommentAndQuotes(s.substr(colon + 1));
    return std::make_pair(std::move(key), std::move(val));
}

void ParseInlineMap(std::string_view text, YamlMap& dst) {
    text = TrimSv(text);
    if (text.size() >= 2 && text.front() == '{' && text.back() == '}') {
        text = text.substr(1, text.size() - 2);
    }
    int depth = 0;
    size_t start = 0;
    auto flush = [&](size_t end) {
        std::string_view part = TrimSv(text.substr(start, end - start));
        if (part.empty()) return;
        const size_t open_brace = part.find('{');
        if (open_brace != std::string_view::npos) {
            ParseInlineMap(part.substr(open_brace), dst);
            if (auto kv = SplitYamlPair(part.substr(0, open_brace)); kv && !kv->second.empty()) {
                SetMapField(dst, kv->first, kv->second);
            }
        } else if (auto kv = SplitYamlPair(part)) {
            SetMapField(dst, kv->first, kv->second);
        }
    };
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '{') ++depth;
        else if (text[i] == '}') --depth;
        else if (text[i] == ',' && depth == 0) {
            flush(i);
            start = i + 1;
        }
    }
    flush(text.size());
}

std::string MapGetAny(const YamlMap& m, std::initializer_list<std::string_view> keys) {
    for (const auto k : keys) {
        for (const auto& kv : m) {
            if (kv.first == k && !kv.second.empty()) return kv.second;
        }
    }
    return "";
}

bool MapGetBoolAny(const YamlMap& m, std::initializer_list<std::string_view> keys) {
    const std::string s = MapGetAny(m, keys);
    return !s.empty() && ParseBoolStr(s);
}

std::vector<ProxyNode> ParseClashYaml(std::string_view doc, std::string_view sub_id) {
    std::vector<std::string_view> lines;
    size_t pos = 0;
    while (pos <= doc.size()) {
        const size_t nl = doc.find('\n', pos);
        std::string_view line = (nl == std::string_view::npos) ? doc.substr(pos) : doc.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        lines.push_back(line);
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }

    size_t start_line = lines.size();
    int section_indent = 0;
    for (size_t i = 0; i < lines.size(); ++i) {
        std::string_view tr = TrimSv(lines[i]);
        if (tr == "proxies:" || tr.starts_with("proxies:")) {
            start_line = i;
            section_indent = 0;
            for (char c : lines[i]) {
                if (c == ' ' || c == '\t') ++section_indent;
                else break;
            }
            break;
        }
    }
    if (start_line >= lines.size()) return {};

    std::vector<YamlMap> blocks;
    YamlMap current;
    bool in_entry = false;

    for (size_t i = start_line + 1; i < lines.size(); ++i) {
        const std::string_view raw = lines[i];
        const std::string_view trimmed = TrimSv(raw);
        if (trimmed.empty() || trimmed.front() == '#') continue;

        int indent = 0;
        for (char c : raw) {
            if (c == ' ' || c == '\t') ++indent;
            else break;
        }
        if (indent <= section_indent && trimmed.front() != '-') break;

        if (trimmed.starts_with("- ")) {
            if (in_entry && !current.empty()) blocks.push_back(std::move(current));
            current.clear();
            in_entry = true;
            std::string_view head = TrimSv(trimmed.substr(2));
            if (!head.empty() && head.front() == '{') {
                ParseInlineMap(head, current);
            } else if (auto kv = SplitYamlPair(head)) {
                SetMapField(current, kv->first, kv->second);
            }
        } else if (in_entry) {
            if (trimmed.back() == ':') continue;
            if (auto kv = SplitYamlPair(trimmed)) {
                if (!kv->second.empty() && kv->second.front() == '{') {
                    ParseInlineMap(kv->second, current);
                } else {
                    SetMapField(current, kv->first, kv->second);
                }
            }
        }
    }
    if (in_entry && !current.empty()) blocks.push_back(std::move(current));

    std::vector<ProxyNode> nodes;
    for (const auto& f : blocks) {
        const std::string server = MapGetAny(f, {"server"});
        const int port = ParseIntBounded(MapGetAny(f, {"port"}), 1, 65535).value_or(0);
        if (server.empty() || port == 0) continue;

        const std::string net = ToLowerAscii(MapGetAny(f, {"network"}));
        bool net_ok = true;
        IsSupportedOrPlainNetwork(net, net_ok);
        if (!net_ok) continue;

        const std::string type = ToLowerAscii(MapGetAny(f, {"type"}));
        ProxyNode node;
        node.server = server;
        node.port = static_cast<uint16_t>(port);
        node.name = MapGetAny(f, {"name"});
        if (node.name.empty()) node.name = server + ":" + std::to_string(port);
        node.subscription_id = std::string(sub_id);

        if (type == "vless") {
            node.protocol = Protocol::Vless;
            node.uuid_or_user = MapGetAny(f, {"uuid"});
            if (node.uuid_or_user.empty()) continue;
            node.flow = MapGetAny(f, {"flow"});
            node.packet_encoding = MapGetAny(f, {"packet-encoding", "packet_encoding", "packetencoding"});
            if (node.packet_encoding.empty()) node.packet_encoding = "xudp";
        } else if (type == "vmess") {
            node.protocol = Protocol::Vmess;
            node.uuid_or_user = MapGetAny(f, {"uuid"});
            if (node.uuid_or_user.empty()) continue;
            node.method = MapGetAny(f, {"cipher", "security", "scy"});
            if (node.method.empty()) node.method = "auto";
        } else if (type == "trojan") {
            node.protocol = Protocol::Trojan;
            node.password_or_key = MapGetAny(f, {"password"});
            if (node.password_or_key.empty()) continue;
        } else if (type == "ss") {
            node.protocol = Protocol::Shadowsocks;
            node.method = MapGetAny(f, {"cipher"});
            node.password_or_key = MapGetAny(f, {"password"});
            if (node.method.empty() || node.password_or_key.empty()) continue;
        } else if (type == "hysteria2" || type == "hy2") {
            node.protocol = Protocol::Hysteria2;
            node.password_or_key = MapGetAny(f, {"password", "auth"});
            if (node.password_or_key.empty()) continue;
            node.hysteria2.obfs_type = MapGetAny(f, {"obfs", "obfs-type", "obfs_type"});
            node.hysteria2.obfs_password = MapGetAny(f, {"obfs-password", "obfspassword", "obfs_password"});
            node.hysteria2.up_mbps = static_cast<uint32_t>(ParseIntBounded(MapGetAny(f, {"up", "up-mbps", "up_mbps"}), 0, 100000).value_or(0));
            node.hysteria2.down_mbps = static_cast<uint32_t>(ParseIntBounded(MapGetAny(f, {"down", "down-mbps", "down_mbps"}), 0, 100000).value_or(0));
        } else if (type == "socks5") {
            node.protocol = Protocol::Socks5;
            node.uuid_or_user = MapGetAny(f, {"username"});
            node.password_or_key = MapGetAny(f, {"password"});
        } else if (type == "http") {
            node.protocol = Protocol::Http;
            node.uuid_or_user = MapGetAny(f, {"username"});
            node.password_or_key = MapGetAny(f, {"password"});
        } else {
            continue;
        }

        const std::string net_any = ToLowerAscii(MapGetAny(f, {"network", "type"}));
        if (net_any == "ws") {
            node.transport.kind = TransportKind::WebSocket;
            node.transport.path = MapGetAny(f, {"path"});
            if (node.transport.path.empty()) node.transport.path = "/";
            node.transport.host = MapGetAny(f, {"Host", "host"});
        } else if (net_any == "grpc") {
            node.transport.kind = TransportKind::Grpc;
            node.transport.service_name = MapGetAny(f, {"grpc-service-name", "grpc_service_name", "serviceName", "service_name", "path"});
            node.transport.grpc_multi_mode = MapGetBoolAny(f, {"multi-mode", "multiMode"}) ||
                                             EqualsIgnoreCase(MapGetAny(f, {"mode"}), "multi");
            node.transport.grpc_authority = MapGetAny(f, {"authority", "grpc-authority"});
        } else if (net_any == "httpupgrade") {
            node.transport.kind = TransportKind::HttpUpgrade;
            node.transport.host = MapGetAny(f, {"host"});
            node.transport.path = MapGetAny(f, {"path"});
            if (node.transport.path.empty()) node.transport.path = "/";
        } else if (net_any == "xhttp" || net_any == "splithttp") {
            node.transport.kind = TransportKind::Xhttp;
            node.transport.host = MapGetAny(f, {"host"});
            node.transport.path = MapGetAny(f, {"path"});
            if (node.transport.path.empty()) node.transport.path = "/";
            node.transport.xhttp_mode = MapGetAny(f, {"mode"});
            if (node.transport.xhttp_mode.empty()) node.transport.xhttp_mode = "auto";
        }

        const std::string reality_key = MapGetAny(f, {"public-key", "public_key", "publicKey", "pbk", "pubkey", "key"});
        const bool implied_tls = (node.protocol == Protocol::Trojan || node.protocol == Protocol::Hysteria2);
        if (MapGetBoolAny(f, {"tls"}) || !reality_key.empty() || implied_tls) {
            node.tls.enabled = true;
            node.tls.server_name = MapGetAny(f, {"servername", "server-name", "server_name", "serverName", "sni", "peer"});
            node.tls.insecure = MapGetBoolAny(f, {"skip-cert-verify", "skip_cert_verify", "insecure", "allow-insecure"});
            node.tls.fingerprint = MapGetAny(f, {"client-fingerprint", "client_fingerprint", "clientFingerprint", "fingerprint", "fp"});
            node.tls.pinned_cert_sha256 = MapGetAny(f, {"pinned-peer-cert-sha256", "pinnedPeerCertSha256", "pcs"});
            node.tls.verify_peer_cert_by_name = MapGetAny(f, {"verify-peer-cert-by-name", "verifyPeerCertByName", "vcn"});
            std::string alpn_raw = MapGetAny(f, {"alpn"});
            if (!alpn_raw.empty()) {
                if (alpn_raw.front() == '[' && alpn_raw.back() == ']') {
                    alpn_raw = alpn_raw.substr(1, alpn_raw.size() - 2);
                }
                node.tls.alpn = SplitCsv(alpn_raw);
            }
            if (!reality_key.empty()) {
                node.tls.reality.enabled = true;
                node.tls.reality.public_key = reality_key;
                node.tls.reality.short_id = MapGetAny(f, {"short-id", "short_id", "shortId", "sid"});
                node.tls.reality.spider_x = NormalizeSpiderX(MapGetAny(f, {"spider-x", "spider_x", "spiderX", "spx", "path"}));
            }
        }

        node.id = ComputeNodeId(node);
        nodes.push_back(std::move(node));
    }
    return nodes;
}

std::string DetectStructuredFormat(std::string_view text) {
    if (text.empty()) return "";
    if (text.front() == '[') return "Xray JSON";
    if (text.front() == '{') {
        if (text.find("\"outbounds\"") != std::string_view::npos) return "Xray/sing-box JSON";
        if (text.find("\"server_port\"") != std::string_view::npos) return "SIP008";
        return "JSON";
    }
    if (text.starts_with("proxies:") || text.find("\nproxies:") != std::string_view::npos ||
        text.find("proxy-groups:") != std::string_view::npos) {
        return "Clash YAML";
    }
    return "";
}

bool LooksLikeLinkList(std::string_view text) {
    size_t pos = 0;
    while (pos <= text.size()) {
        const size_t nl = text.find('\n', pos);
        const std::string_view line = TrimSv((nl == std::string_view::npos) ? text.substr(pos) : text.substr(pos, nl - pos));
        const size_t sp = line.find("://");
        if (sp != std::string_view::npos && sp > 0 && sp < 14) return true;
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    return false;
}

void ScanMetadataLines(std::string_view text, std::vector<std::pair<std::string, std::string>>& out) {
    static constexpr const char* kKeys[] = {
        "billing-manifest-url", "payment-url", "sub-expire-button-link",
        "profile-web-page-url", "support-url", "profile-title", "subscription-userinfo",
    };
    size_t pos = 0;
    int non_blank = 0;
    while (pos <= text.size()) {
        const size_t nl = text.find('\n', pos);
        const std::string_view line = TrimSv((nl == std::string_view::npos) ? text.substr(pos) : text.substr(pos, nl - pos));
        if (!line.empty()) {
            if (++non_blank > 10) break;
            std::string_view unc;
            if (line.starts_with("//")) unc = TrimSv(line.substr(2));
            else if (line.front() == '#') unc = TrimSv(line.substr(1));
            if (!unc.empty()) {
                const size_t colon = unc.find(':');
                if (colon != std::string_view::npos && colon > 0) {
                    const std::string key = ToLowerAscii(TrimSv(unc.substr(0, colon)));
                    const std::string_view val = TrimSv(unc.substr(colon + 1));
                    bool allowed = false;
                    for (const char* k : kKeys) {
                        if (key == k) { allowed = true; break; }
                    }
                    if (allowed && !val.empty()) {
                        bool exists = false;
                        for (const auto& kv : out) {
                            if (kv.first == key) { exists = true; break; }
                        }
                        if (!exists) out.emplace_back(key, std::string(val));
                    }
                }
            }
        }
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
}

}  // namespace

std::string ComputeNodeId(const ProxyNode& node) {
    uint64_t h = 14695981039346656037ULL;
    auto feed = [&](std::string_view s) {
        for (unsigned char c : s) {
            h ^= c;
            h *= 1099511628211ULL;
        }
        h ^= 0xFFu;
        h *= 1099511628211ULL;
    };
    feed(ToString(node.protocol));
    feed(node.server);
    feed(std::to_string(node.port));
    feed(node.uuid_or_user);
    feed(node.password_or_key);
    feed(node.wireguard.peer_public_key);
    feed(ToString(node.transport.kind));
    feed(node.transport.path);
    feed(node.tls.server_name);
    feed(node.subscription_id);

    char hex[17];
    std::snprintf(hex, sizeof(hex), "%016llx", static_cast<unsigned long long>(h));
    return std::string(hex);
}

bool IsPlaceholderNode(const ProxyNode& node) noexcept {
    return node.server.empty() || node.server == "0.0.0.0" || node.port <= 1;
}

std::optional<ProxyNode> ParseProxyUri(std::string_view uri, std::string_view subscription_id) {
    const std::string_view tr = TrimSv(uri);
    if (tr.empty() || tr.front() == '#') return std::nullopt;
    const size_t sp = tr.find("://");
    if (sp == std::string_view::npos || sp == 0) return std::nullopt;
    const std::string scheme = ToLowerAscii(tr.substr(0, sp));

    if (scheme == "vless") return ParseVlessUri(tr, subscription_id);
    if (scheme == "vmess") return ParseVmessUri(tr, subscription_id);
    if (scheme == "trojan") return ParseTrojanUri(tr, subscription_id);
    if (scheme == "ss") return ParseShadowsocksUri(tr, subscription_id);
    if (scheme == "hysteria2" || scheme == "hy2") return ParseHysteria2Uri(tr, subscription_id);
    if (scheme == "wireguard" || scheme == "wg") return ParseWireGuardUri(tr, subscription_id);
    if (scheme == "socks" || scheme == "socks5" || scheme == "socks4") return ParseSocksOrHttpUri(tr, subscription_id, false);
    if (scheme == "http" || scheme == "https") return ParseSocksOrHttpUri(tr, subscription_id, true);
    return std::nullopt;
}

std::vector<ProxyNode> ParseProxyUris(std::string_view text, std::string_view subscription_id) {
    std::vector<ProxyNode> nodes;
    size_t pos = 0;
    while (pos <= text.size()) {
        const size_t nl = text.find('\n', pos);
        const std::string_view line = TrimSv((nl == std::string_view::npos) ? text.substr(pos) : text.substr(pos, nl - pos));
        if (!line.empty()) {
            if (auto n = ParseProxyUri(line, subscription_id)) {
                nodes.push_back(std::move(*n));
            }
        }
        if (nl == std::string_view::npos) break;
        pos = nl + 1;
    }
    return nodes;
}

SubscriptionParseResult ParseSubscriptionBody(std::string_view body, std::string_view subscription_id) {
    SubscriptionParseResult res;
    const std::string_view tr = TrimSv(body);
    if (tr.empty()) {
        res.status = SubscriptionParseResult::Status::Empty;
        return res;
    }

    auto try_structured = [&](std::string_view doc_text) -> bool {
        const std::string fmt = DetectStructuredFormat(doc_text);
        if (fmt.empty()) return false;
        res.format_label = fmt;
        res.nodes = (fmt == "Clash YAML")
            ? ParseClashYaml(doc_text, subscription_id)
            : ParseJsonDocument(doc_text, subscription_id);
        res.status = res.nodes.empty()
            ? SubscriptionParseResult::Status::UnsupportedFormat
            : SubscriptionParseResult::Status::Ok;
        return true;
    };

    if (try_structured(tr)) return res;

    auto finalize_nodes = [&](std::vector<ProxyNode>&& parsed) {
        if (parsed.empty()) {
            res.status = SubscriptionParseResult::Status::NoSupportedServers;
            return;
        }
        bool all_ph = true;
        for (const auto& n : parsed) {
            if (!IsPlaceholderNode(n)) {
                all_ph = false;
                break;
            }
        }
        if (all_ph) {
            res.placeholder_notice = parsed.front().name;
        }
        res.nodes = std::move(parsed);
        res.status = SubscriptionParseResult::Status::Ok;
    };

    if (LooksLikeLinkList(tr)) {
        finalize_nodes(ParseProxyUris(tr, subscription_id));
        return res;
    }

    auto decoded = Base64DecodeString(tr);
    if (!decoded) {
        res.status = SubscriptionParseResult::Status::NotBase64;
        return res;
    }

    const std::string_view dec_tr = TrimSv(*decoded);
    if (try_structured(dec_tr)) return res;
    finalize_nodes(ParseProxyUris(dec_tr, subscription_id));
    return res;
}

std::optional<SubscriptionUserInfo> ParseSubscriptionUserInfo(std::string_view header) {
    header = TrimSv(header);
    if (header.empty()) return std::nullopt;
    SubscriptionUserInfo info;
    bool any = false;
    size_t pos = 0;
    while (pos <= header.size()) {
        const size_t semi = header.find(';', pos);
        const std::string_view part = TrimSv((semi == std::string_view::npos) ? header.substr(pos) : header.substr(pos, semi - pos));
        const size_t eq = part.find('=');
        if (eq != std::string_view::npos && eq > 0) {
            const std::string k = ToLowerAscii(TrimSv(part.substr(0, eq)));
            const std::string_view v = TrimSv(part.substr(eq + 1));
            if (k == "upload") {
                if (auto u = ParseU64(v)) { info.has_upload = true; info.upload_bytes = *u; any = true; }
            } else if (k == "download") {
                if (auto d = ParseU64(v)) { info.has_download = true; info.download_bytes = *d; any = true; }
            } else if (k == "total") {
                if (auto t = ParseU64(v)) { info.has_total = true; info.total_bytes = *t; any = true; }
            } else if (k == "expire") {
                char tmp[64]{};
                const size_t n = std::min(v.size(), sizeof(tmp) - 1);
                std::memcpy(tmp, v.data(), n);
                char* endp = nullptr;
                const double dv = std::strtod(tmp, &endp);
                if (endp != tmp) {
                    int64_t sec = static_cast<int64_t>(dv);
                    if (sec > 253402300799LL) sec /= 1000LL;
                    info.has_expire = true;
                    info.expires_at_epoch_sec = sec;
                    any = true;
                }
            }
        }
        if (semi == std::string_view::npos) break;
        pos = semi + 1;
    }
    if (!any) return std::nullopt;
    return info;
}

std::vector<std::pair<std::string, std::string>> ParseMetadataComments(std::string_view body) {
    std::vector<std::pair<std::string, std::string>> out;
    const std::string_view tr = TrimSv(body);
    if (tr.empty()) return out;
    ScanMetadataLines(tr, out);
    if (!out.empty() || LooksLikeLinkList(tr) || !DetectStructuredFormat(tr).empty()) {
        return out;
    }
    if (auto dec = Base64DecodeString(tr)) {
        ScanMetadataLines(*dec, out);
    }
    return out;
}

std::string DecodeProfileTitle(std::string_view raw) {
    const std::string_view tr = TrimSv(raw);
    if (StartsWithIgnoreCase(tr, "base64:")) {
        if (auto dec = Base64DecodeString(tr.substr(7))) return *dec;
    }
    return std::string(tr);
}

}  // namespace yumi_nx::parse
