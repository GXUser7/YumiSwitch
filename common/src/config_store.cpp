#include "yumi_nx/config_store.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

namespace yumi_nx::store {

namespace {

void WriteU8(std::vector<uint8_t>& buf, uint8_t v) { buf.push_back(v); }

void WriteU16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
}

void WriteU32(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
}

void WriteStr(std::vector<uint8_t>& buf, const std::string& s) {
    const uint16_t len = static_cast<uint16_t>(std::min<size_t>(s.size(), 4096));
    WriteU16(buf, len);
    buf.insert(buf.end(), s.begin(), s.begin() + len);
}

struct Reader {
    const uint8_t* data = nullptr;
    size_t size = 0;
    size_t pos = 0;

    bool ReadU8(uint8_t& out) {
        if (pos + 1 > size) return false;
        out = data[pos++];
        return true;
    }

    bool ReadU16(uint16_t& out) {
        if (pos + 2 > size) return false;
        out = static_cast<uint16_t>(data[pos]) | (static_cast<uint16_t>(data[pos + 1]) << 8);
        pos += 2;
        return true;
    }

    bool ReadU32(uint32_t& out) {
        if (pos + 4 > size) return false;
        out = static_cast<uint32_t>(data[pos]) |
              (static_cast<uint32_t>(data[pos + 1]) << 8) |
              (static_cast<uint32_t>(data[pos + 2]) << 16) |
              (static_cast<uint32_t>(data[pos + 3]) << 24);
        pos += 4;
        return true;
    }

    bool ReadStr(std::string& out) {
        uint16_t len = 0;
        if (!ReadU16(len)) return false;
        if (len > 4096 || pos + len > size) return false;
        out.assign(reinterpret_cast<const char*>(data + pos), len);
        pos += len;
        return true;
    }
};

uint32_t Fnv1a32(const uint8_t* data, size_t len) noexcept {
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

}  // namespace

std::vector<uint8_t> EncodeActiveNodeBinary(const ProxyNode& node) {
    std::vector<uint8_t> buf;
    buf.reserve(512);
    WriteU32(buf, kActiveNodeMagic);
    WriteU16(buf, kActiveNodeVersion);
    WriteU8(buf, static_cast<uint8_t>(node.protocol));
    WriteU8(buf, static_cast<uint8_t>(node.transport.kind));
    WriteU16(buf, node.port);

    WriteStr(buf, node.id);
    WriteStr(buf, node.name);
    WriteStr(buf, node.server);
    WriteStr(buf, node.uuid_or_user);
    WriteStr(buf, node.password_or_key);
    WriteStr(buf, node.method);
    WriteStr(buf, node.flow);
    WriteStr(buf, node.packet_encoding);

    // TLS + REALITY
    WriteU8(buf, node.tls.enabled ? 1 : 0);
    WriteU8(buf, node.tls.insecure ? 1 : 0);
    WriteStr(buf, node.tls.server_name);
    WriteStr(buf, node.tls.fingerprint);
    WriteStr(buf, node.tls.pinned_cert_sha256);
    WriteStr(buf, node.tls.verify_peer_cert_by_name);
    const uint16_t alpn_count = static_cast<uint16_t>(std::min<size_t>(node.tls.alpn.size(), 16));
    WriteU16(buf, alpn_count);
    for (uint16_t i = 0; i < alpn_count; ++i) WriteStr(buf, node.tls.alpn[i]);
    WriteU8(buf, node.tls.reality.enabled ? 1 : 0);
    WriteStr(buf, node.tls.reality.public_key);
    WriteStr(buf, node.tls.reality.short_id);
    WriteStr(buf, node.tls.reality.spider_x);

    // Transport
    WriteStr(buf, node.transport.path);
    WriteStr(buf, node.transport.host);
    WriteStr(buf, node.transport.service_name);
    WriteU8(buf, node.transport.grpc_multi_mode ? 1 : 0);
    WriteStr(buf, node.transport.grpc_authority);
    WriteStr(buf, node.transport.xhttp_mode);

    // WireGuard
    WriteStr(buf, node.wireguard.private_key);
    WriteStr(buf, node.wireguard.peer_public_key);
    WriteStr(buf, node.wireguard.pre_shared_key);
    WriteU16(buf, node.wireguard.mtu);
    WriteU8(buf, node.wireguard.has_reserved ? 1 : 0);
    WriteU8(buf, node.wireguard.reserved[0]);
    WriteU8(buf, node.wireguard.reserved[1]);
    WriteU8(buf, node.wireguard.reserved[2]);
    const uint16_t wg_addr_count =
        static_cast<uint16_t>(std::min<size_t>(node.wireguard.local_addresses.size(), 16));
    WriteU16(buf, wg_addr_count);
    for (uint16_t i = 0; i < wg_addr_count; ++i) WriteStr(buf, node.wireguard.local_addresses[i]);

    // Hysteria2
    WriteStr(buf, node.hysteria2.obfs_type);
    WriteStr(buf, node.hysteria2.obfs_password);
    WriteU32(buf, node.hysteria2.up_mbps);
    WriteU32(buf, node.hysteria2.down_mbps);

    WriteStr(buf, node.subscription_id);

    const uint32_t checksum = Fnv1a32(buf.data(), buf.size());
    WriteU32(buf, checksum);
    return buf;
}

std::optional<ProxyNode> DecodeActiveNodeBinary(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 14) return std::nullopt;
    const size_t payload_len = bytes.size() - 4;
    Reader crc_reader{bytes.data() + payload_len, 4, 0};
    uint32_t expected_crc = 0;
    if (!crc_reader.ReadU32(expected_crc)) return std::nullopt;
    if (Fnv1a32(bytes.data(), payload_len) != expected_crc) return std::nullopt;

    Reader r{bytes.data(), payload_len, 0};
    uint32_t magic = 0;
    uint16_t ver = 0;
    uint8_t proto = 0;
    uint8_t transp = 0;
    if (!r.ReadU32(magic) || magic != kActiveNodeMagic) return std::nullopt;
    if (!r.ReadU16(ver) || ver != kActiveNodeVersion) return std::nullopt;

    ProxyNode node;
    if (!r.ReadU8(proto) || proto > static_cast<uint8_t>(Protocol::Direct)) return std::nullopt;
    if (!r.ReadU8(transp) || transp > static_cast<uint8_t>(TransportKind::Xhttp)) return std::nullopt;
    node.protocol = static_cast<Protocol>(proto);
    node.transport.kind = static_cast<TransportKind>(transp);
    if (!r.ReadU16(node.port)) return std::nullopt;

    if (!r.ReadStr(node.id) || !r.ReadStr(node.name) || !r.ReadStr(node.server) ||
        !r.ReadStr(node.uuid_or_user) || !r.ReadStr(node.password_or_key) ||
        !r.ReadStr(node.method) || !r.ReadStr(node.flow) || !r.ReadStr(node.packet_encoding)) {
        return std::nullopt;
    }

    uint8_t b = 0;
    if (!r.ReadU8(b)) return std::nullopt;
    node.tls.enabled = b != 0;
    if (!r.ReadU8(b)) return std::nullopt;
    node.tls.insecure = b != 0;
    if (!r.ReadStr(node.tls.server_name) || !r.ReadStr(node.tls.fingerprint) ||
        !r.ReadStr(node.tls.pinned_cert_sha256) || !r.ReadStr(node.tls.verify_peer_cert_by_name)) {
        return std::nullopt;
    }
    uint16_t alpn_count = 0;
    if (!r.ReadU16(alpn_count) || alpn_count > 16) return std::nullopt;
    node.tls.alpn.resize(alpn_count);
    for (uint16_t i = 0; i < alpn_count; ++i) {
        if (!r.ReadStr(node.tls.alpn[i])) return std::nullopt;
    }
    if (!r.ReadU8(b)) return std::nullopt;
    node.tls.reality.enabled = b != 0;
    if (!r.ReadStr(node.tls.reality.public_key) || !r.ReadStr(node.tls.reality.short_id) ||
        !r.ReadStr(node.tls.reality.spider_x)) {
        return std::nullopt;
    }

    if (!r.ReadStr(node.transport.path) || !r.ReadStr(node.transport.host) ||
        !r.ReadStr(node.transport.service_name)) {
        return std::nullopt;
    }
    if (!r.ReadU8(b)) return std::nullopt;
    node.transport.grpc_multi_mode = b != 0;
    if (!r.ReadStr(node.transport.grpc_authority) || !r.ReadStr(node.transport.xhttp_mode)) {
        return std::nullopt;
    }

    if (!r.ReadStr(node.wireguard.private_key) || !r.ReadStr(node.wireguard.peer_public_key) ||
        !r.ReadStr(node.wireguard.pre_shared_key) || !r.ReadU16(node.wireguard.mtu)) {
        return std::nullopt;
    }
    if (!r.ReadU8(b)) return std::nullopt;
    node.wireguard.has_reserved = b != 0;
    if (!r.ReadU8(node.wireguard.reserved[0]) || !r.ReadU8(node.wireguard.reserved[1]) ||
        !r.ReadU8(node.wireguard.reserved[2])) {
        return std::nullopt;
    }
    uint16_t wg_addr_count = 0;
    if (!r.ReadU16(wg_addr_count) || wg_addr_count > 16) return std::nullopt;
    node.wireguard.local_addresses.resize(wg_addr_count);
    for (uint16_t i = 0; i < wg_addr_count; ++i) {
        if (!r.ReadStr(node.wireguard.local_addresses[i])) return std::nullopt;
    }

    if (!r.ReadStr(node.hysteria2.obfs_type) || !r.ReadStr(node.hysteria2.obfs_password) ||
        !r.ReadU32(node.hysteria2.up_mbps) || !r.ReadU32(node.hysteria2.down_mbps)) {
        return std::nullopt;
    }

    if (!r.ReadStr(node.subscription_id)) return std::nullopt;
    if (r.pos != r.size) return std::nullopt;
    return node;
}

std::string SerializeSettingsJson(const AppSettings& s) {
    nlohmann::json j;
    j["routing_mode"] = static_cast<uint8_t>(s.routing_mode);
    j["bypass_lan"] = s.bypass_lan;
    j["block_ads"] = s.block_ads;
    j["block_quic"] = s.block_quic;
    j["enable_ipv6"] = s.enable_ipv6;

    j["remote_dns"] = s.remote_dns;
    j["direct_dns"] = s.direct_dns;
    j["hijack_dns"] = s.hijack_dns;
    j["dns_fallback"] = s.dns_fallback;
    j["resolve_server_address"] = s.resolve_server_address;
    j["resolve_doh_url"] = s.resolve_doh_url;

    j["tls_fingerprint"] = static_cast<uint8_t>(s.tls_fingerprint);
    j["fragment_mode"] = static_cast<uint8_t>(s.fragment_mode);
    j["fragment_scope"] = static_cast<uint8_t>(s.fragment_scope);
    j["fragment_length"] = s.fragment_length;
    j["fragment_interval"] = s.fragment_interval;
    j["fragment_max_chunks"] = s.fragment_max_chunks;

    j["auto_connect_on_boot"] = s.auto_connect_on_boot;
    j["split_tunnel_mode"] = static_cast<uint8_t>(s.split_tunnel_mode);
    j["split_tunnel_title_ids"] = s.split_tunnel_title_ids;

    j["device_id"] = s.device_id;
    j["subscription_auto_update"] = s.subscription_auto_update;
    j["subscription_update_minutes"] = s.subscription_update_minutes;
    j["log_level"] = static_cast<uint8_t>(s.log_level);

    j["custom_rules"] = {
        {"proxy", s.custom_rules.proxy},
        {"direct", s.custom_rules.direct},
        {"block", s.custom_rules.block},
    };
    return j.dump(2);
}

std::optional<AppSettings> DeserializeSettingsJson(const std::string& json_text) {
    auto parsed = nlohmann::json::parse(json_text, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_object()) return std::nullopt;

    AppSettings s;
    auto clamp_enum = [](uint8_t v, uint8_t max_v, uint8_t def_v) -> uint8_t {
        return (v <= max_v) ? v : def_v;
    };
    if (parsed.contains("routing_mode") && parsed["routing_mode"].is_number_unsigned()) {
        s.routing_mode = static_cast<RoutingMode>(
            clamp_enum(parsed["routing_mode"].get<uint8_t>(), 2, 1));
    }
    s.bypass_lan = parsed.value("bypass_lan", s.bypass_lan);
    s.block_ads = parsed.value("block_ads", s.block_ads);
    s.block_quic = parsed.value("block_quic", s.block_quic);
    s.enable_ipv6 = parsed.value("enable_ipv6", s.enable_ipv6);

    s.remote_dns = parsed.value("remote_dns", s.remote_dns);
    s.direct_dns = parsed.value("direct_dns", s.direct_dns);
    s.hijack_dns = parsed.value("hijack_dns", s.hijack_dns);
    s.dns_fallback = parsed.value("dns_fallback", s.dns_fallback);
    s.resolve_server_address = parsed.value("resolve_server_address", s.resolve_server_address);
    s.resolve_doh_url = parsed.value("resolve_doh_url", s.resolve_doh_url);

    if (parsed.contains("tls_fingerprint") && parsed["tls_fingerprint"].is_number_unsigned()) {
        s.tls_fingerprint = static_cast<TlsFingerprint>(
            clamp_enum(parsed["tls_fingerprint"].get<uint8_t>(), 10, 0));
    }
    if (parsed.contains("fragment_mode") && parsed["fragment_mode"].is_number_unsigned()) {
        s.fragment_mode = static_cast<FragmentMode>(
            clamp_enum(parsed["fragment_mode"].get<uint8_t>(), 2, 0));
    }
    if (parsed.contains("fragment_scope") && parsed["fragment_scope"].is_number_unsigned()) {
        s.fragment_scope = static_cast<FragmentScope>(
            clamp_enum(parsed["fragment_scope"].get<uint8_t>(), 2, 1));
    }
    s.fragment_length = parsed.value("fragment_length", s.fragment_length);
    s.fragment_interval = parsed.value("fragment_interval", s.fragment_interval);
    s.fragment_max_chunks = parsed.value("fragment_max_chunks", s.fragment_max_chunks);

    s.auto_connect_on_boot = parsed.value("auto_connect_on_boot", s.auto_connect_on_boot);
    if (parsed.contains("split_tunnel_mode") && parsed["split_tunnel_mode"].is_number_unsigned()) {
        s.split_tunnel_mode = static_cast<SplitTunnelMode>(
            clamp_enum(parsed["split_tunnel_mode"].get<uint8_t>(), 2, 0));
    }
    if (parsed.contains("split_tunnel_title_ids") && parsed["split_tunnel_title_ids"].is_array()) {
        for (const auto& item : parsed["split_tunnel_title_ids"]) {
            if (item.is_number_unsigned()) s.split_tunnel_title_ids.push_back(item.get<uint64_t>());
        }
    }

    s.device_id = parsed.value("device_id", s.device_id);
    s.subscription_auto_update = parsed.value("subscription_auto_update", s.subscription_auto_update);
    s.subscription_update_minutes = parsed.value("subscription_update_minutes", s.subscription_update_minutes);
    if (parsed.contains("log_level") && parsed["log_level"].is_number_unsigned()) {
        s.log_level = static_cast<LogLevel>(
            clamp_enum(parsed["log_level"].get<uint8_t>(), 4, 2));
    }

    if (parsed.contains("custom_rules") && parsed["custom_rules"].is_object()) {
        const auto& cr = parsed["custom_rules"];
        auto read_str_list = [&](const char* key, std::vector<std::string>& dest) {
            if (!cr.contains(key) || !cr[key].is_array()) return;
            for (const auto& el : cr[key]) {
                if (el.is_string()) dest.push_back(el.get<std::string>());
            }
        };
        read_str_list("proxy", s.custom_rules.proxy);
        read_str_list("direct", s.custom_rules.direct);
        read_str_list("block", s.custom_rules.block);
    }
    return s;
}

std::string SerializeSubscriptionsJson(const std::vector<parse::SubscriptionRecord>& subs) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& s : subs) {
        nlohmann::json item;
        item["id"] = s.id;
        item["name"] = s.name;
        item["remote_title"] = s.remote_title;
        item["url"] = s.url;
        item["user_agent_override"] = s.user_agent_override;
        item["enabled"] = s.enabled;
        item["node_count"] = s.node_count;
        item["last_updated_epoch_ms"] = s.last_updated_epoch_ms;
        item["last_error"] = s.last_error;
        nlohmann::json hdrs = nlohmann::json::object();
        for (const auto& kv : s.headers) {
            hdrs[kv.first] = kv.second;
        }
        item["headers"] = hdrs;
        if (s.user_info.has_value()) {
            const auto& ui = *s.user_info;
            nlohmann::json u;
            if (ui.has_upload) u["upload"] = ui.upload_bytes;
            if (ui.has_download) u["download"] = ui.download_bytes;
            if (ui.has_total) u["total"] = ui.total_bytes;
            if (ui.has_expire) u["expire"] = ui.expires_at_epoch_sec;
            item["user_info"] = u;
        }
        arr.push_back(std::move(item));
    }
    return arr.dump(2);
}

std::optional<std::vector<parse::SubscriptionRecord>> DeserializeSubscriptionsJson(const std::string& json_text) {
    auto parsed = nlohmann::json::parse(json_text, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_array()) return std::nullopt;
    std::vector<parse::SubscriptionRecord> out;
    for (const auto& item : parsed) {
        if (!item.is_object()) continue;
        parse::SubscriptionRecord s;
        s.id = item.value("id", std::string{});
        s.name = item.value("name", std::string{});
        s.remote_title = item.value("remote_title", std::string{});
        s.url = item.value("url", std::string{});
        s.user_agent_override = item.value("user_agent_override", std::string{});
        s.enabled = item.value("enabled", true);
        s.node_count = item.value("node_count", 0);
        s.last_updated_epoch_ms = item.value("last_updated_epoch_ms", int64_t{0});
        s.last_error = item.value("last_error", std::string{});
        if (item.contains("headers") && item["headers"].is_object()) {
            for (const auto& kv : item["headers"].items()) {
                if (kv.value().is_string()) s.headers.emplace_back(kv.key(), kv.value().get<std::string>());
            }
        }
        if (item.contains("user_info") && item["user_info"].is_object()) {
            const auto& u = item["user_info"];
            parse::SubscriptionUserInfo ui;
            if (u.contains("upload") && u["upload"].is_number_unsigned()) {
                ui.has_upload = true;
                ui.upload_bytes = u["upload"].get<uint64_t>();
            }
            if (u.contains("download") && u["download"].is_number_unsigned()) {
                ui.has_download = true;
                ui.download_bytes = u["download"].get<uint64_t>();
            }
            if (u.contains("total") && u["total"].is_number_unsigned()) {
                ui.has_total = true;
                ui.total_bytes = u["total"].get<uint64_t>();
            }
            if (u.contains("expire") && u["expire"].is_number_integer()) {
                ui.has_expire = true;
                ui.expires_at_epoch_sec = u["expire"].get<int64_t>();
            }
            s.user_info = ui;
        }
        if (!s.id.empty()) out.push_back(std::move(s));
    }
    return out;
}

std::string SerializeNodesJson(const std::vector<ProxyNode>& nodes) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& n : nodes) {
        nlohmann::json j;
        j["id"] = n.id;
        j["name"] = n.name;
        j["server"] = n.server;
        j["port"] = n.port;
        j["protocol"] = static_cast<uint8_t>(n.protocol);
        j["uuid_or_user"] = n.uuid_or_user;
        j["password_or_key"] = n.password_or_key;
        j["method"] = n.method;
        j["flow"] = n.flow;
        j["packet_encoding"] = n.packet_encoding;
        j["subscription_id"] = n.subscription_id;
        j["tls"] = {
            {"enabled", n.tls.enabled},
            {"server_name", n.tls.server_name},
            {"insecure", n.tls.insecure},
            {"alpn", n.tls.alpn},
            {"fingerprint", n.tls.fingerprint},
            {"pinned_cert_sha256", n.tls.pinned_cert_sha256},
            {"verify_peer_cert_by_name", n.tls.verify_peer_cert_by_name},
            {"reality", {
                {"enabled", n.tls.reality.enabled},
                {"public_key", n.tls.reality.public_key},
                {"short_id", n.tls.reality.short_id},
                {"spider_x", n.tls.reality.spider_x},
            }},
        };
        j["transport"] = {
            {"kind", static_cast<uint8_t>(n.transport.kind)},
            {"path", n.transport.path},
            {"host", n.transport.host},
            {"service_name", n.transport.service_name},
            {"grpc_multi_mode", n.transport.grpc_multi_mode},
            {"grpc_authority", n.transport.grpc_authority},
            {"xhttp_mode", n.transport.xhttp_mode},
        };
        j["wireguard"] = {
            {"private_key", n.wireguard.private_key},
            {"peer_public_key", n.wireguard.peer_public_key},
            {"pre_shared_key", n.wireguard.pre_shared_key},
            {"local_addresses", n.wireguard.local_addresses},
            {"mtu", n.wireguard.mtu},
            {"has_reserved", n.wireguard.has_reserved},
            {"reserved", {n.wireguard.reserved[0], n.wireguard.reserved[1], n.wireguard.reserved[2]}},
        };
        j["hysteria2"] = {
            {"obfs_type", n.hysteria2.obfs_type},
            {"obfs_password", n.hysteria2.obfs_password},
            {"up_mbps", n.hysteria2.up_mbps},
            {"down_mbps", n.hysteria2.down_mbps},
        };
        arr.push_back(std::move(j));
    }
    return arr.dump(2);
}

std::optional<std::vector<ProxyNode>> DeserializeNodesJson(const std::string& json_text) {
    auto parsed = nlohmann::json::parse(json_text, nullptr, false);
    if (parsed.is_discarded() || !parsed.is_array()) return std::nullopt;
    std::vector<ProxyNode> out;
    for (const auto& j : parsed) {
        if (!j.is_object()) continue;
        ProxyNode n;
        n.id = j.value("id", std::string{});
        n.name = j.value("name", std::string{});
        n.server = j.value("server", std::string{});
        n.port = static_cast<uint16_t>(j.value("port", 443));
        const uint8_t p = j.contains("protocol") && j["protocol"].is_number_unsigned()
            ? j["protocol"].get<uint8_t>() : 0;
        if (p <= static_cast<uint8_t>(Protocol::Direct)) n.protocol = static_cast<Protocol>(p);
        n.uuid_or_user = j.value("uuid_or_user", std::string{});
        n.password_or_key = j.value("password_or_key", std::string{});
        n.method = j.value("method", std::string{});
        n.flow = j.value("flow", std::string{});
        n.packet_encoding = j.value("packet_encoding", std::string{"xudp"});
        n.subscription_id = j.value("subscription_id", std::string{});
        if (j.contains("tls") && j["tls"].is_object()) {
            const auto& t = j["tls"];
            n.tls.enabled = t.value("enabled", false);
            n.tls.server_name = t.value("server_name", std::string{});
            n.tls.insecure = t.value("insecure", false);
            n.tls.fingerprint = t.value("fingerprint", std::string{});
            n.tls.pinned_cert_sha256 = t.value("pinned_cert_sha256", std::string{});
            n.tls.verify_peer_cert_by_name = t.value("verify_peer_cert_by_name", std::string{});
            if (t.contains("alpn") && t["alpn"].is_array()) {
                for (const auto& a : t["alpn"]) if (a.is_string()) n.tls.alpn.push_back(a.get<std::string>());
            }
            if (t.contains("reality") && t["reality"].is_object()) {
                const auto& r = t["reality"];
                n.tls.reality.enabled = r.value("enabled", false);
                n.tls.reality.public_key = r.value("public_key", std::string{});
                n.tls.reality.short_id = r.value("short_id", std::string{});
                n.tls.reality.spider_x = r.value("spider_x", std::string{"/"});
            }
        }
        if (j.contains("transport") && j["transport"].is_object()) {
            const auto& tr = j["transport"];
            const uint8_t tk = tr.contains("kind") && tr["kind"].is_number_unsigned()
                ? tr["kind"].get<uint8_t>() : 0;
            if (tk <= static_cast<uint8_t>(TransportKind::Xhttp)) n.transport.kind = static_cast<TransportKind>(tk);
            n.transport.path = tr.value("path", std::string{"/"});
            n.transport.host = tr.value("host", std::string{});
            n.transport.service_name = tr.value("service_name", std::string{});
            n.transport.grpc_multi_mode = tr.value("grpc_multi_mode", false);
            n.transport.grpc_authority = tr.value("grpc_authority", std::string{});
            n.transport.xhttp_mode = tr.value("xhttp_mode", std::string{"auto"});
        }
        if (j.contains("wireguard") && j["wireguard"].is_object()) {
            const auto& w = j["wireguard"];
            n.wireguard.private_key = w.value("private_key", std::string{});
            n.wireguard.peer_public_key = w.value("peer_public_key", std::string{});
            n.wireguard.pre_shared_key = w.value("pre_shared_key", std::string{});
            n.wireguard.mtu = static_cast<uint16_t>(w.value("mtu", 1408));
            n.wireguard.has_reserved = w.value("has_reserved", false);
            if (w.contains("local_addresses") && w["local_addresses"].is_array()) {
                for (const auto& a : w["local_addresses"]) {
                    if (a.is_string()) n.wireguard.local_addresses.push_back(a.get<std::string>());
                }
            }
            if (w.contains("reserved") && w["reserved"].is_array() && w["reserved"].size() >= 3) {
                for (size_t i = 0; i < 3; ++i) {
                    if (w["reserved"][i].is_number_unsigned()) {
                        n.wireguard.reserved[i] = w["reserved"][i].get<uint8_t>();
                    }
                }
            }
        }
        if (j.contains("hysteria2") && j["hysteria2"].is_object()) {
            const auto& h = j["hysteria2"];
            n.hysteria2.obfs_type = h.value("obfs_type", std::string{});
            n.hysteria2.obfs_password = h.value("obfs_password", std::string{});
            n.hysteria2.up_mbps = h.value("up_mbps", uint32_t{0});
            n.hysteria2.down_mbps = h.value("down_mbps", uint32_t{0});
        }
        if (!n.server.empty() && n.port > 0) out.push_back(std::move(n));
    }
    return out;
}

bool WriteFileAtomic(const std::string& path, const std::string& data) {
    std::vector<uint8_t> bytes(data.begin(), data.end());
    return WriteFileAtomic(path, bytes);
}

bool WriteFileAtomic(const std::string& path, const std::vector<uint8_t>& data) {
    std::error_code ec;
    const std::filesystem::path target(path);
    if (target.has_parent_path()) {
        std::filesystem::create_directories(target.parent_path(), ec);
        if (ec) return false;
    }
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        if (!data.empty()) {
            out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        }
        out.flush();
        if (!out.good()) return false;
    }
    std::filesystem::rename(tmp, target, ec);
    if (ec) {
        std::filesystem::remove(target, ec);
        ec.clear();
        std::filesystem::rename(tmp, target, ec);
    }
    return !ec;
}

std::optional<std::string> ReadTextFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return std::nullopt;
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return content;
}

std::optional<std::vector<uint8_t>> ReadBinaryFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return std::nullopt;
    std::vector<uint8_t> content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return content;
}

}  // namespace yumi_nx::store
