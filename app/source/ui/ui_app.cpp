#include "ui_app.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>

#include "nanovg.h"
#include "http_client.hpp"
#include "yumi_nx/config_store.hpp"
#include "yumi_nx/crypto.hpp"
#include "yumi_nx/paths.hpp"
#include "yumi_nx/rules_bin.hpp"

namespace yumi_nx::ui {

namespace {

constexpr float kCanvasW = 1280.0f;
constexpr float kCanvasH = 720.0f;

constexpr float kRailX = 20.0f;
constexpr float kRailY = 20.0f;
constexpr float kRailW = 92.0f;
constexpr float kRailH = 680.0f;

constexpr float kWorkX = 130.0f;
constexpr float kWorkY = 20.0f;
constexpr float kWorkW = 1130.0f;
constexpr float kWorkH = 680.0f;

inline NVGcolor Nvg(ColorRgba c) noexcept {
    return nvgRGBA(c.r, c.g, c.b, c.a);
}

std::string FormatDuration(uint64_t sec) {
    char buf[32];
    const unsigned m = static_cast<unsigned>(sec / 60u);
    const unsigned s = static_cast<unsigned>(sec % 60u);
    std::snprintf(buf, sizeof(buf), "%02u:%02u", m, s);
    return buf;
}

std::string FormatRateMib(uint64_t bps) {
    char buf[32];
    if (bps == 0) return "0.0 B/s";
    const double mib = static_cast<double>(bps) / (1024.0 * 1024.0);
    if (mib >= 0.1) {
        std::snprintf(buf, sizeof(buf), "%.1f MiB/s", mib);
    } else {
        std::snprintf(buf, sizeof(buf), "%.0f KiB/s", static_cast<double>(bps) / 1024.0);
    }
    return buf;
}

void DrawCbgRadii(int idx, int count, bool active, float outer_r,
                  float& tl, float& tr, float& br, float& bl) noexcept {
    if (active || count <= 1) {
        const float pill = outer_r + 16.0f;
        tl = tr = br = bl = pill;
        return;
    }
    tl = (idx == 0) ? outer_r : 8.0f;
    bl = (idx == 0) ? outer_r : 8.0f;
    tr = (idx == count - 1) ? outer_r : 8.0f;
    br = (idx == count - 1) ? outer_r : 8.0f;
}

void DrawStackRadii(int idx, int count, float outer_r,
                    float& tl, float& tr, float& br, float& bl) noexcept {
    if (count <= 1) {
        tl = tr = br = bl = outer_r;
        return;
    }
    tl = (idx == 0) ? outer_r : 8.0f;
    tr = (idx == 0) ? outer_r : 8.0f;
    bl = (idx == count - 1) ? outer_r : 8.0f;
    br = (idx == count - 1) ? outer_r : 8.0f;
}

void DrawTextClipped(NVGcontext* vg, float x, float y, float max_w, int font,
                     float size, ColorRgba col, int align, const char* text) {
    if (!text || max_w <= 2.0f) return;
    nvgSave(vg);
    const float clip_x = (align & NVG_ALIGN_RIGHT) ? (x - max_w)
                       : (align & NVG_ALIGN_CENTER) ? (x - max_w * 0.5f) : x;
    nvgIntersectScissor(vg, clip_x, y - size * 1.4f, max_w, size * 2.8f);
    nvgFontFaceId(vg, font >= 0 ? font : 0);
    nvgFontSize(vg, size);
    nvgFillColor(vg, Nvg(col));
    nvgTextAlign(vg, align);
    nvgText(vg, x, y, text, nullptr);
    nvgRestore(vg);
}

void DrawKeycap(NVGcontext* vg, float cx, float cy, const char* label,
                ColorRgba bg, ColorRgba fg, int mono_font) {
    constexpr float kW = 24.0f;
    constexpr float kH = 22.0f;
    DrawRoundedBox(vg, cx - kW * 0.5f, cy - kH * 0.5f, kW, kH, 11.0f, bg);
    nvgFontFaceId(vg, mono_font >= 0 ? mono_font : 0);
    nvgFontSize(vg, 11.5f);
    nvgFillColor(vg, Nvg(fg));
    nvgTextAlign(vg, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE);
    nvgText(vg, cx, cy + 0.5f, label, nullptr);
}

const char* ModeLabel(RoutingMode m) noexcept {
    switch (m) {
        case RoutingMode::Global: return "Global";
        case RoutingMode::Rules:  return "Rules";
        case RoutingMode::Direct: return "Direct";
    }
    return "Rules";
}

const char* UtlsLabel(TlsFingerprint fp) noexcept {
    switch (fp) {
        case TlsFingerprint::Auto:       return "Auto";
        case TlsFingerprint::Chrome:     return "Chrome";
        case TlsFingerprint::Firefox:    return "Firefox";
        case TlsFingerprint::Safari:     return "Safari";
        case TlsFingerprint::Edge:       return "Edge";
        case TlsFingerprint::Random:     return "Random";
        default:                         return "Chrome";
    }
}

const char* FragLabel(FragmentMode fm) noexcept {
    switch (fm) {
        case FragmentMode::Off:         return "Off";
        case FragmentMode::TlsHello:    return "TlsHello";
        case FragmentMode::TcpSegments: return "TcpSegments";
    }
    return "Off";
}

bool PointIn(float x, float y, float rx, float ry, float rw, float rh) noexcept {
    return x >= rx && x <= rx + rw && y >= ry && y <= ry + rh;
}

std::string ProtocolLabelOf(Protocol p) {
    switch (p) {
        case Protocol::Vless:       return "VLESS";
        case Protocol::Vmess:       return "VMess";
        case Protocol::Trojan:      return "Trojan";
        case Protocol::Shadowsocks: return "SS";
        case Protocol::Hysteria2:   return "Hysteria2";
        case Protocol::WireGuard:   return "WireGuard";
        case Protocol::Socks5:      return "SOCKS5";
        case Protocol::Http:        return "HTTP";
        case Protocol::Direct:      return "Direct";
    }
    return "VLESS";
}

std::string TransportLabelOf(const ProxyNode& n) {
    if (n.protocol == Protocol::WireGuard) return "UDP";
    if (n.protocol == Protocol::Hysteria2) {
        return n.hysteria2.obfs_type.empty() ? "QUIC" : "Salamander";
    }
    if (n.tls.reality.enabled) return "REALITY";
    switch (n.transport.kind) {
        case TransportKind::Raw:         return n.tls.enabled ? "TLS" : "TCP";
        case TransportKind::WebSocket:   return "WS";
        case TransportKind::HttpUpgrade: return "HTTPUpgrade";
        case TransportKind::Grpc:        return "gRPC";
        case TransportKind::Xhttp:       return "XHTTP";
    }
    return "TCP";
}

void GuessGeoFromName(std::string_view text, std::string& out_cc, float& out_lat, float& out_lon) {
    auto contains = [&](std::string_view needle) {
        return text.find(needle) != std::string_view::npos;
    };
    if (contains("FI") || contains("Фин") || contains("Helsinki") || contains("fi")) {
        out_cc = "FI"; out_lat = 60.17f; out_lon = 24.94f;
    } else if (contains("NL") || contains("Нидер") || contains("Amst") || contains("nl")) {
        out_cc = "NL"; out_lat = 52.37f; out_lon = 4.90f;
    } else if (contains("DE") || contains("Герм") || contains("Frank") || contains("de")) {
        out_cc = "DE"; out_lat = 50.11f; out_lon = 8.68f;
    } else if (contains("SE") || contains("Швец") || contains("Stock") || contains("se")) {
        out_cc = "SE"; out_lat = 59.33f; out_lon = 18.07f;
    } else if (contains("JP") || contains("Япон") || contains("Tokyo") || contains("jp")) {
        out_cc = "JP"; out_lat = 35.68f; out_lon = 139.65f;
    } else if (contains("PL") || contains("Поль") || contains("War")) {
        out_cc = "PL"; out_lat = 52.23f; out_lon = 21.01f;
    } else if (contains("CH") || contains("Швей") || contains("Zurich")) {
        out_cc = "CH"; out_lat = 47.37f; out_lon = 8.54f;
    } else if (contains("EE") || contains("Эст") || contains("Tallinn")) {
        out_cc = "EE"; out_lat = 59.44f; out_lon = 24.75f;
    } else if (contains("US") || contains("США") || contains("America")) {
        out_cc = "US"; out_lat = 40.71f; out_lon = -74.01f;
    } else if (contains("GB") || contains("UK") || contains("London")) {
        out_cc = "GB"; out_lat = 51.51f; out_lon = -0.13f;
    } else {
        out_cc = "NX"; out_lat = 55.75f; out_lon = 37.62f;
    }
}

UiServerEntry MakeUiServerEntry(const ProxyNode& node, const std::string& sub_name, int ping_ms) {
    UiServerEntry e;
    e.node = node;
    if (e.node.id.empty()) e.node.id = parse::ComputeNodeId(node);
    e.id = e.node.id;
    e.name = node.name.empty() ? (node.server + ":" + std::to_string(node.port)) : node.name;
    GuessGeoFromName(e.name + " " + node.server, e.cc, e.lat_deg, e.lon_deg);
    e.short_name = e.cc;
    e.proto_label = ProtocolLabelOf(node.protocol);
    e.transport_label = TransportLabelOf(node);
    e.flow_label = node.flow.empty() ? (node.tls.enabled ? "TLS 1.3" : "Direct") :
                   (node.flow.find("vision") != std::string::npos ? "Vision" : node.flow);
    e.sni = node.tls.server_name.empty() ? "—" : node.tls.server_name;
    e.utls = node.tls.fingerprint.empty() ? "auto" : node.tls.fingerprint;
    e.endpoint = node.server + ":" + std::to_string(node.port);
    e.sub_id = node.subscription_id;
    e.sub_name = sub_name.empty() ? std::string("Подписка") : sub_name;
    e.ping_ms = ping_ms;
    return e;
}

std::string FormatSubExpiry(const parse::SubscriptionRecord& rec) {
    if (!rec.last_error.empty()) return "Ошибка: " + rec.last_error.substr(0, 28);
    if (rec.user_info.has_value() && rec.user_info->has_expire && rec.user_info->expires_at_epoch_sec > 0) {
        const std::time_t tt = static_cast<std::time_t>(rec.user_info->expires_at_epoch_sec);
        std::tm tm_val{};
#ifdef _WIN32
        localtime_s(&tm_val, &tt);
#else
        localtime_r(&tt, &tm_val);
#endif
        char buf[32];
        std::snprintf(buf, sizeof(buf), "до %02d.%02d.%02d",
                      tm_val.tm_mday, tm_val.tm_mon + 1, (tm_val.tm_year + 1900) % 100);
        return std::string(buf);
    }
    if (rec.url.rfind("sdmc:", 0) == 0 || rec.url.rfind("local", 0) == 0) return "Локальный файл";
    return "Безлимит";
}

}  // namespace

YumiUiApp::YumiUiApp(ipc::IYumiCtlClient& ctl_client, std::string font_dir, bool is_desktop_preview)
    : ctl_(ctl_client), font_dir_(std::move(font_dir)), is_desktop_preview_(is_desktop_preview) {
    InitSeedData();
    LoadFromDisk();
    qr_pair_ = BuildQrMatrixAuto("yumi://pair?v=1&host=127.0.0.1&port=47654&sid=init&key=init&name=Switch");
    qr_remote_ = BuildQrMatrixAuto("yumi://remote?v=1&host=127.0.0.1&port=47654&code=init&key=init&id=sw&name=Switch");
}

YumiUiApp::~YumiUiApp() {
    StopBackgroundServices();
}

void YumiUiApp::InitSeedData() {
    settings_ = AppSettings{};
    settings_.routing_mode = RoutingMode::Rules;
    settings_.block_quic = true;
    settings_.resolve_server_address = true;
    settings_.auto_connect_on_boot = false;
    settings_.split_tunnel_mode = SplitTunnelMode::AllowList;
    settings_.split_tunnel_title_ids = {0x01003A400C3DA000ULL, 0x010000000000100FULL};
    settings_.fragment_mode = FragmentMode::TlsHello;
    settings_.custom_rules.proxy = {"domain:googlevideo.com", "domain:youtube.com", "domain:ytimg.com"};
    settings_.custom_rules.direct = {"geosite:category-ru", "domain:vk.com", "192.168.0.0/16"};
    settings_.custom_rules.block = {"geosite:category-ads-all", "udp:443"};

    subs_ = {
        {"sub1", "Основная подписка", "sub.example.net", 24, 142, 500, "до 18 дек", true},
        {"sub2", "Домашний WireGuard", "192.168.1.1", 3, 0, 0, "Безлимит", true},
    };
    sub_records_.clear();
    for (const auto& su : subs_) {
        parse::SubscriptionRecord r;
        r.id = su.id;
        r.name = su.name;
        r.url = su.url;
        r.node_count = su.node_total;
        r.enabled = su.enabled;
        if (su.limit_gb > 0) {
            parse::SubscriptionUserInfo ui;
            ui.has_download = true;
            ui.download_bytes = static_cast<uint64_t>(su.used_gb) * 1024ULL * 1024ULL * 1024ULL;
            ui.has_total = true;
            ui.total_bytes = static_cast<uint64_t>(su.limit_gb) * 1024ULL * 1024ULL * 1024ULL;
            r.user_info = ui;
        }
        sub_records_.push_back(std::move(r));
    }

    auto make_node = [](const char* id, const char* cc, const char* short_n, const char* name,
                        Protocol proto, TransportKind tk, const char* p_lbl, const char* t_lbl,
                        const char* f_lbl, const char* sni, const char* utls, const char* ep,
                        const char* sub_id, const char* sub_name, int ping, float lat, float lon,
                        const char* srv, uint16_t port) {
        UiServerEntry e;
        e.id = id;
        e.cc = cc;
        e.short_name = short_n;
        e.name = name;
        e.proto_label = p_lbl;
        e.transport_label = t_lbl;
        e.flow_label = f_lbl;
        e.sni = sni;
        e.utls = utls;
        e.endpoint = ep;
        e.sub_id = sub_id;
        e.sub_name = sub_name;
        e.ping_ms = ping;
        e.lat_deg = lat;
        e.lon_deg = lon;
        e.node.id = id;
        e.node.name = name;
        e.node.server = srv;
        e.node.port = port;
        e.node.protocol = proto;
        e.node.transport.kind = tk;
        e.node.flow = f_lbl;
        e.node.tls.enabled = (proto == Protocol::Vless || proto == Protocol::Trojan || proto == Protocol::Hysteria2);
        e.node.tls.server_name = sni;
        e.node.tls.fingerprint = utls;
        e.node.tls.reality.enabled = (proto == Protocol::Vless && std::string(t_lbl) == "REALITY");
        e.node.subscription_id = sub_id;
        return e;
    };

    servers_ = {
        make_node("fi1", "FI", "FI #1", "Финляндия · Хельсинки #1", Protocol::Vless, TransportKind::Raw,
                  "VLESS", "REALITY", "Vision", "www.microsoft.com", "chrome", "fi1.example.net:443",
                  "sub1", "Основная подписка", 34, 60.17f, 24.94f, "fi1.example.net", 443),
        make_node("nl1", "NL", "NL #1", "Нидерланды · Амстердам", Protocol::WireGuard, TransportKind::Raw,
                  "WireGuard", "UDP", "Noise_IK", "—", "native", "192.168.1.1:51820",
                  "sub2", "Домашний WireGuard", 48, 52.37f, 4.90f, "192.168.1.1", 51820),
        make_node("de1", "DE", "DE #1", "Германия · Франкфурт", Protocol::Hysteria2, TransportKind::Raw,
                  "Hysteria2", "Salamander", "QUIC v2", "cdn.cloudflare.net", "chrome", "de1.example.net:8443",
                  "sub1", "Основная подписка", 52, 50.11f, 8.68f, "de1.example.net", 8443),
        make_node("se1", "SE", "SE #1", "Швеция · Стокгольм", Protocol::Trojan, TransportKind::WebSocket,
                  "Trojan", "WS", "TLS 1.3", "edge.example.org", "firefox", "se1.example.net:443",
                  "sub1", "Основная подписка", 41, 59.33f, 18.07f, "se1.example.net", 443),
        make_node("jp1", "JP", "JP #1", "Япония · Токио CDN", Protocol::Vless, TransportKind::Xhttp,
                  "VLESS", "XHTTP", "TLS 1.3", "cdn.jp-node.net", "safari", "jp1.example.net:443",
                  "sub1", "Основная подписка", 146, 35.68f, 139.65f, "jp1.example.net", 443),
        make_node("pl1", "PL", "PL #1", "Польша · Варшава", Protocol::Shadowsocks, TransportKind::Raw,
                  "SS", "2022-blake3", "AES-128", "—", "none", "pl1.example.net:9443",
                  "sub1", "Основная подписка", -1, 52.23f, 21.01f, "pl1.example.net", 9443),
    };

    title_ids_ = {
        {0x01003A400C3DA000ULL, "YouTube", true},
        {0x010000000000100FULL, "Веб-браузер HOS", true},
        {0x050000BADDAD0000ULL, "Tinfoil", false},
        {0x0100000000008001ULL, "Moonlight-NX", false},
    };

    logs_ = {
        {1, "rr4---sn-n8v7kn7l.googlevideo.com", 443, "TCP", "YouTube", 0, "VPN", "14:22:18"},
        {2, "www.youtube.com", 443, "TCP", "YouTube", 0, "VPN", "14:22:15"},
        {3, "www.youtube.com", 443, "UDP", "YouTube", 2, "BLOCK (QUIC)", "14:22:15"},
        {4, "api.vk.com", 443, "TCP", "Браузер", 1, "DIRECT (RU)", "14:21:59"},
        {5, "192.168.1.1", 80, "TCP", "Система", 1, "DIRECT (LAN)", "14:21:44"},
    };
}

void YumiUiApp::SyncSubRecordsToUi() {
    subs_.clear();
    for (const auto& r : sub_records_) {
        UiSubEntry u;
        u.id = r.id;
        u.name = r.name.empty() ? (r.remote_title.empty() ? r.id : r.remote_title) : r.name;
        u.url = r.url;
        u.node_total = 0;
        for (const auto& s : servers_) {
            if (s.sub_id == r.id) ++u.node_total;
        }
        if (u.node_total == 0) u.node_total = r.node_count;
        if (r.user_info.has_value()) {
            const uint64_t used = r.user_info->upload_bytes + r.user_info->download_bytes;
            u.used_gb = static_cast<int>(used / (1024ULL * 1024ULL * 1024ULL));
            u.limit_gb = static_cast<int>(r.user_info->total_bytes / (1024ULL * 1024ULL * 1024ULL));
        }
        u.expires = FormatSubExpiry(r);
        u.enabled = r.enabled;
        subs_.push_back(std::move(u));
    }
}

void YumiUiApp::LoadFromDisk() {
    if (auto txt = store::ReadTextFile(paths::SettingsFile())) {
        if (auto parsed = store::DeserializeSettingsJson(*txt)) {
            settings_ = *parsed;
        }
    }
    if (settings_.device_id.empty()) {
        uint8_t rnd[8]{};
        if (net::crypto::RandomBytes(rnd, sizeof(rnd))) {
            settings_.device_id = net::crypto::HexEncode(rnd, sizeof(rnd));
        } else {
            settings_.device_id = "yumi-nx-0001";
        }
    }

    auto installed = logic::EnumerateInstalledTitles();
    if (!installed.empty()) {
        title_ids_.clear();
        for (const auto& app : installed) {
            const bool routed = std::find(settings_.split_tunnel_title_ids.begin(),
                                          settings_.split_tunnel_title_ids.end(), app.title_id) !=
                                settings_.split_tunnel_title_ids.end();
            title_ids_.push_back({app.title_id, app.name, routed});
        }
    } else {
        for (auto& t : title_ids_) {
            t.vpn_routed = std::find(settings_.split_tunnel_title_ids.begin(),
                                     settings_.split_tunnel_title_ids.end(), t.tid) !=
                           settings_.split_tunnel_title_ids.end();
        }
    }

    if (auto stxt = store::ReadTextFile(paths::SubscriptionsFile())) {
        if (auto subs = store::DeserializeSubscriptionsJson(*stxt); subs.has_value() && !subs->empty()) {
            sub_records_ = *subs;
        }
    }
    if (auto ntxt = store::ReadTextFile(paths::NodesFile())) {
        if (auto nodes = store::DeserializeNodesJson(*ntxt); nodes.has_value() && !nodes->empty()) {
            servers_.clear();
            for (const auto& n : *nodes) {
                std::string sname = "Подписка";
                for (const auto& sr : sub_records_) {
                    if (sr.id == n.subscription_id && !sr.name.empty()) {
                        sname = sr.name;
                        break;
                    }
                }
                servers_.push_back(MakeUiServerEntry(n, sname, -1));
            }
        }
    }
    SyncSubRecordsToUi();

    if (auto bin = store::ReadBinaryFile(paths::ActiveNodeFile())) {
        if (auto node = store::DecodeActiveNodeBinary(*bin)) {
            for (size_t i = 0; i < servers_.size(); ++i) {
                if (servers_[i].id == node->id) {
                    inspected_node_idx_ = static_cast<int>(i);
                    break;
                }
            }
        }
    }
}

void YumiUiApp::SaveConfigAndSync() {
    settings_.split_tunnel_title_ids.clear();
    for (const auto& t : title_ids_) {
        if (t.vpn_routed) settings_.split_tunnel_title_ids.push_back(t.tid);
    }
    settings_.split_tunnel_mode = settings_.split_tunnel_title_ids.empty()
        ? SplitTunnelMode::Off : SplitTunnelMode::AllowList;

    if (!is_desktop_preview_) {
        (void)store::WriteFileAtomic(paths::SettingsFile(), store::SerializeSettingsJson(settings_));
        (void)store::WriteFileAtomic(paths::SubscriptionsFile(), store::SerializeSubscriptionsJson(sub_records_));
        std::vector<ProxyNode> raw_nodes;
        raw_nodes.reserve(servers_.size());
        for (const auto& s : servers_) raw_nodes.push_back(s.node);
        (void)store::WriteFileAtomic(paths::NodesFile(), store::SerializeNodesJson(raw_nodes));

        if (!servers_.empty()) {
            const auto& active = ActiveServer();
            (void)store::WriteFileAtomic(paths::ActiveNodeFile(), store::EncodeActiveNodeBinary(active.node));
        }

        const auto geosite_blob = store::ReadBinaryFile(paths::Join(paths::kConfigDir, "geosite.dat"));
        const auto geoip_blob = store::ReadBinaryFile(paths::Join(paths::kConfigDir, "geoip.dat"));
        const auto r_idx = rules::CompileRulesIndex(
            settings_,
            geosite_blob.has_value() ? &(*geosite_blob) : nullptr,
            geoip_blob.has_value() ? &(*geoip_blob) : nullptr);
        (void)store::WriteFileAtomic(paths::RulesBinFile(), rules::SerializeRulesBin(r_idx));

        std::string quick;
        int written = 0;
        for (const auto& s : servers_) {
            if (!IsSubEnabled(s.sub_id)) continue;
            quick += s.id + "|" + s.name + "|" + std::to_string(s.ping_ms) + "\n";
            if (++written >= 4) break;
        }
        (void)store::WriteFileAtomic(paths::QuickNodesFile(), quick);
    }
    if (ctl_.IsConnected()) {
        ctl_.SetRoutingMode(settings_.routing_mode);
        ctl_.ReloadConfig();
    }
    ++nodes_revision_;
    ++subs_revision_;
    PushRemoteSnapshot();
}

void YumiUiApp::StartBackgroundServices() {
    if (headless_mode_) {
        qr_pair_ = BuildQrMatrixAuto("yumi://pair?v=1&host=" + lan_ip_ +
                                     "&port=47654&sid=YumiSwitchHeadless01&key=headless&name=Nintendo%20Switch");
        qr_remote_ = BuildQrMatrixAuto("yumi://remote?v=1&host=" + lan_ip_ +
                                       "&port=47654&code=YumiRemoteHeadless012345&key=headless&id=sw-01&name=Nintendo%20Switch");
        return;
    }

    const std::string id_path = is_desktop_preview_
        ? std::string{}
        : paths::Join(paths::kConfigDir, "remote_identity.json");
    if (remote_server_.Start(lan_ip_, id_path, "Nintendo Switch", false, logic::kRemoteDefaultPort)) {
        remote_beacon_.Start(remote_server_.HostId(), remote_server_.HostName(),
                             remote_server_.Port(), false, logic::kRemoteBeaconPort);
        qr_remote_ = BuildQrMatrixAuto(remote_server_.ShareUrl());
    }

    const bool started_pair = pairing_server_.Start(
        lan_ip_, "Nintendo Switch", false, 0,
        [this](const logic::SubscriptionTransfer& tr) -> logic::PairingResult {
            {
                logic::SimpleLock lk(async_mu_);
                pairing_done_.push_back(tr);
            }
            return {true, "accepted", tr.name};
        });
    if (started_pair) {
        qr_pair_ = BuildQrMatrixAuto(pairing_server_.ShareUrl());
    }
}

void YumiUiApp::StopBackgroundServices() {
    pair_sim_worker_.Join();
    sub_refresh_worker_.Join();
    latency_batch_.Stop();
    speed_runner_.Stop();
    update_checker_.Stop();
    pairing_server_.Stop();
    remote_beacon_.Stop();
    remote_server_.Stop();
}

void YumiUiApp::PushRemoteSnapshot() {
    if (headless_mode_ || !remote_server_.IsRunning()) return;
    logic::RemoteHostSnapshot snap;
    snap.host_name = "Nintendo Switch";
    switch (status_.state) {
        case TunnelState::Off:        snap.state = "Off"; break;
        case TunnelState::Connecting: snap.state = "Warming"; break;
        case TunnelState::On:         snap.state = "On"; break;
        case TunnelState::Stopping:   snap.state = "Stopping"; break;
        case TunnelState::Error:      snap.state = "Failed"; break;
    }
    snap.selected_node_id = servers_.empty() ? std::string{} : ActiveServer().id;
    snap.download_bytes_per_sec = stats_.downlink_bps;
    snap.upload_bytes_per_sec = stats_.uplink_bps;
    snap.nodes_revision = nodes_revision_;
    for (const auto& s : servers_) {
        logic::RemoteNodeSnapshot rn;
        rn.id = s.id;
        rn.name = s.name;
        rn.group = s.sub_name;
        rn.latency_ms = s.ping_ms;
        rn.latency_failed = (s.ping_ms < 0);
        rn.protocol = s.node.protocol;
        rn.badges = {s.proto_label, s.transport_label};
        rn.subscription_id = s.sub_id;
        snap.nodes.push_back(std::move(rn));
    }
    {
        logic::SimpleLock lk(async_mu_);
        snap.pinging_node_ids = pinging_ids_;
    }
    snap.subscriptions_revision = subs_revision_;
    for (const auto& r : sub_records_) {
        logic::RemoteSubSnapshot rs;
        rs.id = r.id;
        rs.name = r.name;
        rs.remote_title = r.remote_title;
        rs.url_host = r.url;
        rs.enabled = r.enabled;
        rs.node_count = r.node_count;
        rs.last_updated_epoch_ms = r.last_updated_epoch_ms;
        rs.last_error = r.last_error;
        rs.user_info = r.user_info;
        rs.refreshing = sub_refresh_busy_.load();
        snap.subscriptions.push_back(std::move(rs));
    }
    snap.settings = settings_;
    remote_server_.SetSnapshot(snap);
}

bool YumiUiApp::Init(NVGcontext* vg) {
    auto load_font = [&](const char* name, const char* file) -> int {
        std::string path = font_dir_;
        if (!path.empty() && path.back() != '/' && path.back() != '\\') path.push_back('/');
        path += file;
        return nvgCreateFont(vg, name, path.c_str());
    };
    font_display_ = load_font("display", "roboto_flex_display.ttf");
    font_semibold_ = load_font("semibold", "roboto_flex_semibold.ttf");
    font_medium_ = load_font("medium", "roboto_flex_medium.ttf");
    font_regular_ = load_font("regular", "roboto_flex_regular.ttf");
    font_mono_ = load_font("mono", "roboto_mono_medium.ttf");

    lan_ip_ = logic::GetLocalLanIpv4();
    RefreshFromCtl(true);
    StartBackgroundServices();
    PushRemoteSnapshot();
    return font_display_ >= 0 && font_semibold_ >= 0 && font_regular_ >= 0 && font_mono_ >= 0;
}

void YumiUiApp::Shutdown(NVGcontext*) {
    StopBackgroundServices();
}

void YumiUiApp::RefreshFromCtl(bool force) {
    ctl_connected_ = ctl_.IsConnected();
    if (!ctl_connected_) {
        if (force) {
            status_ = ipc::IpcStatus{};
            stats_ = ipc::IpcTrafficStats{};
            version_info_ = ipc::IpcVersionInfo{};
        }
        return;
    }
    if (!ctl_.GetVersion(version_info_) ||
        !ctl_.GetStatus(status_) ||
        !ctl_.GetTrafficStats(stats_)) {
        ctl_connected_ = false;
        status_ = ipc::IpcStatus{};
        stats_ = ipc::IpcTrafficStats{};
        version_info_ = ipc::IpcVersionInfo{};
        return;
    }

    std::vector<ipc::IpcConnectionRecord> recs;
    if (ctl_.GetConnectionLog(last_conn_seq_, recs) && !recs.empty()) {
        for (const auto& r : recs) {
            last_conn_seq_ = std::max(last_conn_seq_, r.sequence_id);
            UiLogEntry e;
            e.sequence_id = r.sequence_id;
            e.host = r.host;
            e.port = r.port;
            e.proto = r.is_udp ? "UDP" : "TCP";
            e.app_name = "Switch";
            for (const auto& t : title_ids_) {
                if (t.tid == r.program_id) { e.app_name = t.name; break; }
            }
            if (r.route_action == 2) { e.route_action = 2; e.badge = "BLOCK (QUIC)"; }
            else if (r.route_action == 1) { e.route_action = 1; e.badge = "DIRECT"; }
            else if (r.route_action == 3) { e.route_action = 0; e.badge = "DNS"; }
            else { e.route_action = 0; e.badge = "VPN"; }
            e.time_str = FormatDuration(static_cast<uint64_t>(anim_sec_));

            // Avoid duplicate seed lines when desktop mock starts
            const bool dup = std::any_of(logs_.begin(), logs_.end(),
                                         [&](const UiLogEntry& ex) { return ex.sequence_id == e.sequence_id; });
            if (!dup) {
                logs_.insert(logs_.begin(), std::move(e));
                if (logs_.size() > 24) logs_.pop_back();
            }
        }
    }
}

void YumiUiApp::ShowToast(const std::string& msg) {
    toast_msg_ = msg;
    toast_ttl_ = 2.6;
}

void YumiUiApp::ToggleTunnel() {
    if (!ctl_.IsConnected()) {
        ShowToast("sysmodule yumi:ctl недоступен");
        return;
    }
    const bool active = status_.state == TunnelState::On || status_.state == TunnelState::Connecting;
    if (active) {
        ctl_.Stop();
        ShowToast("Туннель отключён");
    } else {
        const auto& s = ActiveServer();
        if (!is_desktop_preview_) {
            (void)store::WriteFileAtomic(paths::ActiveNodeFile(), store::EncodeActiveNodeBinary(s.node));
        }
        ctl_.SelectActiveNode(s.id);
        ctl_.ReloadConfig();
        ctl_.Start();
        ShowToast("Подключение: " + s.name);
    }
    RefreshFromCtl(true);
}

void YumiUiApp::ShiftTab(int delta) {
    const int next = (static_cast<int>(active_tab_) + delta + 5) % 5;
    active_tab_ = static_cast<UiTab>(next);
    focus_idx_ = 0;
    if (delta < 0) shoulder_flash_l_ = 8;
    else shoulder_flash_r_ = 8;
}

void YumiUiApp::RunPingMeasure(int node_idx_or_all) {
    if (servers_.empty()) return;
    if (headless_mode_) {
        for (size_t i = 0; i < servers_.size(); ++i) {
            if (node_idx_or_all >= 0 && static_cast<int>(i) != node_idx_or_all) continue;
            if (servers_[i].ping_ms < 0) servers_[i].ping_ms = 58;
        }
        return;
    }

    std::vector<ProxyNode> batch;
    {
        logic::SimpleLock lk(async_mu_);
        pinging_ids_.clear();
        for (size_t i = 0; i < servers_.size(); ++i) {
            if (node_idx_or_all >= 0 && static_cast<int>(i) != node_idx_or_all) continue;
            if (!IsSubEnabled(servers_[i].sub_id)) continue;
            batch.push_back(servers_[i].node);
            pinging_ids_.push_back(servers_[i].id);
        }
    }
    if (batch.empty()) {
        ShowToast("Нет активных узлов для замера");
        return;
    }
    latency_batch_.Start(std::move(batch), settings_, logic::LatencyTestMethod::TcpConnect, 1, 3000, 3);
    PushRemoteSnapshot();
    ShowToast(node_idx_or_all >= 0 ? "Замер узла запущен…" : "Замер задержки всех узлов…");
}

void YumiUiApp::AddCustomRuleAction(CustomRules::Action action, const std::string& host) {
    auto clean = CustomRules::Normalize(host).value_or("domain:" + host);
    auto erase_from = [&](std::vector<std::string>& vec) {
        vec.erase(std::remove(vec.begin(), vec.end(), clean), vec.end());
    };
    erase_from(settings_.custom_rules.proxy);
    erase_from(settings_.custom_rules.direct);
    erase_from(settings_.custom_rules.block);

    uint8_t r_act = 0;
    const char* badge = "VPN (Rule)";
    if (action == CustomRules::Action::Proxy) {
        settings_.custom_rules.proxy.insert(settings_.custom_rules.proxy.begin(), clean);
        rule_bucket_ = 0;
    } else if (action == CustomRules::Action::Direct) {
        settings_.custom_rules.direct.insert(settings_.custom_rules.direct.begin(), clean);
        rule_bucket_ = 1;
        r_act = 1;
        badge = "DIRECT (Rule)";
    } else {
        settings_.custom_rules.block.insert(settings_.custom_rules.block.begin(), clean);
        rule_bucket_ = 2;
        r_act = 2;
        badge = "BLOCK (Rule)";
    }

    for (auto& l : logs_) {
        if (l.host == host) {
            l.route_action = r_act;
            l.badge = badge;
        }
    }
    SaveConfigAndSync();
    ShowToast("Правило: " + clean);
}

void YumiUiApp::ImportFromSd() {
    auto sd_txt = store::ReadTextFile(paths::ImportFile());
    if (sd_txt.has_value() && !sd_txt->empty()) {
        const auto parsed = parse::ParseSubscriptionBody(*sd_txt, "sub-sd");
        if (!parsed.nodes.empty()) {
            const auto meta = parse::ParseMetadataComments(*sd_txt);
            parse::SubscriptionRecord sd_rec;
            sd_rec.id = "sub-sd";
            sd_rec.name = "SD · Импорт import.txt";
            sd_rec.url = paths::ImportFile();
            sd_rec.enabled = true;
            sd_rec.node_count = static_cast<int32_t>(parsed.nodes.size());
            sd_rec.last_updated_epoch_ms = logic::CurrentEpochMs();
            for (const auto& kv : meta) {
                if (kv.first == "profile-title") {
                    sd_rec.remote_title = parse::DecodeProfileTitle(kv.second);
                    if (!sd_rec.remote_title.empty()) sd_rec.name = sd_rec.remote_title;
                } else if (kv.first == "subscription-userinfo") {
                    sd_rec.user_info = parse::ParseSubscriptionUserInfo(kv.second);
                }
            }

            sub_records_.erase(
                std::remove_if(sub_records_.begin(), sub_records_.end(),
                               [](const parse::SubscriptionRecord& r) { return r.id == "sub-sd"; }),
                sub_records_.end());
            sub_records_.push_back(sd_rec);

            servers_.erase(
                std::remove_if(servers_.begin(), servers_.end(),
                               [](const UiServerEntry& s) { return s.sub_id == "sub-sd"; }),
                servers_.end());
            for (const auto& n : parsed.nodes) {
                servers_.push_back(MakeUiServerEntry(n, sd_rec.name, -1));
            }
            sd_imported_ = true;
            SyncSubRecordsToUi();
            SaveConfigAndSync();
            ShowToast("Импорт SD: добавлено узлов — " + std::to_string(parsed.nodes.size()));
            return;
        }
        ShowToast("import.txt не содержит поддерживаемых узлов");
        return;
    }

    if (!is_desktop_preview_) {
        ShowToast("Файл " + paths::ImportFile() + " не найден");
        return;
    }
    if (sd_imported_) {
        ShowToast("import.txt уже добавлен в подписки");
        return;
    }
    sd_imported_ = true;
    parse::SubscriptionRecord sd_rec;
    sd_rec.id = "sub-sd";
    sd_rec.name = "SD · Резервные узлы";
    sd_rec.url = paths::ImportFile();
    sd_rec.node_count = 1;
    sd_rec.enabled = true;
    sub_records_.push_back(sd_rec);
    ProxyNode ee_n;
    ee_n.id = "ee1";
    ee_n.name = "Эстония · Таллин";
    ee_n.server = "ee1.example.net";
    ee_n.port = 443;
    ee_n.protocol = Protocol::Vless;
    ee_n.flow = "xtls-rprx-vision";
    ee_n.tls.enabled = true;
    ee_n.tls.server_name = "ee1.example.net";
    ee_n.tls.fingerprint = "chrome";
    ee_n.tls.reality.enabled = true;
    ee_n.subscription_id = "sub-sd";
    servers_.push_back(MakeUiServerEntry(ee_n, sd_rec.name, 27));
    SyncSubRecordsToUi();
    ShowToast("Импорт import.txt: +Эстония · Таллин");
}

void YumiUiApp::SubRefreshThreadEntry(void* arg) {
    auto* app = static_cast<YumiUiApp*>(arg);
    if (!app) return;

    parse::SubscriptionRecord rec;
    AppSettings cfg;
    {
        logic::SimpleLock lk(app->async_mu_);
        rec = app->sub_refresh_job_;
        cfg = app->settings_;
    }

    SubRefreshResult res;
    res.sub_id = rec.id;

    if (rec.url.rfind("http://", 0) != 0 && rec.url.rfind("https://", 0) != 0) {
        res.error = "Локальный профиль";
    } else {
        logic::HttpRequest req;
        req.method = "GET";
        req.url = rec.url;
        req.headers = rec.headers;
        if (!rec.user_agent_override.empty()) req.user_agent = rec.user_agent_override;
        req.timeout_ms = 12000;
        req.settings = cfg;

        const auto resp = logic::ExecuteHttpRequest(req);
        if (!resp.ok || resp.status_code < 200 || resp.status_code >= 300) {
            res.error = resp.error.empty() ? ("HTTP " + std::to_string(resp.status_code)) : resp.error;
        } else {
            const auto parsed = parse::ParseSubscriptionBody(resp.body, rec.id);
            if (parsed.nodes.empty()) {
                res.error = "Нет поддерживаемых узлов";
            } else {
                res.ok = true;
                res.nodes = parsed.nodes;
                const std::string ui_hdr = resp.Header("subscription-userinfo");
                if (!ui_hdr.empty()) res.user_info = parse::ParseSubscriptionUserInfo(ui_hdr);
                const std::string pt_hdr = resp.Header("profile-title");
                if (!pt_hdr.empty()) res.remote_title = parse::DecodeProfileTitle(pt_hdr);

                const auto meta = parse::ParseMetadataComments(resp.body);
                for (const auto& kv : meta) {
                    if (kv.first == "subscription-userinfo" && !res.user_info.has_value()) {
                        res.user_info = parse::ParseSubscriptionUserInfo(kv.second);
                    } else if (kv.first == "profile-title" && res.remote_title.empty()) {
                        res.remote_title = parse::DecodeProfileTitle(kv.second);
                    }
                }
            }
        }
    }

    {
        logic::SimpleLock lk(app->async_mu_);
        app->sub_refresh_done_.push_back(std::move(res));
    }
    app->sub_refresh_busy_.store(false);
}

void YumiUiApp::StartSubscriptionRefresh(size_t sub_idx) {
    if (sub_idx >= sub_records_.size() || headless_mode_) return;
    if (sub_refresh_busy_.load()) {
        ShowToast("Подписка уже обновляется…");
        return;
    }
    sub_refresh_worker_.Join();
    {
        logic::SimpleLock lk(async_mu_);
        sub_refresh_job_ = sub_records_[sub_idx];
    }
    sub_refresh_busy_.store(true);
    if (!sub_refresh_worker_.Start(&YumiUiApp::SubRefreshThreadEntry, this, 0x10000)) {
        sub_refresh_busy_.store(false);
        ShowToast("Не удалось запустить поток обновления");
        return;
    }
    ShowToast("Обновляем подписку: " + sub_records_[sub_idx].name + "…");
}

void YumiUiApp::PairSimThreadEntry(void* arg) {
    auto* app = static_cast<YumiUiApp*>(arg);
    if (!app) return;
    std::string uri;
    {
        logic::SimpleLock lk(app->async_mu_);
        uri = app->pair_sim_uri_;
    }
    logic::SubscriptionTransfer tr;
    tr.version = 1;
    tr.name = "Игровой маршрут · Yumi Phone";
    tr.url = "https://sub.yumi.invalid/profile";
    (void)logic::SendPairingSubscription(uri, tr, 4000);
}

void YumiUiApp::StartLoopbackPairSim() {
    if (headless_mode_ || !pairing_server_.IsActive()) return;
    pair_sim_worker_.Join();
    std::string uri = pairing_server_.ShareUrl();
    const size_t hpos = uri.find("host=");
    if (hpos != std::string::npos) {
        const size_t amp = uri.find('&', hpos);
        uri.replace(hpos + 5, (amp == std::string::npos ? uri.size() : amp) - (hpos + 5), "127.0.0.1");
    }
    {
        logic::SimpleLock lk(async_mu_);
        pair_sim_uri_ = uri;
    }
    pair_sim_worker_.Start(&YumiUiApp::PairSimThreadEntry, this, 0x8000);
}

void YumiUiApp::PollBackgroundServices() {
    // 1. Latency batch progress
    if (latency_batch_.IsRunning() || !pinging_ids_.empty()) {
        std::vector<logic::LatencyResult> batch_res;
        latency_batch_.DrainCompleted(batch_res);
        bool updated = !batch_res.empty();
        for (const auto& r : batch_res) {
            for (auto& s : servers_) {
                if (s.id == r.node_id) {
                    s.ping_ms = r.ping_ms;
                    break;
                }
            }
            logic::SimpleLock lk(async_mu_);
            pinging_ids_.erase(std::remove(pinging_ids_.begin(), pinging_ids_.end(), r.node_id), pinging_ids_.end());
        }
        if (!latency_batch_.IsRunning() && !pinging_ids_.empty()) {
            logic::SimpleLock lk(async_mu_);
            pinging_ids_.clear();
            updated = true;
        }
        if (updated) {
            ++nodes_revision_;
            PushRemoteSnapshot();
            if (!latency_batch_.IsRunning()) {
                ShowToast("Замер задержки завершён");
            }
        }
    }

    // 2. Phone pairing receipts (yumi://pair)
    std::vector<logic::SubscriptionTransfer> transfers;
    {
        logic::SimpleLock lk(async_mu_);
        transfers.swap(pairing_done_);
    }
    for (const auto& tr : transfers) {
        phone_scanned_ = true;
        parse::SubscriptionRecord rec;
        rec.id = "sub-phone-" + std::to_string(sub_records_.size() + 1);
        rec.name = tr.name;
        rec.url = tr.url;
        rec.user_agent_override = tr.user_agent_override;
        rec.headers = tr.headers;
        rec.enabled = true;
        rec.last_updated_epoch_ms = logic::CurrentEpochMs();
        sub_records_.push_back(rec);

        if (tr.url.find(".invalid") != std::string::npos) {
            ProxyNode ch;
            ch.id = "ch-" + std::to_string(servers_.size() + 1);
            ch.name = "Швейцария · Цюрих #1";
            ch.server = "ch1.example.net";
            ch.port = 443;
            ch.protocol = Protocol::Vless;
            ch.flow = "xtls-rprx-vision";
            ch.tls.enabled = true;
            ch.tls.server_name = "www.logitech.com";
            ch.tls.fingerprint = "chrome";
            ch.tls.reality.enabled = true;
            ch.subscription_id = rec.id;
            servers_.push_back(MakeUiServerEntry(ch, rec.name, 39));
            sub_records_.back().node_count = 1;
        }
        SyncSubRecordsToUi();
        SaveConfigAndSync();
        ShowToast("Принято по ECDH P-256: " + tr.name);
        if (tr.url.find(".invalid") == std::string::npos) {
            StartSubscriptionRefresh(sub_records_.size() - 1);
        }
    }

    // 3. Subscription HTTP refresh completions
    std::vector<SubRefreshResult> ref_done;
    {
        logic::SimpleLock lk(async_mu_);
        ref_done.swap(sub_refresh_done_);
    }
    for (const auto& r : ref_done) {
        std::string sub_name = "Подписка";
        for (auto& sr : sub_records_) {
            if (sr.id == r.sub_id) {
                sr.last_updated_epoch_ms = logic::CurrentEpochMs();
                if (r.ok) {
                    sr.last_error.clear();
                    sr.node_count = static_cast<int32_t>(r.nodes.size());
                    if (r.user_info.has_value()) sr.user_info = r.user_info;
                    if (!r.remote_title.empty()) sr.remote_title = r.remote_title;
                } else {
                    sr.last_error = r.error;
                }
                sub_name = sr.name;
                break;
            }
        }
        if (r.ok) {
            servers_.erase(
                std::remove_if(servers_.begin(), servers_.end(),
                               [&](const UiServerEntry& s) { return s.sub_id == r.sub_id; }),
                servers_.end());
            for (const auto& n : r.nodes) {
                servers_.push_back(MakeUiServerEntry(n, sub_name, -1));
            }
            ShowToast("Обновлена: " + sub_name + " (" + std::to_string(r.nodes.size()) + ")");
        } else {
            ShowToast("Подписка " + sub_name + ": " + r.error);
        }
        SyncSubRecordsToUi();
        SaveConfigAndSync();
    }

    // 4. SpeedTest & UpdateChecker state polling
    if (speed_runner_.IsRunning() || speedtest_result_.find("Замер") != std::string::npos ||
        speedtest_result_.find("Запуск") != std::string::npos) {
        const auto st = speed_runner_.Snapshot();
        if (!st.summary.empty()) speedtest_result_ = st.summary;
    }
    if (update_checker_.IsBusy() || update_status_.find("Проверка") != std::string::npos ||
        update_status_.find("Загрузка") != std::string::npos) {
        const auto up = update_checker_.Snapshot();
        if (!up.status_line.empty()) update_status_ = up.status_line;
    }
}

void YumiUiApp::HandleRemoteCommands() {
    if (headless_mode_ || !remote_server_.IsRunning()) return;
    std::vector<logic::RemoteCommand> cmds;
    remote_server_.DrainCommands(cmds);
    for (const auto& cmd : cmds) {
        switch (cmd.type) {
            case logic::RemoteCommand::Type::Look:
                PushRemoteSnapshot();
                break;
            case logic::RemoteCommand::Type::Connect:
                if (status_.state != TunnelState::On && status_.state != TunnelState::Connecting) {
                    ToggleTunnel();
                }
                break;
            case logic::RemoteCommand::Type::Disconnect:
                if (status_.state == TunnelState::On || status_.state == TunnelState::Connecting) {
                    ToggleTunnel();
                }
                break;
            case logic::RemoteCommand::Type::Select:
                for (size_t i = 0; i < servers_.size(); ++i) {
                    if (servers_[i].id == cmd.node_id) {
                        inspected_node_idx_ = static_cast<int>(i);
                        if (!is_desktop_preview_) {
                            (void)store::WriteFileAtomic(paths::ActiveNodeFile(),
                                                         store::EncodeActiveNodeBinary(servers_[i].node));
                        }
                        if (ctl_.IsConnected()) {
                            ctl_.SelectActiveNode(servers_[i].id);
                            ctl_.ReloadConfig();
                        }
                        PushRemoteSnapshot();
                        break;
                    }
                }
                break;
            case logic::RemoteCommand::Type::PingAll:
                RunPingMeasure(-1);
                break;
            case logic::RemoteCommand::Type::PingOne:
                for (size_t i = 0; i < servers_.size(); ++i) {
                    if (servers_[i].id == cmd.node_id) {
                        RunPingMeasure(static_cast<int>(i));
                        break;
                    }
                }
                break;
            case logic::RemoteCommand::Type::AddSub:
                if (!cmd.url.empty()) {
                    parse::SubscriptionRecord rec;
                    rec.id = "sub-rem-" + std::to_string(sub_records_.size() + 1);
                    rec.name = cmd.name.empty() ? std::string("Удалённая подписка") : cmd.name;
                    rec.url = cmd.url;
                    rec.enabled = true;
                    sub_records_.push_back(rec);
                    SyncSubRecordsToUi();
                    SaveConfigAndSync();
                    StartSubscriptionRefresh(sub_records_.size() - 1);
                }
                break;
            case logic::RemoteCommand::Type::RefreshSub:
                for (size_t i = 0; i < sub_records_.size(); ++i) {
                    if (sub_records_[i].id == cmd.subscription_id) {
                        StartSubscriptionRefresh(i);
                        break;
                    }
                }
                break;
            case logic::RemoteCommand::Type::RemoveSub:
                sub_records_.erase(
                    std::remove_if(sub_records_.begin(), sub_records_.end(),
                                   [&](const parse::SubscriptionRecord& r) { return r.id == cmd.subscription_id; }),
                    sub_records_.end());
                servers_.erase(
                    std::remove_if(servers_.begin(), servers_.end(),
                                   [&](const UiServerEntry& s) { return s.sub_id == cmd.subscription_id; }),
                    servers_.end());
                SyncSubRecordsToUi();
                SaveConfigAndSync();
                break;
            case logic::RemoteCommand::Type::ToggleSub:
                for (auto& r : sub_records_) {
                    if (r.id == cmd.subscription_id) {
                        r.enabled = cmd.enabled;
                        break;
                    }
                }
                SyncSubRecordsToUi();
                SaveConfigAndSync();
                break;
            case logic::RemoteCommand::Type::UpdateSettings:
                if (logic::ApplyRemoteSettingsPatch(cmd.settings_patch_json, settings_)) {
                    SaveConfigAndSync();
                }
                break;
        }
    }
}

void YumiUiApp::ExecuteHit(const HitZone& hz) {
    switch (hz.action) {
        case HitAction::None: break;
        case HitAction::ShoulderL: ShiftTab(-1); break;
        case HitAction::ShoulderR: ShiftTab(+1); break;
        case HitAction::SelectTab:
            active_tab_ = static_cast<UiTab>(std::clamp(hz.arg0, 0, 4));
            focus_idx_ = 0;
            break;
        case HitAction::ToggleTunnel: ToggleTunnel(); break;
        case HitAction::ToggleVis:
            vis_planet_ = !vis_planet_;
            ShowToast(vis_planet_ ? "Визуализация: Пиксельная планета" : "Визуализация: Живые волны");
            break;
        case HitAction::SetRoute:
            settings_.routing_mode = static_cast<RoutingMode>(std::clamp(hz.arg0, 0, 2));
            SaveConfigAndSync();
            ShowToast(std::string("Маршрутизация: ") + ModeLabel(settings_.routing_mode));
            break;
        case HitAction::GotoServers:
            active_tab_ = UiTab::Servers;
            inspected_node_idx_ = ActiveServerIndex();
            focus_idx_ = 0;
            break;
        case HitAction::GotoRules:
            active_tab_ = UiTab::Rules;
            focus_idx_ = 0;
            break;
        case HitAction::FilterProto: {
            proto_filter_ = hz.arg0;
            const auto flt = FilteredServerIndices();
            if (!flt.empty() && std::find(flt.begin(), flt.end(), inspected_node_idx_) == flt.end()) {
                inspected_node_idx_ = flt[0];
            }
            list_scroll_servers_ = 0.0f;
            break;
        }
        case HitAction::PingAll: RunPingMeasure(-1); break;
        case HitAction::InspectNode: inspected_node_idx_ = std::clamp(hz.arg0, 0, static_cast<int>(servers_.size()) - 1); break;
        case HitAction::ConnectNode: {
            const int idx = std::clamp(hz.arg0, 0, static_cast<int>(servers_.size()) - 1);
            inspected_node_idx_ = idx;
            const auto& srv = servers_[static_cast<size_t>(idx)];
            if (!is_desktop_preview_) {
                (void)store::WriteFileAtomic(paths::ActiveNodeFile(), store::EncodeActiveNodeBinary(srv.node));
            }
            if (ctl_.IsConnected()) {
                ctl_.SelectActiveNode(srv.id);
                ctl_.ReloadConfig();
                if (status_.state != TunnelState::On) ctl_.Start();
                RefreshFromCtl(true);
            }
            ShowToast("Активный узел: " + srv.name);
            break;
        }
        case HitAction::PingOne: RunPingMeasure(hz.arg0); break;
        case HitAction::ToggleSub: {
            const size_t si = static_cast<size_t>(std::clamp(hz.arg0, 0, static_cast<int>(subs_.size()) - 1));
            subs_[si].enabled = !subs_[si].enabled;
            if (si < sub_records_.size()) sub_records_[si].enabled = subs_[si].enabled;
            SaveConfigAndSync();
            ShowToast(subs_[si].name + (subs_[si].enabled ? ": включена" : ": отключена"));
            break;
        }
        case HitAction::RefreshSub: {
            const size_t si = static_cast<size_t>(std::clamp(hz.arg0, 0, static_cast<int>(subs_.size()) - 1));
            StartSubscriptionRefresh(si);
            break;
        }
        case HitAction::SdImport: ImportFromSd(); break;
        case HitAction::SimScan:
            if (!headless_mode_ && pairing_server_.IsActive() && !phone_scanned_) {
                StartLoopbackPairSim();
                ShowToast("Отправляем тестовую подписку по ECDH P-256…");
            } else if (!headless_mode_) {
                pairing_server_.Start(
                    lan_ip_, "Nintendo Switch", false, 0,
                    [this](const logic::SubscriptionTransfer& tr) -> logic::PairingResult {
                        {
                            logic::SimpleLock lk(async_mu_);
                            pairing_done_.push_back(tr);
                        }
                        return {true, "accepted", tr.name};
                    });
                qr_pair_ = BuildQrMatrixAuto(pairing_server_.ShareUrl());
                ShowToast("Создана новая сессия QR-привязки");
            } else {
                ShowToast("Профиль с телефона уже передан");
            }
            break;
        case HitAction::SetLogFilter: log_filter_ = hz.arg0; list_scroll_logs_ = 0.0f; break;
        case HitAction::SimLog: {
            const size_t n = logs_.size() + 1;
            logs_.insert(logs_.begin(), {static_cast<uint32_t>(n + 10), "i.ytimg.com", 443, "TCP", "YouTube", 0, "VPN", "14:23:05"});
            if (logs_.size() > 12) logs_.pop_back();
            ShowToast("Новое соединение: i.ytimg.com:443");
            break;
        }
        case HitAction::AddRule: {
            if (hz.arg0 >= 0 && hz.arg0 < static_cast<int>(logs_.size())) {
                AddCustomRuleAction(static_cast<CustomRules::Action>(hz.arg1), logs_[static_cast<size_t>(hz.arg0)].host);
            }
            break;
        }
        case HitAction::SetRuleBucket: rule_bucket_ = hz.arg0; break;
        case HitAction::DelRule: {
            auto& vec = (rule_bucket_ == 0) ? settings_.custom_rules.proxy
                      : (rule_bucket_ == 1) ? settings_.custom_rules.direct : settings_.custom_rules.block;
            if (hz.arg0 >= 0 && hz.arg0 < static_cast<int>(vec.size())) {
                const std::string removed = vec[static_cast<size_t>(hz.arg0)];
                vec.erase(vec.begin() + hz.arg0);
                SaveConfigAndSync();
                ShowToast("Удалено правило: " + removed);
            }
            break;
        }
        case HitAction::CycleTitleId: {
            if (hz.arg0 >= 0 && hz.arg0 < static_cast<int>(title_ids_.size())) {
                auto& t = title_ids_[static_cast<size_t>(hz.arg0)];
                t.vpn_routed = !t.vpn_routed;
                SaveConfigAndSync();
                ShowToast(t.name + (t.vpn_routed ? " -> Через VPN" : " -> Напрямую"));
            }
            break;
        }
        case HitAction::SetTitleIdMode: {
            if (hz.arg0 >= 0 && hz.arg0 < static_cast<int>(title_ids_.size())) {
                auto& t = title_ids_[static_cast<size_t>(hz.arg0)];
                t.vpn_routed = (hz.arg1 != 0);
                SaveConfigAndSync();
                ShowToast(t.name + (t.vpn_routed ? " -> Через VPN" : " -> Напрямую"));
            }
            break;
        }
        case HitAction::SetSettingsCat: settings_cat_ = static_cast<SettingsCategory>(std::clamp(hz.arg0, 0, 4)); break;
        case HitAction::ToggleQuic:
            settings_.block_quic = !settings_.block_quic;
            SaveConfigAndSync();
            ShowToast(settings_.block_quic ? "Блокировка QUIC (UDP 443) включена" : "QUIC (UDP 443) разрешён");
            break;
        case HitAction::ToggleDoh:
            settings_.resolve_server_address = !settings_.resolve_server_address;
            SaveConfigAndSync();
            ShowToast(settings_.resolve_server_address ? "DoH-резолв сервера включён" : "DoH-резолв выключен");
            break;
        case HitAction::ToggleAutoBoot:
            settings_.auto_connect_on_boot = !settings_.auto_connect_on_boot;
            SaveConfigAndSync();
            ShowToast(settings_.auto_connect_on_boot ? "Автозапуск при старте Switch включён" : "Автозапуск выключен");
            break;
        case HitAction::SetUtls:
            settings_.tls_fingerprint = static_cast<TlsFingerprint>(hz.arg0);
            SaveConfigAndSync();
            ShowToast(std::string("Отпечаток uTLS: ") + UtlsLabel(settings_.tls_fingerprint));
            break;
        case HitAction::SetFragMode:
            settings_.fragment_mode = static_cast<FragmentMode>(hz.arg0);
            SaveConfigAndSync();
            ShowToast(std::string("Фрагментация: ") + FragLabel(settings_.fragment_mode));
            break;
        case HitAction::RunSpeedTest: {
            if (headless_mode_) break;
            if (speed_runner_.IsRunning()) {
                ShowToast("SpeedTest уже выполняется…");
                break;
            }
            logic::SpeedTestConfig scfg;
            scfg.download_url = speedtest_url_dl_;
            scfg.upload_url = speedtest_url_ul_;
            scfg.via_node = (status_.state == TunnelState::On && !servers_.empty()) ? &ActiveServer().node : nullptr;
            scfg.settings = settings_;
            speed_runner_.Start(scfg);
            speedtest_result_ = "Замер скорости…";
            ShowToast("SpeedTest запущен");
            break;
        }
        case HitAction::CheckUpdate: {
            if (headless_mode_) break;
            if (update_checker_.IsBusy()) {
                ShowToast("Проверка уже выполняется…");
                break;
            }
            const ProxyNode* via = (status_.state == TunnelState::On && !servers_.empty()) ? &ActiveServer().node : nullptr;
            update_checker_.StartCheck(update_repo_, app_version_, settings_, via, false);
            update_status_ = "Проверка GitHub Releases…";
            ShowToast("Проверяем обновления GitHub…");
            break;
        }
        case HitAction::SelectPalette:
            theme_ = BuildYumiTheme(static_cast<PaletteId>(hz.arg0), theme_.amoled);
            ShowToast(std::string("Палитра: ") + theme_.name);
            break;
        case HitAction::ToggleAmoled:
            theme_ = BuildYumiTheme(theme_.id, !theme_.amoled);
            ShowToast(theme_.amoled ? "Режим AMOLED включён" : "Режим AMOLED выключен");
            break;
    }
}

void YumiUiApp::Update(double dt_sec, const UiInputState& input) {
    anim_sec_ += dt_sec;
    poll_timer_ += dt_sec;
    if (toast_ttl_ > 0.0) toast_ttl_ = std::max(0.0, toast_ttl_ - dt_sec);
    if (shoulder_flash_l_ > 0) --shoulder_flash_l_;
    if (shoulder_flash_r_ > 0) --shoulder_flash_r_;

    if (poll_timer_ >= 0.35) {
        poll_timer_ = 0.0;
        RefreshFromCtl(false);
        PushRemoteSnapshot();
    }
    PollBackgroundServices();
    HandleRemoteCommands();

    // Smooth swells for wave/planet animation
    const bool is_conn = status_.state == TunnelState::On;
    const bool is_warm = status_.state == TunnelState::Connecting;
    if (is_conn) {
        connected_elapsed_sec_ += dt_sec;
    } else {
        connected_elapsed_sec_ = 0.0;
    }
    const float down_mib = is_conn ? static_cast<float>(stats_.downlink_bps) / (1024.0f * 1024.0f) : 0.0f;
    const float up_mib = is_conn ? static_cast<float>(stats_.uplink_bps) / (1024.0f * 1024.0f) : 0.0f;
    const float target_d = is_warm ? 0.45f : (is_conn ? std::max(0.22f, PaceOfMibPerSec(down_mib)) : 0.0f);
    const float target_u = is_warm ? 0.30f : (is_conn ? std::max(0.12f, PaceOfMibPerSec(up_mib)) : 0.0f);
    const float rate = std::min(1.0f, static_cast<float>(dt_sec) * 1.6f);
    down_swell_ += (target_d - down_swell_) * rate;
    up_swell_ += (target_u - up_swell_) * rate;
    planet_cam_.marker_deg = std::fmod(planet_cam_.marker_deg + static_cast<float>(dt_sec) * 8.0f, 360.0f);

    if (input.shoulder_l) ShiftTab(-1);
    if (input.shoulder_r) ShiftTab(+1);

    if (input.action_x) {
        if (active_tab_ == UiTab::Servers) RunPingMeasure(-1);
        else {
            const uint8_t next = static_cast<uint8_t>((static_cast<uint8_t>(settings_.routing_mode) + 1) % 3);
            settings_.routing_mode = static_cast<RoutingMode>(next);
            SaveConfigAndSync();
            ShowToast(std::string("Маршрутизация: ") + ModeLabel(settings_.routing_mode));
        }
    }
    if (input.action_y) {
        if (active_tab_ == UiTab::Subs) ImportFromSd();
        else {
            ctl_.ReloadConfig();
            ShowToast("Конфигурация перезагружена");
        }
    }

    if (std::fabs(input.scroll_delta) > 0.01f) {
        if (active_tab_ == UiTab::Servers) {
            list_scroll_servers_ = std::max(0.0f, list_scroll_servers_ - input.scroll_delta * 36.0f);
        } else if (active_tab_ == UiTab::Rules) {
            list_scroll_logs_ = std::max(0.0f, list_scroll_logs_ - input.scroll_delta * 36.0f);
        }
    }

    // Build focusable indices
    std::vector<int> focusables;
    for (size_t i = 0; i < hit_zones_.size(); ++i) {
        if (hit_zones_[i].focusable) focusables.push_back(static_cast<int>(i));
    }

    if (!focusables.empty()) {
        if (focus_idx_ >= static_cast<int>(focusables.size())) focus_idx_ = 0;

        auto move_dpad = [&](int dx_sign, int dy_sign) {
            const auto& cur = hit_zones_[static_cast<size_t>(focusables[static_cast<size_t>(focus_idx_)])];
            const float cx = cur.x + cur.w * 0.5f;
            const float cy = cur.y + cur.h * 0.5f;
            int best_f = -1;
            float best_score = 1e9f;
            for (size_t fi = 0; fi < focusables.size(); ++fi) {
                if (static_cast<int>(fi) == focus_idx_) continue;
                const auto& cand = hit_zones_[static_cast<size_t>(focusables[fi])];
                const float dx = (cand.x + cand.w * 0.5f) - cx;
                const float dy = (cand.y + cand.h * 0.5f) - cy;
                if (dx_sign > 0 && dx <= 8.0f) continue;
                if (dx_sign < 0 && dx >= -8.0f) continue;
                if (dy_sign > 0 && dy <= 8.0f) continue;
                if (dy_sign < 0 && dy >= -8.0f) continue;
                const float pri = (dx_sign != 0) ? std::fabs(dx) : std::fabs(dy);
                const float cross = (dx_sign != 0) ? std::fabs(dy) : std::fabs(dx);
                const float score = pri + cross * 2.2f;
                if (score < best_score) {
                    best_score = score;
                    best_f = static_cast<int>(fi);
                }
            }
            if (best_f >= 0) focus_idx_ = best_f;
        };

        if (input.right) move_dpad(+1, 0);
        if (input.left)  move_dpad(-1, 0);
        if (input.down)  move_dpad(0, +1);
        if (input.up)    move_dpad(0, -1);

        if (input.confirm) {
            const HitZone hz = hit_zones_[static_cast<size_t>(focusables[static_cast<size_t>(focus_idx_)])];
            ExecuteHit(hz);
        }
    }

    if (input.clicked) {
        // Walk backwards so overlapping inner controls win over background boxes
        for (int i = static_cast<int>(hit_zones_.size()) - 1; i >= 0; --i) {
            const auto& hz = hit_zones_[static_cast<size_t>(i)];
            if (PointIn(input.pointer_x, input.pointer_y, hz.x, hz.y, hz.w, hz.h)) {
                auto it = std::find(focusables.begin(), focusables.end(), i);
                if (it != focusables.end()) {
                    focus_idx_ = static_cast<int>(it - focusables.begin());
                }
                ExecuteHit(hz);
                break;
            }
        }
    }
}

const UiServerEntry& YumiUiApp::ActiveServer() const {
    for (const auto& s : servers_) {
        if (s.id == status_.active_node_id) return s;
    }
    if (!servers_.empty()) {
        if (inspected_node_idx_ >= 0 && inspected_node_idx_ < static_cast<int>(servers_.size())) {
            return servers_[static_cast<size_t>(inspected_node_idx_)];
        }
        return servers_.front();
    }
    static const UiServerEntry kFallbackEmpty = MakeUiServerEntry(ProxyNode{}, "Нет узлов", -1);
    return kFallbackEmpty;
}

int YumiUiApp::ActiveServerIndex() const {
    for (size_t i = 0; i < servers_.size(); ++i) {
        if (servers_[i].id == status_.active_node_id) return static_cast<int>(i);
    }
    return 0;
}

bool YumiUiApp::IsSubEnabled(const std::string& sub_id) const {
    for (const auto& s : subs_) {
        if (s.id == sub_id) return s.enabled;
    }
    return true;
}

uint64_t YumiUiApp::ActiveConnectedSeconds() const noexcept {
    if (status_.state != TunnelState::On) return 0;
#ifdef __SWITCH__
    if (status_.connected_at_epoch_sec > 0) {
        const uint64_t now_sec = net::MonotonicMs() / 1000ULL;
        if (now_sec >= status_.connected_at_epoch_sec) {
            return now_sec - status_.connected_at_epoch_sec;
        }
    }
#endif
    return static_cast<uint64_t>(std::max(0.0, connected_elapsed_sec_));
}

std::vector<int> YumiUiApp::FilteredServerIndices() const {
    static const char* kFilterProtos[] = {"", "VLESS", "WireGuard", "Hysteria2", "Trojan", "SS"};
    std::vector<int> out;
    for (size_t i = 0; i < servers_.size(); ++i) {
        if (!IsSubEnabled(servers_[i].sub_id)) continue;
        if (proto_filter_ > 0 && proto_filter_ < 6) {
            if (servers_[i].proto_label != kFilterProtos[proto_filter_]) continue;
        }
        out.push_back(static_cast<int>(i));
    }
    if (out.empty() && proto_filter_ == 0) {
        for (size_t i = 0; i < servers_.size(); ++i) out.push_back(static_cast<int>(i));
    }
    return out;
}

int YumiUiApp::CountCustomRules() const {
    return static_cast<int>(settings_.custom_rules.proxy.size() +
                            settings_.custom_rules.direct.size() +
                            settings_.custom_rules.block.size());
}

void YumiUiApp::PushHit(float x, float y, float w, float h, HitAction act,
                        int arg0, int arg1, bool focusable,
                        float r_tl, float r_tr, float r_br, float r_bl) {
    hit_zones_.push_back({x, y, w, h, act, arg0, arg1, focusable, r_tl, r_tr, r_br, r_bl});
}

void YumiUiApp::RenderRail(NVGcontext* vg) {
    DrawRoundedBox(vg, kRailX, kRailY, kRailW, kRailH, 46.0f, theme_.surface_highest);

    // Top shoulder L trigger
    const float lx = kRailX + 17.0f;
    const float ly = kRailY + 10.0f;
    DrawRoundedBox(vg, lx, ly, 58.0f, 26.0f, 13.0f,
                   shoulder_flash_l_ > 0 ? theme_.primary : theme_.surface_container);
    DrawTextClipped(vg, lx + 29.0f, ly + 13.5f, 50.0f, font_mono_, 12.0f,
                    shoulder_flash_l_ > 0 ? theme_.on_primary : theme_.on_surface_variant,
                    NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, "L");
    PushHit(lx, ly, 58.0f, 26.0f, HitAction::ShoulderL, 0, 0, false, 13.0f, 13.0f, 13.0f, 13.0f);

    struct RailDef {
        const char* label;
        UiIcon ico;
    };
    static constexpr std::array<RailDef, 5> kItems = {{
        {"Туннель", UiIcon::Shield},
        {"Серверы", UiIcon::Servers},
        {"Подписки", UiIcon::Cloud},
        {"Правила", UiIcon::Rules},
        {"Настройки", UiIcon::Settings},
    }};

    const float nav_y0 = ly + 32.0f;
    const float nav_h = (kRailH - 84.0f - 4.0f * 6.0f) / 5.0f;
    for (int i = 0; i < 5; ++i) {
        const float iy = nav_y0 + static_cast<float>(i) * (nav_h + 6.0f);
        const float ix = kRailX + 8.0f;
        const float iw = kRailW - 16.0f;
        const bool sel = static_cast<int>(active_tab_) == i;
        if (sel) {
            DrawRoundedBox(vg, ix, iy, iw, nav_h, 38.0f, theme_.primary_container);
        }
        const ColorRgba fg = sel ? theme_.on_primary_container : theme_.on_surface_variant;
        DrawVectorIcon(vg, kItems[static_cast<size_t>(i)].ico, ix + iw * 0.5f, iy + nav_h * 0.5f - 9.0f, 24.0f, fg);
        DrawTextClipped(vg, ix + iw * 0.5f, iy + nav_h * 0.5f + 16.0f, iw - 4.0f, font_semibold_, 10.5f,
                        fg, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, kItems[static_cast<size_t>(i)].label);
        PushHit(ix, iy, iw, nav_h, HitAction::SelectTab, i, 0, true, 38.0f, 38.0f, 38.0f, 38.0f);
    }

    // Bottom shoulder R trigger
    const float ry = kRailY + kRailH - 36.0f;
    DrawRoundedBox(vg, lx, ry, 58.0f, 26.0f, 13.0f,
                   shoulder_flash_r_ > 0 ? theme_.primary : theme_.surface_container);
    DrawTextClipped(vg, lx + 29.0f, ry + 13.5f, 50.0f, font_mono_, 12.0f,
                    shoulder_flash_r_ > 0 ? theme_.on_primary : theme_.on_surface_variant,
                    NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, "R");
    PushHit(lx, ry, 58.0f, 26.0f, HitAction::ShoulderR, 0, 0, false, 13.0f, 13.0f, 13.0f, 13.0f);
}

void YumiUiApp::RenderTopBar(NVGcontext* vg, const char* title, const char* subtitle, bool show_status_pill) {
    DrawTextClipped(vg, kWorkX, kWorkY + 23.0f, 360.0f, font_display_, 28.0f,
                    theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, title);

    float title_w = 180.0f;
    if (font_display_ >= 0) {
        nvgFontFaceId(vg, font_display_);
        nvgFontSize(vg, 28.0f);
        title_w = nvgTextBounds(vg, 0, 0, title, nullptr, nullptr);
    }
    DrawTextClipped(vg, kWorkX + title_w + 16.0f, kWorkY + 24.0f, 440.0f, font_regular_, 13.5f,
                    theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, subtitle);

    if (show_status_pill) {
        const auto& srv = ActiveServer();
        const bool is_conn = status_.state == TunnelState::On;
        char txt[64];
        if (is_conn) {
            std::snprintf(txt, sizeof(txt), "Туннель: %s · %d ms", srv.short_name.c_str(),
                          srv.ping_ms >= 0 ? srv.ping_ms : 34);
        } else {
            std::snprintf(txt, sizeof(txt), "Туннель выключен");
        }
        const float pw = is_conn ? 216.0f : 176.0f;
        const float px = kWorkX + kWorkW - pw;
        const float py = kWorkY + 5.0f;
        DrawRoundedBox(vg, px, py, pw, 36.0f, 18.0f, is_conn ? theme_.primary_container : theme_.surface_container);
        nvgBeginPath(vg);
        nvgCircle(vg, px + 18.0f, py + 18.0f, 4.5f);
        nvgFillColor(vg, Nvg(is_conn ? theme_.latency_fast : theme_.error));
        nvgFill(vg);
        DrawTextClipped(vg, px + 30.0f, py + 18.0f, pw - 42.0f, font_semibold_, 13.0f,
                        is_conn ? theme_.on_primary_container : theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, txt);
        PushHit(px, py, pw, 36.0f, HitAction::ToggleTunnel, 0, 0, true, 18.0f, 18.0f, 18.0f, 18.0f);
    }
}

void YumiUiApp::RenderConnectTab(NVGcontext* vg) {
    const auto& srv = ActiveServer();
    const bool is_conn = status_.state == TunnelState::On;
    const bool is_busy = status_.state == TunnelState::Connecting;
    const bool is_fail = status_.state == TunnelState::Error;

    constexpr float kCenterW = 756.0f;
    constexpr float kRightX = kWorkX + kCenterW + 18.0f;
    constexpr float kRightW = kWorkW - kCenterW - 18.0f;  // 356px

    // Top headline + detail + right tag
    const char* headline = is_conn ? "Защищено"
                         : is_busy ? "Подключаем…"
                         : is_fail ? "Ошибка связи" : "Туннель выключен";
    const ColorRgba head_col = is_conn ? theme_.primary : is_fail ? theme_.error : theme_.on_surface;
    DrawTextClipped(vg, kWorkX + 4.0f, kWorkY + 26.0f, kCenterW - 210.0f, font_display_, 40.0f,
                    head_col, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, headline);

    char detail[128];
    if (is_conn) {
        std::snprintf(detail, sizeof(detail), "%s · %s", srv.name.c_str(),
                      FormatDuration(ActiveConnectedSeconds()).c_str());
    } else if (is_busy) {
        std::snprintf(detail, sizeof(detail), "%s · Рукопожатие %s", srv.name.c_str(), srv.transport_label.c_str());
    } else if (srv.ping_ms >= 0) {
        std::snprintf(detail, sizeof(detail), "%s · %d ms", srv.name.c_str(), srv.ping_ms);
    } else {
        std::snprintf(detail, sizeof(detail), "%s · %s", srv.name.c_str(), srv.proto_label.c_str());
    }
    DrawTextClipped(vg, kWorkX + 4.0f, kWorkY + 66.0f, kCenterW - 210.0f, font_semibold_, 15.5f,
                    theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, detail);

    const bool bsd_mitm_ok = (version_info_.mitm_active & ipc::mitm_flag::kBsdMitmActive) != 0;
    const char* ctl_chip = !ctl_connected_ ? "sysmodule выкл"
                         : bsd_mitm_ok     ? "yumi:ctl · MITM"
                                           : "yumi:ctl · без MITM";
    DrawRoundedBox(vg, kWorkX + kCenterW - 190.0f, kWorkY + 46.0f, 190.0f, 34.0f, 17.0f, theme_.surface_container);
    DrawTextClipped(vg, kWorkX + kCenterW - 95.0f, kWorkY + 63.0f, 176.0f, font_semibold_, 12.5f,
                    theme_.on_surface_variant, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, ctl_chip);

    // Flow canvas well
    constexpr float kFlowY = kWorkY + 86.0f;
    constexpr float kFlowH = kWorkH - 86.0f;  // 594px
    DrawRoundedBox(vg, kWorkX, kFlowY, kCenterW, kFlowH, 36.0f,
                   (is_conn || is_busy) ? theme_.surface_low : theme_.surface_lowest);

    if (vis_planet_) {
        DrawPixelPlanet(vg, kWorkX, kFlowY, kCenterW, kFlowH, 0.016f, is_conn, is_busy,
                        srv.lat_deg, srv.lon_deg, planet_cam_, theme_);
    } else {
        DrawTrafficWaves(vg, kWorkX, kFlowY, kCenterW, kFlowH, static_cast<float>(anim_sec_),
                         down_swell_, up_swell_, theme_);
    }

    // Top-left LatencyBadge 68x68, r=19
    const float lx = kWorkX + 16.0f;
    const float ly = kFlowY + 16.0f;
    DrawRoundedBox(vg, lx, ly, 68.0f, 68.0f, 19.0f, theme_.surface_high);
    char ms_buf[16];
    if (is_fail || srv.ping_ms < 0) std::snprintf(ms_buf, sizeof(ms_buf), "—");
    else std::snprintf(ms_buf, sizeof(ms_buf), "%d", srv.ping_ms);
    DrawTextClipped(vg, lx + 34.0f, ly + 26.0f, 58.0f, font_mono_, 20.0f,
                    is_fail ? theme_.latency_dead : LatencyColorFor(theme_, srv.ping_ms),
                    NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, ms_buf);
    DrawTextClipped(vg, lx + 34.0f, ly + 50.0f, 58.0f, font_semibold_, 10.0f,
                    theme_.on_surface_variant, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, "MS");
    PushHit(lx, ly, 68.0f, 68.0f, HitAction::GotoServers, 0, 0, true, 19.0f, 19.0f, 19.0f, 19.0f);

    // Top-right speed capsule + vis toggle
    const float vx = kWorkX + kCenterW - 118.0f - 16.0f;
    const float sx = vx - 232.0f - 8.0f;
    DrawRoundedBox(vg, sx, ly, 232.0f, 36.0f, 18.0f, theme_.surface_high);
    char spd_d[32], spd_u[32];
    std::snprintf(spd_d, sizeof(spd_d), "↓ %s", FormatRateMib(is_conn ? stats_.downlink_bps : 0).c_str());
    std::snprintf(spd_u, sizeof(spd_u), "↑ %s", FormatRateMib(is_conn ? stats_.uplink_bps : 0).c_str());
    DrawTextClipped(vg, sx + 14.0f, ly + 18.0f, 104.0f, font_mono_, 12.5f, theme_.primary, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, spd_d);
    DrawTextClipped(vg, sx + 124.0f, ly + 18.0f, 96.0f, font_mono_, 12.5f, theme_.tertiary, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, spd_u);

    DrawRoundedBox(vg, vx, ly, 118.0f, 36.0f, 18.0f, theme_.surface_high);
    DrawVectorIcon(vg, vis_planet_ ? UiIcon::Planet : UiIcon::Waves, vx + 20.0f, ly + 18.0f, 16.0f, theme_.on_surface);
    DrawTextClipped(vg, vx + 34.0f, ly + 18.0f, 76.0f, font_semibold_, 12.5f, theme_.on_surface,
                    NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, vis_planet_ ? "Планета" : "Волны");
    PushHit(vx, ly, 118.0f, 36.0f, HitAction::ToggleVis, 0, 0, true, 18.0f, 18.0f, 18.0f, 18.0f);

    // Bottom concentric dock (padding 14 -> r = 22)
    const float by = kFlowY + kFlowH - 14.0f - 44.0f;
    static constexpr const char* kRoutes[3] = {"Global", "Rules", "Direct"};
    float rx_cur = kWorkX + 14.0f;
    for (int i = 0; i < 3; ++i) {
        const float bw = (i == 0) ? 84.0f : (i == 1 ? 82.0f : 84.0f);
        const bool active = static_cast<int>(settings_.routing_mode) == i;
        float tl, tr, br, bl;
        DrawCbgRadii(i, 3, active, 22.0f, tl, tr, br, bl);
        DrawRoundedPanel(vg, rx_cur, by, bw, 44.0f, tl, tr, br, bl,
                         active ? theme_.primary_container : theme_.surface_high);
        DrawTextClipped(vg, rx_cur + bw * 0.5f, by + 22.0f, bw - 12.0f, font_semibold_, 13.5f,
                        active ? theme_.on_primary_container : theme_.on_surface_variant,
                        NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, kRoutes[i]);
        PushHit(rx_cur, by, bw, 44.0f, HitAction::SetRoute, i, 0, true, tl, tr, br, bl);
        rx_cur += bw + 3.0f;
    }

    const bool quic_prot = is_conn && settings_.routing_mode != RoutingMode::Direct && settings_.block_quic;
    const float qx = kWorkX + kCenterW - 14.0f - 188.0f;
    DrawRoundedBox(vg, qx, by, 188.0f, 44.0f, 22.0f, quic_prot ? theme_.primary_container : theme_.surface_high);
    DrawVectorIcon(vg, UiIcon::Block, qx + 22.0f, by + 22.0f, 16.0f,
                   quic_prot ? theme_.on_primary_container : theme_.on_surface_variant);
    DrawTextClipped(vg, qx + 38.0f, by + 22.0f, 138.0f, font_semibold_, 13.0f,
                    quic_prot ? theme_.on_primary_container : theme_.on_surface_variant,
                    NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, settings_.block_quic ? "YouTube · QUIC блок" : "UDP 443 открыт");
    PushHit(qx, by, 188.0f, 44.0f, HitAction::GotoRules, 0, 0, true, 22.0f, 22.0f, 22.0f, 22.0f);

    // Right column: Hero Connect Slab + Segmented 28/8/4px Stack
    constexpr float kHeroH = 466.0f;
    const float hero_r = is_conn ? 36.0f : 178.0f;
    const ColorRgba hero_bg = is_conn ? theme_.surface
                            : is_busy ? theme_.primary_container
                            : is_fail ? theme_.error_container : theme_.primary;
    const ColorRgba hero_fg = is_conn ? theme_.primary
                            : is_busy ? theme_.primary
                            : is_fail ? theme_.on_error_container : theme_.on_primary;
    DrawRoundedBox(vg, kRightX, kWorkY, kRightW, kHeroH, hero_r, hero_bg);
    if (is_conn) DrawFocusStroke(vg, kRightX, kWorkY, kRightW, kHeroH, hero_r, hero_r, hero_r, hero_r, theme_.primary, 3.0f);
    if (is_fail) DrawFocusStroke(vg, kRightX, kWorkY, kRightW, kHeroH, hero_r, hero_r, hero_r, hero_r, theme_.error, 3.0f);

    const float hcx = kRightX + kRightW * 0.5f;
    const float hcy = kWorkY + kHeroH * 0.5f;
    if (is_busy) {
        DrawShapeSpinner(vg, hcx, hcy - 34.0f, 29.0f, static_cast<float>(anim_sec_), hero_fg);
    } else {
        DrawVectorIcon(vg, is_conn ? UiIcon::Pause : (is_fail ? UiIcon::Error : UiIcon::Power),
                       hcx, hcy - 34.0f, 52.0f, hero_fg);
    }
    const char* hlbl = is_conn ? "Отключить" : is_busy ? "Подключаем" : is_fail ? "Повторить" : "Подключить";
    DrawTextClipped(vg, hcx, hcy + 24.0f, kRightW - 40.0f, font_display_, 31.0f, hero_fg,
                    NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, hlbl);
    char hsub[64];
    if (is_conn) {
        std::snprintf(hsub, sizeof(hsub), "%s · %s",
                      FormatDuration(ActiveConnectedSeconds()).c_str(), srv.transport_label.c_str());
    } else {
        std::snprintf(hsub, sizeof(hsub), "%s · %s", srv.proto_label.c_str(), srv.transport_label.c_str());
    }
    DrawTextClipped(vg, hcx, hcy + 60.0f, kRightW - 40.0f, font_mono_, 14.0f, hero_fg.WithAlpha(220),
                    NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, hsub);
    PushHit(kRightX, kWorkY, kRightW, kHeroH, HitAction::ToggleTunnel, 0, 0, true, hero_r, hero_r, hero_r, hero_r);

    // Segmented stack card 1: Active Server
    const float c1y = kWorkY + kHeroH + 12.0f;
    constexpr float kCard1H = 98.0f;
    DrawRoundedPanel(vg, kRightX, c1y, kRightW, kCard1H, 28.0f, 28.0f, 8.0f, 8.0f, theme_.surface_container);
    DrawTextClipped(vg, kRightX + 18.0f, c1y + 20.0f, 180.0f, font_semibold_, 10.5f,
                    theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "АКТИВНЫЙ СЕРВЕР");
    DrawTextClipped(vg, kRightX + kRightW - 18.0f, c1y + 20.0f, 120.0f, font_semibold_, 10.5f,
                    theme_.on_surface_variant, NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, "СМЕНИТЬ ->");
    DrawTextClipped(vg, kRightX + 18.0f, c1y + 47.0f, kRightW - 36.0f, font_semibold_, 16.0f,
                    theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, srv.name.c_str());
    char srv_meta[64];
    std::snprintf(srv_meta, sizeof(srv_meta), "%s · %s · %s",
                  srv.proto_label.c_str(), srv.transport_label.c_str(), srv.flow_label.c_str());
    DrawTextClipped(vg, kRightX + 18.0f, c1y + 74.0f, kRightW - 96.0f, font_mono_, 12.0f,
                    theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, srv_meta);
    char ping_s[16];
    if (srv.ping_ms >= 0) std::snprintf(ping_s, sizeof(ping_s), "%d ms", srv.ping_ms);
    else std::snprintf(ping_s, sizeof(ping_s), "—");
    DrawTextClipped(vg, kRightX + kRightW - 18.0f, c1y + 74.0f, 70.0f, font_mono_, 12.5f,
                    LatencyColorFor(theme_, srv.ping_ms), NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, ping_s);
    PushHit(kRightX, c1y, kRightW, kCard1H, HitAction::GotoServers, 0, 0, true, 28.0f, 28.0f, 8.0f, 8.0f);

    // Segmented stack card 2: RAM sysmodule
    const float c2y = c1y + kCard1H + 4.0f;
    constexpr float kCard2H = 100.0f;
    DrawRoundedPanel(vg, kRightX, c2y, kRightW, kCard2H, 8.0f, 8.0f, 28.0f, 28.0f, theme_.surface_container);
    DrawTextClipped(vg, kRightX + 18.0f, c2y + 20.0f, 160.0f, font_semibold_, 10.5f,
                    theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "RAM SYSMODULE");
    const char* hos_lbl = (version_info_.hos_generation == ipc::HosGeneration::Hos19) ? "HOS 19.x" : "HOS 20.0+";
    DrawTextClipped(vg, kRightX + kRightW - 18.0f, c2y + 20.0f, 100.0f, font_semibold_, 10.5f,
                    theme_.on_surface_variant, NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, hos_lbl);
    const double used_mb = ctl_connected_
        ? (static_cast<double>(stats_.sysmodule_heap_used_bytes) / (1024.0 * 1024.0))
        : 0.0;
    const double total_mb = (ctl_connected_ && stats_.sysmodule_heap_total_bytes > 0)
        ? (static_cast<double>(stats_.sysmodule_heap_total_bytes) / (1024.0 * 1024.0))
        : 1.5;
    const float ratio = ctl_connected_
        ? static_cast<float>(std::clamp(used_mb / std::max(0.5, total_mb), 0.0, 1.0))
        : 0.0f;
    char ram_buf[48], pct_buf[16];
    if (ctl_connected_) {
        std::snprintf(ram_buf, sizeof(ram_buf), "%.2f / %.1f MB", used_mb, total_mb);
        std::snprintf(pct_buf, sizeof(pct_buf), "%d%%", static_cast<int>(std::round(ratio * 100.0f)));
    } else {
        std::snprintf(ram_buf, sizeof(ram_buf), "sysmodule выкл");
        std::snprintf(pct_buf, sizeof(pct_buf), "—");
    }
    DrawTextClipped(vg, kRightX + 18.0f, c2y + 49.0f, 210.0f, font_mono_, 18.0f,
                    theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, ram_buf);
    DrawTextClipped(vg, kRightX + kRightW - 18.0f, c2y + 49.0f, 70.0f, font_mono_, 13.0f,
                    theme_.tertiary, NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, pct_buf);
    DrawRoundedBox(vg, kRightX + 18.0f, c2y + 73.0f, kRightW - 36.0f, 8.0f, 4.0f, theme_.surface_highest);
    DrawRoundedBox(vg, kRightX + 18.0f, c2y + 73.0f, (kRightW - 36.0f) * ratio, 8.0f, 4.0f, theme_.primary);
}

void YumiUiApp::RenderServersTab(NVGcontext* vg) {
    const auto flt_indices = FilteredServerIndices();
    char sub[128];
    std::snprintf(sub, sizeof(sub), "Доступно %zu из %zu узлов", flt_indices.size(), servers_.size());
    RenderTopBar(vg, "Серверы", sub, true);

    // Filter row
    static constexpr const char* kProtos[6] = {"Все", "VLESS", "WireGuard", "Hysteria2", "Trojan", "SS"};
    static constexpr float kProtoW[6] = {60.0f, 76.0f, 102.0f, 96.0f, 78.0f, 54.0f};
    float fx = kWorkX;
    const float fy = kWorkY + 56.0f;
    for (int i = 0; i < 6; ++i) {
        const bool active = proto_filter_ == i;
        float tl, tr, br, bl;
        DrawCbgRadii(i, 6, active, 18.0f, tl, tr, br, bl);
        DrawRoundedPanel(vg, fx, fy, kProtoW[i], 36.0f, tl, tr, br, bl,
                         active ? theme_.primary_container : theme_.surface_container);
        DrawTextClipped(vg, fx + kProtoW[i] * 0.5f, fy + 18.0f, kProtoW[i] - 8.0f, font_semibold_, 12.5f,
                        active ? theme_.on_primary_container : theme_.on_surface_variant,
                        NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, kProtos[i]);
        PushHit(fx, fy, kProtoW[i], 36.0f, HitAction::FilterProto, i, 0, true, tl, tr, br, bl);
        fx += kProtoW[i] + 3.0f;
    }

    // Outlined [X] Замерить все (N)
    const float px = kWorkX + kWorkW - 194.0f;
    DrawRoundedBox(vg, px, fy, 194.0f, 36.0f, 18.0f, theme_.surface);
    DrawFocusStroke(vg, px, fy, 194.0f, 36.0f, 18.0f, 18.0f, 18.0f, 18.0f, theme_.outline, 1.5f);
    DrawKeycap(vg, px + 22.0f, fy + 18.0f, "X", theme_.surface_highest, theme_.on_surface, font_mono_);
    DrawVectorIcon(vg, UiIcon::Ping, px + 46.0f, fy + 18.0f, 16.0f, theme_.on_surface);
    char meas_lbl[48];
    std::snprintf(meas_lbl, sizeof(meas_lbl), "Замерить все (%zu)", flt_indices.size());
    DrawTextClipped(vg, px + 62.0f, fy + 18.0f, 122.0f, font_semibold_, 13.0f,
                    theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, meas_lbl);
    PushHit(px, fy, 194.0f, 36.0f, HitAction::PingAll, 0, 0, true, 18.0f, 18.0f, 18.0f, 18.0f);

    // Master-detail split (43% / 57%)
    constexpr float kSplitY = kWorkY + 106.0f;
    constexpr float kSplitH = kWorkH - 106.0f;  // 574px
    constexpr float kListW = 478.0f;
    constexpr float kInspX = kWorkX + kListW + 16.0f;
    constexpr float kInspW = kWorkW - kListW - 16.0f;

    // Scrollable segmented node list
    nvgSave(vg);
    nvgIntersectScissor(vg, kWorkX, kSplitY, kListW, kSplitH);
    const float max_scroll = std::max(0.0f, static_cast<float>(flt_indices.size()) * 78.0f - kSplitH);
    list_scroll_servers_ = std::min(list_scroll_servers_, max_scroll);
    for (size_t pos = 0; pos < flt_indices.size(); ++pos) {
        const int idx = flt_indices[pos];
        const auto& n = servers_[static_cast<size_t>(idx)];
        const float ry = kSplitY + static_cast<float>(pos) * 78.0f - list_scroll_servers_;
        if (ry + 74.0f < kSplitY || ry > kSplitY + kSplitH) continue;

        const bool sel = (idx == inspected_node_idx_);
        const bool live = (n.id == status_.active_node_id && status_.state == TunnelState::On);
        float tl, tr, br, bl;
        DrawStackRadii(static_cast<int>(pos), static_cast<int>(flt_indices.size()), 26.0f, tl, tr, br, bl);
        DrawRoundedPanel(vg, kWorkX, ry, kListW, 74.0f, tl, tr, br, bl,
                         sel ? theme_.primary_container : theme_.surface_high);
        if (sel) DrawFocusStroke(vg, kWorkX, ry, kListW, 74.0f, tl, tr, br, bl, theme_.primary, 3.0f);

        DrawRoundedBox(vg, kWorkX + 15.0f, ry + 18.0f, 38.0f, 38.0f, 12.0f, theme_.surface_highest);
        DrawTextClipped(vg, kWorkX + 34.0f, ry + 37.0f, 34.0f, font_mono_, 13.0f, theme_.on_surface,
                        NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, n.cc.c_str());

        DrawTextClipped(vg, kWorkX + 65.0f, ry + 26.0f, kListW - 154.0f, font_semibold_, 15.0f,
                        sel ? theme_.on_primary_container : theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, n.name.c_str());
        char sub_line[64];
        std::snprintf(sub_line, sizeof(sub_line), "%s · %s", n.proto_label.c_str(), n.transport_label.c_str());
        DrawTextClipped(vg, kWorkX + 65.0f, ry + 49.0f, kListW - 154.0f, font_regular_, 12.5f,
                        sel ? theme_.on_primary_container.WithAlpha(210) : theme_.on_surface_variant,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, sub_line);

        if (live) {
            nvgBeginPath(vg);
            nvgCircle(vg, kWorkX + kListW - 74.0f, ry + 37.0f, 4.5f);
            nvgFillColor(vg, Nvg(theme_.primary));
            nvgFill(vg);
        }
        char pbuf[16];
        if (n.ping_ms >= 0) std::snprintf(pbuf, sizeof(pbuf), "%d ms", n.ping_ms);
        else std::snprintf(pbuf, sizeof(pbuf), "—");
        DrawTextClipped(vg, kWorkX + kListW - 16.0f, ry + 37.0f, 64.0f, font_mono_, 14.0f,
                        LatencyColorFor(theme_, n.ping_ms), NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, pbuf);
        PushHit(kWorkX, ry, kListW, 74.0f, HitAction::InspectNode, idx, 0, true, tl, tr, br, bl);
    }
    nvgRestore(vg);

    // Right inspector card
    const int safe_idx = std::clamp(inspected_node_idx_, 0, static_cast<int>(servers_.size()) - 1);
    const auto& insp = servers_[static_cast<size_t>(safe_idx)];
    const bool is_live = (insp.id == status_.active_node_id && status_.state == TunnelState::On);

    DrawRoundedBox(vg, kInspX, kSplitY, kInspW, kSplitH, 28.0f, theme_.surface_high);
    const float ix = kInspX + 24.0f;
    const float iw = kInspW - 48.0f;

    DrawRoundedBox(vg, ix, kSplitY + 28.0f, 50.0f, 50.0f, 16.0f, theme_.surface_highest);
    DrawTextClipped(vg, ix + 25.0f, kSplitY + 53.0f, 44.0f, font_mono_, 16.0f, theme_.on_surface,
                    NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, insp.cc.c_str());
    DrawTextClipped(vg, ix + 64.0f, kSplitY + 41.0f, iw - 200.0f, font_display_, 23.0f,
                    theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, insp.name.c_str());
    char insp_sub[96];
    std::snprintf(insp_sub, sizeof(insp_sub), "%s%s", is_live ? "Живой туннель · " : "", insp.sub_name.c_str());
    DrawTextClipped(vg, ix + 64.0f, kSplitY + 69.0f, iw - 200.0f, font_regular_, 13.5f,
                    is_live ? theme_.primary : theme_.on_surface_variant,
                    NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, insp_sub);

    // Ping box top-right of inspector
    const float pb_x = ix + iw - 122.0f;
    DrawRoundedBox(vg, pb_x, kSplitY + 24.0f, 122.0f, 62.0f, 18.0f, theme_.surface_container);
    char ping_big[16];
    if (insp.ping_ms >= 0) std::snprintf(ping_big, sizeof(ping_big), "%d ms", insp.ping_ms);
    else std::snprintf(ping_big, sizeof(ping_big), "—");
    DrawTextClipped(vg, pb_x + 106.0f, kSplitY + 46.0f, 100.0f, font_mono_, 23.0f,
                    LatencyColorFor(theme_, insp.ping_ms), NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, ping_big);
    const char* p_lbl = (insp.ping_ms < 0) ? "Не проверен" : (insp.ping_ms <= 65 ? "Отлично" : "Стабильно");
    DrawTextClipped(vg, pb_x + 106.0f, kSplitY + 71.0f, 100.0f, font_regular_, 11.5f,
                    theme_.on_surface_variant, NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, p_lbl);

    // 2x2 Spec cells
    const float cell_w = (iw - 4.0f) * 0.5f;
    constexpr float kCellH = 88.0f;
    const float gy = kSplitY + 124.0f;
    const std::string eff_utls = (settings_.tls_fingerprint == TlsFingerprint::Auto)
        ? insp.utls : UtlsLabel(settings_.tls_fingerprint);
    char spec1[64], spec2[96], spec4[96];
    std::snprintf(spec1, sizeof(spec1), "%s · %s · %s", insp.proto_label.c_str(), insp.transport_label.c_str(), insp.flow_label.c_str());
    std::snprintf(spec2, sizeof(spec2), "%s · %s", insp.sni.c_str(), eff_utls.c_str());
    std::snprintf(spec4, sizeof(spec4), "%s · %s%s", ModeLabel(settings_.routing_mode),
                  settings_.block_quic ? "Блок QUIC" : "UDP открыт", settings_.resolve_server_address ? " · DoH" : "");

    const char* keys[4] = {"Протокол и транспорт", "SNI и отпечаток uTLS", "Конечная точка (Endpoint)", "Маршрут ядра core-net"};
    const char* vals[4] = {spec1, spec2, insp.endpoint.c_str(), spec4};
    for (int i = 0; i < 4; ++i) {
        const int col = i % 2;
        const int row = i / 2;
        const float cx = ix + col * (cell_w + 4.0f);
        const float cy = gy + row * (kCellH + 4.0f);
        const float tl = (i == 0) ? 20.0f : 8.0f;
        const float tr = (i == 1) ? 20.0f : 8.0f;
        const float bl = (i == 2) ? 20.0f : 8.0f;
        const float br = (i == 3) ? 20.0f : 8.0f;
        DrawRoundedPanel(vg, cx, cy, cell_w, kCellH, tl, tr, br, bl, theme_.surface_container);
        DrawTextClipped(vg, cx + 16.0f, cy + 28.0f, cell_w - 32.0f, font_regular_, 12.0f,
                        theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, keys[i]);
        DrawTextClipped(vg, cx + 16.0f, cy + 56.0f, cell_w - 32.0f, (i == 1 || i == 2) ? font_mono_ : font_semibold_,
                        14.5f, theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, vals[i]);
    }

    // Fragmentation / coords strip
    const float sy = gy + 2 * kCellH + 28.0f;
    DrawRoundedBox(vg, ix, sy, iw, 44.0f, 16.0f, theme_.surface_container);
    char frag_s[64], coords_s[48];
    std::snprintf(frag_s, sizeof(frag_s), "Фрагментация пакетов: %s", FragLabel(settings_.fragment_mode));
    std::snprintf(coords_s, sizeof(coords_s), "coords: %.2f, %.2f", insp.lat_deg, insp.lon_deg);
    DrawTextClipped(vg, ix + 16.0f, sy + 22.0f, iw * 0.6f, font_regular_, 12.5f, theme_.on_surface_variant,
                    NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, frag_s);
    DrawTextClipped(vg, ix + iw - 16.0f, sy + 22.0f, iw * 0.35f, font_mono_, 12.5f, theme_.on_surface_variant,
                    NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, coords_s);

    // Bottom primary CTA buttons
    const float by = kSplitY + kSplitH - 22.0f - 50.0f;
    const float ping_btn_w = 162.0f;
    const float conn_btn_w = iw - ping_btn_w - 12.0f;
    DrawRoundedBox(vg, ix, by, conn_btn_w, 50.0f, 25.0f, theme_.primary);
    DrawKeycap(vg, ix + 28.0f, by + 25.0f, "A", theme_.primary_container, theme_.on_primary_container, font_mono_);
    DrawTextClipped(vg, ix + conn_btn_w * 0.5f + 10.0f, by + 25.0f, conn_btn_w - 60.0f, font_semibold_, 15.0f,
                    theme_.on_primary, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE,
                    is_live ? "Подключён сейчас (активный)" : "Подключить сюда");
    PushHit(ix, by, conn_btn_w, 50.0f, HitAction::ConnectNode, safe_idx, 0, true, 25.0f, 25.0f, 25.0f, 25.0f);

    const float pbx = ix + conn_btn_w + 12.0f;
    DrawRoundedBox(vg, pbx, by, ping_btn_w, 50.0f, 25.0f, theme_.surface_highest);
    DrawKeycap(vg, pbx + 24.0f, by + 25.0f, "X", theme_.surface_container, theme_.on_surface, font_mono_);
    DrawVectorIcon(vg, UiIcon::Ping, pbx + 50.0f, by + 25.0f, 18.0f, theme_.on_surface);
    DrawTextClipped(vg, pbx + 66.0f, by + 25.0f, ping_btn_w - 76.0f, font_semibold_, 14.5f,
                    theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Пинг узла");
    PushHit(pbx, by, ping_btn_w, 50.0f, HitAction::PingOne, safe_idx, 0, true, 25.0f, 25.0f, 25.0f, 25.0f);
}

void YumiUiApp::RenderSubsTab(NVGcontext* vg) {
    int total_nodes = 0;
    for (const auto& s : subs_) total_nodes += s.node_total;
    char sub[128];
    std::snprintf(sub, sizeof(sub), "Профилей: %zu · Всего узлов: %d · Авто 12 ч", subs_.size(), total_nodes);
    RenderTopBar(vg, "Подписки и QR", sub, true);

    constexpr float kSplitY = kWorkY + 58.0f;
    constexpr float kSplitH = kWorkH - 58.0f;  // 622px
    constexpr float kLeftW = 436.0f;
    constexpr float kRightX = kWorkX + kLeftW + 16.0f;
    constexpr float kRightW = kWorkW - kLeftW - 16.0f;  // 678px

    // Left: subscriptions segmented list + SD import button
    float cy = kSplitY;
    for (size_t i = 0; i < subs_.size() && i < 4; ++i) {
        const auto& s = subs_[i];
        constexpr float kH = 114.0f;
        float tl, tr, br, bl;
        DrawStackRadii(static_cast<int>(i), static_cast<int>(std::min<size_t>(subs_.size(), 4)), 26.0f, tl, tr, br, bl);
        DrawRoundedPanel(vg, kWorkX, cy, kLeftW, kH, tl, tr, br, bl, theme_.surface_high);

        const ColorRgba title_c = s.enabled ? theme_.on_surface : theme_.on_surface.WithAlpha(125);
        DrawTextClipped(vg, kWorkX + 18.0f, cy + 25.0f, kLeftW - 134.0f, font_semibold_, 15.5f,
                        title_c, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, s.name.c_str());
        DrawTextClipped(vg, kWorkX + 18.0f, cy + 47.0f, kLeftW - 134.0f, font_mono_, 12.0f,
                        theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, s.url.c_str());

        // Refresh + Switch
        const float rbx = kWorkX + kLeftW - 116.0f;
        DrawRoundedBox(vg, rbx, cy + 16.0f, 38.0f, 38.0f, 14.0f, theme_.surface_highest);
        DrawVectorIcon(vg, UiIcon::Refresh, rbx + 19.0f, cy + 35.0f, 18.0f, theme_.on_surface);
        PushHit(rbx, cy + 16.0f, 38.0f, 38.0f, HitAction::RefreshSub, static_cast<int>(i), 0, true, 14.0f, 14.0f, 14.0f, 14.0f);

        const float swx = kWorkX + kLeftW - 70.0f;
        DrawM3Switch(vg, swx, cy + 20.0f, s.enabled, theme_);
        PushHit(swx, cy + 20.0f, 54.0f, 30.0f, HitAction::ToggleSub, static_cast<int>(i), 0, true, 15.0f, 15.0f, 15.0f, 15.0f);

        char stats_line[80];
        if (s.limit_gb > 0) {
            std::snprintf(stats_line, sizeof(stats_line), "%d узлов · %d / %d ГБ · %s",
                          s.node_total, s.used_gb, s.limit_gb, s.expires.c_str());
        } else {
            std::snprintf(stats_line, sizeof(stats_line), "%d узлов · %s", s.node_total, s.expires.c_str());
        }
        DrawTextClipped(vg, kWorkX + 18.0f, cy + 75.0f, kLeftW - 36.0f, font_mono_, 12.5f,
                        theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, stats_line);

        const float fill_frac = (s.limit_gb > 0) ? std::clamp(static_cast<float>(s.used_gb) / s.limit_gb, 0.05f, 1.0f) : 1.0f;
        DrawRoundedBox(vg, kWorkX + 18.0f, cy + 93.0f, kLeftW - 36.0f, 8.0f, 4.0f, theme_.surface_lowest);
        DrawRoundedBox(vg, kWorkX + 18.0f, cy + 93.0f, (kLeftW - 36.0f) * fill_frac, 8.0f, 4.0f,
                       (s.limit_gb > 0) ? theme_.primary : theme_.tertiary);
        cy += kH + 4.0f;
    }

    const float sd_y = kSplitY + kSplitH - 50.0f;
    DrawRoundedBox(vg, kWorkX, sd_y, kLeftW, 50.0f, 25.0f, theme_.primary_container);
    DrawKeycap(vg, kWorkX + 28.0f, sd_y + 25.0f, "Y", theme_.surface_highest, theme_.on_surface, font_mono_);
    DrawVectorIcon(vg, UiIcon::Sd, kWorkX + 54.0f, sd_y + 25.0f, 18.0f, theme_.on_primary_container);
    DrawTextClipped(vg, kWorkX + 72.0f, sd_y + 25.0f, kLeftW - 88.0f, font_semibold_, 14.5f,
                    theme_.on_primary_container, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Добавить из файла (SD) · import.txt");
    PushHit(kWorkX, sd_y, kLeftW, 50.0f, HitAction::SdImport, 0, 0, true, 25.0f, 25.0f, 25.0f, 25.0f);

    // Right: QR pairing wizard
    DrawRoundedBox(vg, kRightX, kSplitY, kRightW, kSplitH, 28.0f, theme_.surface_high);
    const float qx = kRightX + 24.0f;
    const float qy = kSplitY + 88.0f;
    const float qw = kRightW - 48.0f - 216.0f - 18.0f;  // 376px

    DrawRoundedBox(vg, qx, qy, 206.0f, 28.0f, 14.0f, theme_.tertiary_container);
    DrawVectorIcon(vg, UiIcon::Lock, qx + 16.0f, qy + 14.0f, 14.0f, theme_.on_tertiary_container);
    DrawTextClipped(vg, qx + 28.0f, qy + 14.0f, 170.0f, font_mono_, 11.5f,
                    theme_.on_tertiary_container, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "ECDH P-256 · AES-256-GCM");

    DrawTextClipped(vg, qx, qy + 52.0f, qw, font_display_, 21.0f, theme_.on_surface,
                    NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Передача подписки с телефона");
    DrawTextClipped(vg, qx, qy + 76.0f, qw, font_regular_, 12.5f, theme_.on_surface_variant,
                    NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Из Android-приложения Yumi · без клавиатуры Switch");

    static constexpr const char* kSteps[3] = {
        "Откройте Yumi на телефоне и выберите профиль",
        "Нажмите «Отправить на Switch» и наведите камеру",
        "Подтвердите передачу — подписка появится слева",
    };
    float sy = qy + 102.0f;
    for (int i = 0; i < 3; ++i) {
        DrawRoundedBox(vg, qx, sy, qw, 44.0f, 14.0f, theme_.surface_container);
        DrawRoundedBox(vg, qx + 10.0f, sy + 10.0f, 24.0f, 24.0f, 12.0f, theme_.primary_container);
        char num[4];
        std::snprintf(num, sizeof(num), "%d", i + 1);
        DrawTextClipped(vg, qx + 22.0f, sy + 22.0f, 18.0f, font_mono_, 12.0f,
                        theme_.on_primary_container, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, num);
        DrawTextClipped(vg, qx + 42.0f, sy + 22.0f, qw - 50.0f, font_regular_, 12.0f,
                        theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, kSteps[i]);
        sy += 52.0f;
    }

    // Pairing endpoint bar
    sy += 8.0f;
    DrawRoundedBox(vg, qx, sy, qw, 42.0f, 14.0f, theme_.surface_container);
    const auto psnap = pairing_server_.Snapshot();
    const uint16_t pport = (psnap.port > 0) ? psnap.port : logic::kRemoteDefaultPort;
    const std::string ep_str = lan_ip_ + ":" + std::to_string(pport);
    DrawTextClipped(vg, qx + 14.0f, sy + 21.0f, 150.0f, font_mono_, 12.5f,
                    theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, ep_str.c_str());
    DrawTextClipped(vg, qx + qw - 14.0f, sy + 21.0f, 200.0f, font_regular_, 12.5f,
                    phone_scanned_ ? theme_.latency_fast : theme_.primary, NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE,
                    phone_scanned_ ? "Подписка добавлена" : psnap.status_message.empty()
                        ? "Сессия активна · ждём камеру" : psnap.status_message.c_str());

    // Simulate scan button
    const float bty = sy + 56.0f;
    DrawRoundedBox(vg, qx, bty, qw, 50.0f, 25.0f, theme_.primary);
    DrawVectorIcon(vg, UiIcon::Phone, qx + qw * 0.5f - 128.0f, bty + 25.0f, 18.0f, theme_.on_primary);
    DrawTextClipped(vg, qx + qw * 0.5f + 12.0f, bty + 25.0f, qw - 52.0f, font_semibold_, 14.5f,
                    theme_.on_primary, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE,
                    phone_scanned_ ? "Обновить QR-код сессии" : "Симулировать скан с телефона");
    PushHit(qx, bty, qw, 50.0f, HitAction::SimScan, 0, 0, true, 25.0f, 25.0f, 25.0f, 25.0f);

    // Right QR code matrix plate
    const float qpx = kRightX + kRightW - 24.0f - 216.0f;
    const float qpy = kSplitY + (kSplitH - 242.0f) * 0.5f;
    DrawQrPlate(vg, qpx, qpy, 216.0f, 20.0f, qr_pair_);
    DrawTextClipped(vg, qpx + 108.0f, qpy + 232.0f, 216.0f, font_mono_, 11.5f,
                    theme_.on_surface_variant, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, "yumi://pair · Локальный TLS");
}

void YumiUiApp::RenderRulesTab(NVGcontext* vg) {
    char sub[64];
    std::snprintf(sub, sizeof(sub), "Режим: %s · Своих правил: %d", ModeLabel(settings_.routing_mode), CountCustomRules());
    RenderTopBar(vg, "Правила и журнал", sub, false);

    // Filter CBG + +Событие top-right
    static constexpr const char* kFlt[4] = {"Все", "VPN", "Напрямую", "Блок"};
    static constexpr float kFltW[4] = {54.0f, 58.0f, 88.0f, 60.0f};
    float fx = kWorkX + kWorkW - 114.0f - 8.0f - 269.0f;
    const float fy = kWorkY + 5.0f;
    for (int i = 0; i < 4; ++i) {
        const bool act = log_filter_ == i;
        float tl, tr, br, bl;
        DrawCbgRadii(i, 4, act, 17.0f, tl, tr, br, bl);
        DrawRoundedPanel(vg, fx, fy, kFltW[i], 36.0f, tl, tr, br, bl,
                         act ? theme_.primary_container : theme_.surface_container);
        DrawTextClipped(vg, fx + kFltW[i] * 0.5f, fy + 18.0f, kFltW[i] - 8.0f, font_semibold_, 12.5f,
                        act ? theme_.on_primary_container : theme_.on_surface_variant,
                        NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, kFlt[i]);
        PushHit(fx, fy, kFltW[i], 36.0f, HitAction::SetLogFilter, i, 0, true, tl, tr, br, bl);
        fx += kFltW[i] + 3.0f;
    }

    const float sx = kWorkX + kWorkW - 114.0f;
    DrawRoundedBox(vg, sx, fy, 114.0f, 36.0f, 18.0f, theme_.primary_container);
    DrawVectorIcon(vg, UiIcon::Plus, sx + 20.0f, fy + 18.0f, 16.0f, theme_.on_primary_container);
    DrawTextClipped(vg, sx + 34.0f, fy + 18.0f, 74.0f, font_semibold_, 13.0f,
                    theme_.on_primary_container, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Событие");
    PushHit(sx, fy, 114.0f, 36.0f, HitAction::SimLog, 0, 0, true, 18.0f, 18.0f, 18.0f, 18.0f);

    constexpr float kSplitY = kWorkY + 58.0f;
    constexpr float kSplitH = kWorkH - 58.0f;  // 622px
    constexpr float kLeftW = 622.0f;
    constexpr float kRightX = kWorkX + kLeftW + 16.0f;
    constexpr float kRightW = kWorkW - kLeftW - 16.0f;  // 492px

    // Left: Connection Log pane
    DrawRoundedBox(vg, kWorkX, kSplitY, kLeftW, kSplitH, 28.0f, theme_.surface_low);
    std::vector<int> vis_logs;
    for (size_t i = 0; i < logs_.size(); ++i) {
        if (log_filter_ == 0 ||
            (log_filter_ == 1 && logs_[i].route_action == 0) ||
            (log_filter_ == 2 && logs_[i].route_action == 1) ||
            (log_filter_ == 3 && logs_[i].route_action == 2)) {
            vis_logs.push_back(static_cast<int>(i));
        }
    }
    char lhead[96];
    std::snprintf(lhead, sizeof(lhead), "Журнал соединений (%zu)", vis_logs.size());
    DrawTextClipped(vg, kWorkX + 18.0f, kSplitY + 28.0f, 280.0f, font_display_, 18.5f,
                    theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, lhead);
    DrawRoundedBox(vg, kWorkX + kLeftW - 258.0f, kSplitY + 12.0f, 240.0f, 32.0f, 16.0f, theme_.surface_container);
    DrawTextClipped(vg, kWorkX + kLeftW - 138.0f, kSplitY + 28.0f, 224.0f, font_semibold_, 12.0f,
                    theme_.on_surface_variant, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, "Нажмите кнопку маршрута в строке");

    const float list_y = kSplitY + 56.0f;
    const float list_h = kSplitH - 72.0f;
    nvgSave(vg);
    nvgIntersectScissor(vg, kWorkX + 14.0f, list_y, kLeftW - 28.0f, list_h);
    const float max_ls = std::max(0.0f, static_cast<float>(vis_logs.size()) * 94.0f - list_h);
    list_scroll_logs_ = std::min(list_scroll_logs_, max_ls);
    for (size_t pos = 0; pos < vis_logs.size(); ++pos) {
        const int idx = vis_logs[pos];
        const auto& l = logs_[static_cast<size_t>(idx)];
        const float iy = list_y + static_cast<float>(pos) * 94.0f - list_scroll_logs_;
        if (iy + 90.0f < list_y || iy > list_y + list_h) continue;

        float tl, tr, br, bl;
        DrawStackRadii(static_cast<int>(pos), static_cast<int>(vis_logs.size()), 22.0f, tl, tr, br, bl);
        DrawRoundedPanel(vg, kWorkX + 16.0f, iy, kLeftW - 32.0f, 90.0f, tl, tr, br, bl, theme_.surface_container);

        char hp[128], meta[96];
        std::snprintf(hp, sizeof(hp), "%s:%u", l.host.c_str(), l.port);
        std::snprintf(meta, sizeof(meta), "%s · %s · %s", l.proto.c_str(), l.app_name.c_str(), l.time_str.c_str());
        DrawTextClipped(vg, kWorkX + 30.0f, iy + 22.0f, kLeftW - 190.0f, font_mono_, 13.5f,
                        theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, hp);
        DrawTextClipped(vg, kWorkX + 30.0f, iy + 40.0f, kLeftW - 190.0f, font_regular_, 12.0f,
                        theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, meta);

        const ColorRgba tag_bg = (l.route_action == 0) ? theme_.primary_container
                               : (l.route_action == 1) ? theme_.tertiary_container : theme_.error_container;
        const ColorRgba tag_fg = (l.route_action == 0) ? theme_.on_primary_container
                               : (l.route_action == 1) ? theme_.on_tertiary_container : theme_.on_error_container;
        DrawRoundedBox(vg, kWorkX + kLeftW - 134.0f, iy + 14.0f, 104.0f, 24.0f, 12.0f, tag_bg);
        DrawTextClipped(vg, kWorkX + kLeftW - 82.0f, iy + 26.0f, 94.0f, font_semibold_, 11.0f,
                        tag_fg, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, l.badge.c_str());

        // 3-way inline action buttons
        static constexpr const char* kAct[3] = {"Через VPN", "Напрямую", "Блок"};
        const float bw = (kLeftW - 60.0f - 6.0f) / 3.0f;
        const float b_y = iy + 52.0f;
        for (int a = 0; a < 3; ++a) {
            const float bx = kWorkX + 30.0f + static_cast<float>(a) * (bw + 3.0f);
            const bool sel = (l.route_action == a);
            float bt_tl, bt_tr, bt_br, bt_bl;
            DrawCbgRadii(a, 3, sel, 16.0f, bt_tl, bt_tr, bt_br, bt_bl);
            const ColorRgba fill = sel ? (a == 0 ? theme_.primary : (a == 1 ? theme_.secondary : theme_.error)) : theme_.surface_high;
            const ColorRgba fg = sel ? (a == 0 ? theme_.on_primary : (a == 1 ? theme_.on_secondary : theme_.on_error)) : theme_.on_surface_variant;
            DrawRoundedPanel(vg, bx, b_y, bw, 30.0f, bt_tl, bt_tr, bt_br, bt_bl, fill);
            DrawTextClipped(vg, bx + bw * 0.5f, b_y + 15.0f, bw - 8.0f, font_semibold_, 12.0f,
                            fg, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, kAct[a]);
            PushHit(bx, b_y, bw, 30.0f, HitAction::AddRule, idx, a, true, bt_tl, bt_tr, bt_br, bt_bl);
        }
    }
    nvgRestore(vg);

    // Right top: CustomRules pane
    constexpr float kTopH = 382.0f;
    DrawRoundedBox(vg, kRightX, kSplitY, kRightW, kTopH, 28.0f, theme_.surface_low);
    DrawTextClipped(vg, kRightX + 18.0f, kSplitY + 26.0f, 340.0f, font_display_, 18.5f,
                    theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Свои правила (CustomRules)");
    char rcnt[24];
    std::snprintf(rcnt, sizeof(rcnt), "%d активн.", CountCustomRules());
    DrawTextClipped(vg, kRightX + kRightW - 18.0f, kSplitY + 26.0f, 90.0f, font_mono_, 12.5f,
                    theme_.on_surface_variant, NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, rcnt);

    const float b_bw = (kRightW - 36.0f - 6.0f) / 3.0f;
    const float b_by = kSplitY + 52.0f;
    const size_t counts[3] = {settings_.custom_rules.proxy.size(), settings_.custom_rules.direct.size(), settings_.custom_rules.block.size()};
    const char* b_names[3] = {"VPN", "Напр.", "Блок"};
    for (int b = 0; b < 3; ++b) {
        const float bx = kRightX + 18.0f + static_cast<float>(b) * (b_bw + 3.0f);
        const bool act = (rule_bucket_ == b);
        float tl, tr, br, bl;
        DrawCbgRadii(b, 3, act, 18.0f, tl, tr, br, bl);
        const ColorRgba fill = act ? (b == 0 ? theme_.primary : (b == 1 ? theme_.secondary : theme_.error)) : theme_.surface_high;
        const ColorRgba fg = act ? (b == 0 ? theme_.on_primary : (b == 1 ? theme_.on_secondary : theme_.on_error)) : theme_.on_surface_variant;
        DrawRoundedPanel(vg, bx, b_by, b_bw, 36.0f, tl, tr, br, bl, fill);
        char lbl[32];
        std::snprintf(lbl, sizeof(lbl), "%s (%zu)", b_names[b], counts[b]);
        DrawTextClipped(vg, bx + b_bw * 0.5f, b_by + 18.0f, b_bw - 10.0f, font_semibold_, 13.0f,
                        fg, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, lbl);
        PushHit(bx, b_by, b_bw, 36.0f, HitAction::SetRuleBucket, b, 0, true, tl, tr, br, bl);
    }

    const auto& vec = (rule_bucket_ == 0) ? settings_.custom_rules.proxy
                    : (rule_bucket_ == 1) ? settings_.custom_rules.direct : settings_.custom_rules.block;
    float chip_x = kRightX + 18.0f;
    float chip_y = b_by + 50.0f;
    const float chip_max_x = kRightX + kRightW - 18.0f;
    for (size_t i = 0; i < vec.size(); ++i) {
        const std::string& e = vec[i];
        const float est_w = std::min(kRightW - 36.0f, 52.0f + static_cast<float>(e.size()) * 7.6f);
        if (chip_x + est_w > chip_max_x && chip_x > kRightX + 20.0f) {
            chip_x = kRightX + 18.0f;
            chip_y += 40.0f;
        }
        if (chip_y + 32.0f > kSplitY + kTopH - 12.0f) break;
        DrawRoundedBox(vg, chip_x, chip_y, est_w, 32.0f, 12.0f, theme_.surface_container);
        DrawTextClipped(vg, chip_x + 12.0f, chip_y + 16.0f, est_w - 36.0f, font_mono_, 12.0f,
                        theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, e.c_str());
        DrawVectorIcon(vg, UiIcon::Close, chip_x + est_w - 15.0f, chip_y + 16.0f, 12.0f, theme_.on_surface_variant);
        PushHit(chip_x, chip_y, est_w, 32.0f, HitAction::DelRule, static_cast<int>(i), 0, true, 12.0f, 12.0f, 12.0f, 12.0f);
        chip_x += est_w + 8.0f;
    }

    // Right bottom: TitleID 2x2 grid
    const float tid_y = kSplitY + kTopH + 14.0f;
    constexpr float kBotH = kSplitH - kTopH - 14.0f;  // 226px
    DrawRoundedBox(vg, kRightX, tid_y, kRightW, kBotH, 28.0f, theme_.surface_low);
    DrawTextClipped(vg, kRightX + 18.0f, tid_y + 28.0f, 260.0f, font_display_, 18.5f,
                    theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Приложения TitleID");
    int vpn_cnt = 0;
    for (const auto& t : title_ids_) if (t.vpn_routed) ++vpn_cnt;
    char tbadge[32];
    std::snprintf(tbadge, sizeof(tbadge), "%d через VPN", vpn_cnt);
    DrawRoundedBox(vg, kRightX + kRightW - 134.0f, tid_y + 12.0f, 116.0f, 32.0f, 16.0f, theme_.primary_container);
    DrawTextClipped(vg, kRightX + kRightW - 76.0f, tid_y + 28.0f, 104.0f, font_semibold_, 12.0f,
                    theme_.on_primary_container, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, tbadge);

    const float tcw = (kRightW - 36.0f - 10.0f) * 0.5f;
    constexpr float kTch = 70.0f;
    for (size_t i = 0; i < title_ids_.size() && i < 4; ++i) {
        const auto& t = title_ids_[i];
        const float cx = kRightX + 18.0f + (i % 2) * (tcw + 10.0f);
        const float cy = tid_y + 56.0f + (i / 2) * (kTch + 10.0f);
        DrawRoundedBox(vg, cx, cy, tcw, kTch, 16.0f, theme_.surface_container);
        DrawTextClipped(vg, cx + 12.0f, cy + 25.0f, tcw - 78.0f, font_semibold_, 14.0f,
                        theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, t.name.c_str());
        char tid_s[24];
        std::snprintf(tid_s, sizeof(tid_s), "%016llX", static_cast<unsigned long long>(t.tid));
        DrawTextClipped(vg, cx + 12.0f, cy + 47.0f, tcw - 78.0f, font_mono_, 11.0f,
                        theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, tid_s);
        DrawRoundedBox(vg, cx + tcw - 64.0f, cy + 23.0f, 52.0f, 24.0f, 12.0f,
                       t.vpn_routed ? theme_.primary_container : theme_.tertiary_container);
        DrawTextClipped(vg, cx + tcw - 38.0f, cy + 35.0f, 46.0f, font_semibold_, 11.5f,
                        t.vpn_routed ? theme_.on_primary_container : theme_.on_tertiary_container,
                        NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, t.vpn_routed ? "VPN" : "Напр.");
        PushHit(cx, cy, tcw, kTch, HitAction::CycleTitleId, static_cast<int>(i), 0, true, 16.0f, 16.0f, 16.0f, 16.0f);
    }
}

void YumiUiApp::RenderSettingsTab(NVGcontext* vg) {
    RenderTopBar(vg, "Настройки", "Nintendo Switch · yumi.nro", true);

    constexpr float kBodyY = kWorkY + 58.0f;
    constexpr float kBodyH = kWorkH - 58.0f;  // 622px
    constexpr float kSideW = 282.0f;
    constexpr float kMainX = kWorkX + kSideW + 16.0f;
    constexpr float kMainW = kWorkW - kSideW - 16.0f;  // 832px

    struct CatSpec {
        const char* label;
        UiIcon ico;
    };
    static constexpr std::array<CatSpec, 5> kCats = {{
        {"Маршрутизация", UiIcon::Shield},
        {"Приложения TitleID", UiIcon::Apps},
        {"Сеть и DPI", UiIcon::Rules},
        {"Журнал и правила", UiIcon::Log},
        {"Пульт и система", UiIcon::Qr},
    }};

    int vpn_tid_cnt = 0;
    for (const auto& t : title_ids_) if (t.vpn_routed) ++vpn_tid_cnt;
    char cnt_tid[32], cnt_log[32];
    std::snprintf(cnt_tid, sizeof(cnt_tid), "%d/%zu", vpn_tid_cnt, title_ids_.size());
    std::snprintf(cnt_log, sizeof(cnt_log), "%zu · %d", logs_.size(), CountCustomRules());
    const char* counts[5] = {ModeLabel(settings_.routing_mode), cnt_tid, UtlsLabel(settings_.tls_fingerprint), cnt_log, "HOS 20+"};

    for (int i = 0; i < 5; ++i) {
        const float cy = kBodyY + static_cast<float>(i) * 62.0f;
        const bool act = static_cast<int>(settings_cat_) == i;
        float tl, tr, br, bl;
        if (act) tl = tr = br = bl = 18.0f;
        else DrawStackRadii(i, 5, 24.0f, tl, tr, br, bl);
        DrawRoundedPanel(vg, kWorkX, cy, kSideW, 58.0f, tl, tr, br, bl,
                         act ? theme_.primary_container : theme_.surface_low);
        if (act) DrawFocusStroke(vg, kWorkX, cy, kSideW, 58.0f, tl, tr, br, bl, theme_.primary, 3.0f);

        const ColorRgba fg = act ? theme_.on_primary_container : theme_.on_surface_variant;
        DrawVectorIcon(vg, kCats[static_cast<size_t>(i)].ico, kWorkX + 26.0f, cy + 29.0f, 19.0f, fg);
        DrawTextClipped(vg, kWorkX + 44.0f, cy + 29.0f, 166.0f, font_semibold_, 14.5f,
                        act ? theme_.on_primary_container : theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, kCats[static_cast<size_t>(i)].label);
        DrawRoundedBox(vg, kWorkX + kSideW - 76.0f, cy + 16.0f, 62.0f, 26.0f, 13.0f,
                       act ? theme_.primary : theme_.surface_high);
        DrawTextClipped(vg, kWorkX + kSideW - 45.0f, cy + 29.0f, 54.0f, font_mono_, 11.5f,
                        act ? theme_.on_primary : theme_.on_surface, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, counts[i]);
        PushHit(kWorkX, cy, kSideW, 58.0f, HitAction::SetSettingsCat, i, 0, true, tl, tr, br, bl);
    }

    // Bottom RAM sys card in sidebar
    const float sy = kBodyY + kBodyH - 112.0f;
    DrawRoundedBox(vg, kWorkX, sy, kSideW, 112.0f, 24.0f, theme_.surface_container);
    DrawTextClipped(vg, kWorkX + 16.0f, sy + 24.0f, 150.0f, font_regular_, 13.5f,
                    theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Память sysmodule");
    const double used_mb = static_cast<double>(stats_.sysmodule_heap_used_bytes) / (1024.0 * 1024.0);
    const double shown_mb = (used_mb > 0.05) ? used_mb : 3.4;
    const float side_ram_ratio = static_cast<float>(std::clamp(shown_mb / 5.5, 0.05, 1.0));
    char sram[32];
    std::snprintf(sram, sizeof(sram), "%.1f / 5.5 MB", shown_mb);
    DrawTextClipped(vg, kWorkX + kSideW - 16.0f, sy + 24.0f, 100.0f, font_mono_, 13.5f,
                    theme_.on_surface, NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, sram);
    DrawRoundedBox(vg, kWorkX + 16.0f, sy + 48.0f, kSideW - 32.0f, 10.0f, 5.0f, theme_.surface_highest);
    DrawRoundedBox(vg, kWorkX + 16.0f, sy + 48.0f, (kSideW - 32.0f) * side_ram_ratio, 10.0f, 5.0f, theme_.primary);
    DrawTextClipped(vg, kWorkX + 16.0f, sy + 84.0f, 100.0f, font_regular_, 12.0f,
                    theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "HOS 20.0+");
    DrawTextClipped(vg, kWorkX + kSideW - 16.0f, sy + 84.0f, 140.0f, font_regular_, 12.0f,
                    theme_.on_surface_variant, NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, "A Выбор · L/R Вкладки");

    // Right category panel
    DrawRoundedBox(vg, kMainX, kBodyY, kMainW, kBodyH, 28.0f, theme_.surface_low);
    const float px = kMainX + 20.0f;
    const float pw = kMainW - 40.0f;

    auto draw_toggle_row = [&](int idx, int total, float y, float h, const char* title, const char* sub,
                               bool on, bool rec, HitAction act) {
        float tl, tr, br, bl;
        DrawStackRadii(idx, total, 22.0f, tl, tr, br, bl);
        DrawRoundedPanel(vg, px, y, pw, h, tl, tr, br, bl, theme_.surface_container);
        DrawTextClipped(vg, px + 18.0f, y + h * 0.5f - 10.0f, pw - 210.0f, font_semibold_, 16.0f,
                        theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, title);
        if (rec) {
            float tw = 220.0f;
            if (font_semibold_ >= 0) {
                nvgFontFaceId(vg, font_semibold_); nvgFontSize(vg, 16.0f);
                tw = std::min(pw - 240.0f, nvgTextBounds(vg, 0, 0, title, nullptr, nullptr));
            }
            DrawRoundedBox(vg, px + 26.0f + tw, y + h * 0.5f - 21.0f, 106.0f, 22.0f, 11.0f, theme_.primary_container);
            DrawTextClipped(vg, px + 26.0f + tw + 53.0f, y + h * 0.5f - 10.0f, 96.0f, font_semibold_, 11.5f,
                            theme_.on_primary_container, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, "Рекомендуется");
        }
        DrawTextClipped(vg, px + 18.0f, y + h * 0.5f + 13.0f, pw - 110.0f, font_regular_, 13.0f,
                        theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, sub);
        DrawM3Switch(vg, px + pw - 70.0f, y + h * 0.5f - 15.0f, on, theme_);
        PushHit(px, y, pw, h, act, 0, 0, true, tl, tr, br, bl);
    };

    if (settings_cat_ == SettingsCategory::Routing) {
        DrawTextClipped(vg, px, kBodyY + 30.0f, 480.0f, font_display_, 21.0f, theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Маршрутизация и базовые защиты");
        DrawRoundedBox(vg, px + pw - 126.0f, kBodyY + 14.0f, 126.0f, 32.0f, 16.0f, theme_.primary_container);
        char rm[32]; std::snprintf(rm, sizeof(rm), "Режим: %s", ModeLabel(settings_.routing_mode));
        DrawTextClipped(vg, px + pw - 63.0f, kBodyY + 30.0f, 114.0f, font_mono_, 12.5f,
                        theme_.on_primary_container, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, rm);

        // Mode card
        const float mcy = kBodyY + 56.0f;
        DrawRoundedBox(vg, px, mcy, pw, 98.0f, 22.0f, theme_.surface_container);
        DrawTextClipped(vg, px + 16.0f, mcy + 22.0f, 260.0f, font_semibold_, 16.0f,
                        theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Режим маршрутизации");
        DrawTextClipped(vg, px + pw - 16.0f, mcy + 22.0f, 420.0f, font_regular_, 12.5f,
                        theme_.on_surface_variant, NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, "Global (всё) · Rules (по правилам) · Direct (напрямую)");
        const float rbw = (pw - 32.0f - 6.0f) / 3.0f;
        const char* rnames[3] = {"Global", "Rules", "Direct"};
        for (int i = 0; i < 3; ++i) {
            const float bx = px + 16.0f + static_cast<float>(i) * (rbw + 3.0f);
            const bool act = static_cast<int>(settings_.routing_mode) == i;
            float tl, tr, br, bl;
            DrawCbgRadii(i, 3, act, 20.0f, tl, tr, br, bl);
            DrawRoundedPanel(vg, bx, mcy + 44.0f, rbw, 40.0f, tl, tr, br, bl, act ? theme_.primary : theme_.surface_high);
            DrawTextClipped(vg, bx + rbw * 0.5f, mcy + 64.0f, rbw - 12.0f, font_semibold_, 14.0f,
                            act ? theme_.on_primary : theme_.on_surface_variant, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, rnames[i]);
            PushHit(bx, mcy + 44.0f, rbw, 40.0f, HitAction::SetRoute, i, 0, true, tl, tr, br, bl);
        }

        const float ly = mcy + 112.0f;
        draw_toggle_row(0, 3, ly, 76.0f, "Блокировка QUIC (UDP 443)",
                        "Переводит YouTube на стабильный TCP, убирает подвисания", settings_.block_quic, true, HitAction::ToggleQuic);
        draw_toggle_row(1, 3, ly + 80.0f, 76.0f, "DoH-резолв адреса сервера",
                        "https://1.1.1.1/dns-query · защита от подмены DNS", settings_.resolve_server_address, true, HitAction::ToggleDoh);
        draw_toggle_row(2, 3, ly + 160.0f, 76.0f, "Автозапуск при загрузке Switch",
                        "Запуск sysmodule yumi:ctl до старта оболочки HOS 20.0+", settings_.auto_connect_on_boot, false, HitAction::ToggleAutoBoot);

        // Quick TitleID strip
        const float qy = kBodyY + kBodyH - 124.0f;
        DrawRoundedBox(vg, px, qy, pw, 108.0f, 22.0f, theme_.surface_container);
        DrawTextClipped(vg, px + 16.0f, qy + 22.0f, 380.0f, font_semibold_, 15.0f,
                        theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "TitleID Split Tunneling (быстрый статус)");
        DrawRoundedBox(vg, px + pw - 116.0f, qy + 8.0f, 100.0f, 28.0f, 14.0f, theme_.surface_high);
        DrawTextClipped(vg, px + pw - 66.0f, qy + 22.0f, 88.0f, font_semibold_, 12.0f,
                        theme_.on_surface, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, "Настроить ->");
        PushHit(px + pw - 116.0f, qy + 8.0f, 100.0f, 28.0f, HitAction::SetSettingsCat, 1, 0, true, 14.0f, 14.0f, 14.0f, 14.0f);

        const float mcw = (pw - 32.0f - 24.0f) / 4.0f;
        for (size_t i = 0; i < title_ids_.size() && i < 4; ++i) {
            const float mx = px + 16.0f + static_cast<float>(i) * (mcw + 8.0f);
            DrawRoundedBox(vg, mx, qy + 42.0f, mcw, 52.0f, 14.0f, theme_.surface_high);
            DrawTextClipped(vg, mx + 10.0f, qy + 59.0f, mcw - 20.0f, font_semibold_, 13.0f,
                            theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, title_ids_[i].name.c_str());
            DrawTextClipped(vg, mx + 10.0f, qy + 79.0f, mcw - 20.0f, font_semibold_, 11.5f,
                            title_ids_[i].vpn_routed ? theme_.primary : theme_.tertiary,
                            NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, title_ids_[i].vpn_routed ? "Через VPN" : "Напрямую");
            PushHit(mx, qy + 42.0f, mcw, 52.0f, HitAction::CycleTitleId, static_cast<int>(i), 0, true, 14.0f, 14.0f, 14.0f, 14.0f);
        }
    } else if (settings_cat_ == SettingsCategory::TitleId) {
        DrawTextClipped(vg, px, kBodyY + 30.0f, 520.0f, font_display_, 21.0f, theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Приложения TitleID (Split Tunneling)");
        float cy = kBodyY + 60.0f;
        for (size_t i = 0; i < title_ids_.size(); ++i) {
            const auto& t = title_ids_[i];
            float tl, tr, br, bl;
            DrawStackRadii(static_cast<int>(i), static_cast<int>(title_ids_.size()), 22.0f, tl, tr, br, bl);
            DrawRoundedPanel(vg, px, cy, pw, 84.0f, tl, tr, br, bl, theme_.surface_container);
            DrawTextClipped(vg, px + 18.0f, cy + 30.0f, 340.0f, font_semibold_, 16.0f, theme_.on_surface,
                            NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, t.name.c_str());
            char tid_s[48];
            std::snprintf(tid_s, sizeof(tid_s), "ProgramID: %016llX", static_cast<unsigned long long>(t.tid));
            DrawTextClipped(vg, px + 18.0f, cy + 54.0f, 340.0f, font_mono_, 12.5f, theme_.on_surface_variant,
                            NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, tid_s);

            const float gx = px + pw - 270.0f - 16.0f;
            const float bw = 133.5f;
            for (int m = 0; m < 2; ++m) {
                const bool want_vpn = (m == 0);
                const bool act = (t.vpn_routed == want_vpn);
                float bt_tl, bt_tr, bt_br, bt_bl;
                DrawCbgRadii(m, 2, act, 20.0f, bt_tl, bt_tr, bt_br, bt_bl);
                const ColorRgba fill = act ? (want_vpn ? theme_.primary : theme_.secondary) : theme_.surface_high;
                const ColorRgba fg = act ? (want_vpn ? theme_.on_primary : theme_.on_secondary) : theme_.on_surface_variant;
                DrawRoundedPanel(vg, gx + m * (bw + 3.0f), cy + 22.0f, bw, 40.0f, bt_tl, bt_tr, bt_br, bt_bl, fill);
                DrawTextClipped(vg, gx + m * (bw + 3.0f) + bw * 0.5f, cy + 42.0f, bw - 12.0f, font_semibold_, 13.5f,
                                fg, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, want_vpn ? "Через VPN" : "Напрямую");
                PushHit(gx + m * (bw + 3.0f), cy + 22.0f, bw, 40.0f, HitAction::SetTitleIdMode, static_cast<int>(i), want_vpn ? 1 : 0,
                        true, bt_tl, bt_tr, bt_br, bt_bl);
            }
            cy += 88.0f;
        }
        DrawRoundedBox(vg, px, kBodyY + kBodyH - 84.0f, pw, 64.0f, 22.0f, theme_.surface_container);
        DrawTextClipped(vg, px + 18.0f, kBodyY + kBodyH - 52.0f, pw - 36.0f, font_regular_, 13.5f,
                        theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE,
                        "В режиме Rules трафик YouTube и браузера идёт через VPN, а Moonlight-NX и Tinfoil напрямую.");
    } else if (settings_cat_ == SettingsCategory::Dpi) {
        DrawTextClipped(vg, px, kBodyY + 30.0f, 520.0f, font_display_, 21.0f, theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Сеть, uTLS и фрагментация пакетов");

        // uTLS picker
        const float ucy = kBodyY + 58.0f;
        DrawRoundedBox(vg, px, ucy, pw, 98.0f, 22.0f, theme_.surface_container);
        DrawTextClipped(vg, px + 16.0f, ucy + 22.0f, 340.0f, font_semibold_, 16.0f, theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "uTLS-отпечаток (ClientHello)");
        static constexpr TlsFingerprint kFps[6] = {
            TlsFingerprint::Auto, TlsFingerprint::Chrome, TlsFingerprint::Firefox,
            TlsFingerprint::Safari, TlsFingerprint::Edge, TlsFingerprint::Random
        };
        const float fbw = (pw - 32.0f - 15.0f) / 6.0f;
        for (int i = 0; i < 6; ++i) {
            const float bx = px + 16.0f + static_cast<float>(i) * (fbw + 3.0f);
            const bool act = settings_.tls_fingerprint == kFps[i];
            float tl, tr, br, bl;
            DrawCbgRadii(i, 6, act, 20.0f, tl, tr, br, bl);
            DrawRoundedPanel(vg, bx, ucy + 44.0f, fbw, 40.0f, tl, tr, br, bl, act ? theme_.primary : theme_.surface_high);
            DrawTextClipped(vg, bx + fbw * 0.5f, ucy + 64.0f, fbw - 8.0f, font_semibold_, 13.0f,
                            act ? theme_.on_primary : theme_.on_surface_variant,
                            NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, UtlsLabel(kFps[i]));
            PushHit(bx, ucy + 44.0f, fbw, 40.0f, HitAction::SetUtls, static_cast<int>(kFps[i]), 0, true, tl, tr, br, bl);
        }

        // Fragment picker
        const float fcy = ucy + 112.0f;
        DrawRoundedBox(vg, px, fcy, pw, 98.0f, 22.0f, theme_.surface_container);
        DrawTextClipped(vg, px + 16.0f, fcy + 22.0f, 320.0f, font_semibold_, 16.0f, theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Фрагментация пакетов");
        DrawTextClipped(vg, px + pw - 16.0f, fcy + 22.0f, 300.0f, font_mono_, 12.5f, theme_.on_surface_variant,
                        NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, "Длина: 20-50 · Интервал: 2-5 ms");
        const float frw = (pw - 32.0f - 6.0f) / 3.0f;
        for (int i = 0; i < 3; ++i) {
            const float bx = px + 16.0f + static_cast<float>(i) * (frw + 3.0f);
            const bool act = static_cast<int>(settings_.fragment_mode) == i;
            float tl, tr, br, bl;
            DrawCbgRadii(i, 3, act, 20.0f, tl, tr, br, bl);
            DrawRoundedPanel(vg, bx, fcy + 44.0f, frw, 40.0f, tl, tr, br, bl, act ? theme_.primary : theme_.surface_high);
            DrawTextClipped(vg, bx + frw * 0.5f, fcy + 64.0f, frw - 10.0f, font_semibold_, 13.5f,
                            act ? theme_.on_primary : theme_.on_surface_variant,
                            NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, FragLabel(static_cast<FragmentMode>(i)));
            PushHit(bx, fcy + 44.0f, frw, 40.0f, HitAction::SetFragMode, i, 0, true, tl, tr, br, bl);
        }

        draw_toggle_row(0, 2, fcy + 114.0f, 76.0f, "Блокировка QUIC (UDP 443)",
                        "Обеспечивает мгновенный TCP-фолбэк для YouTube", settings_.block_quic, true, HitAction::ToggleQuic);
        draw_toggle_row(1, 2, fcy + 194.0f, 76.0f, "DoH-резолв адреса сервера",
                        "https://1.1.1.1/dns-query", settings_.resolve_server_address, true, HitAction::ToggleDoh);
    } else if (settings_cat_ == SettingsCategory::LogRules) {
        DrawTextClipped(vg, px, kBodyY + 30.0f, 440.0f, font_display_, 21.0f, theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Журнал соединений и Свои правила");
        DrawRoundedBox(vg, px + pw - 186.0f, kBodyY + 14.0f, 186.0f, 32.0f, 16.0f, theme_.primary_container);
        DrawTextClipped(vg, px + pw - 93.0f, kBodyY + 30.0f, 174.0f, font_semibold_, 12.5f,
                        theme_.on_primary_container, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, "Открыть полный вид ->");
        PushHit(px + pw - 186.0f, kBodyY + 14.0f, 186.0f, 32.0f, HitAction::GotoRules, 0, 0, true, 16.0f, 16.0f, 16.0f, 16.0f);

        float ly = kBodyY + 60.0f;
        const size_t nshow = std::min<size_t>(logs_.size(), 5);
        for (size_t i = 0; i < nshow; ++i) {
            const auto& l = logs_[i];
            float tl, tr, br, bl;
            DrawStackRadii(static_cast<int>(i), static_cast<int>(nshow), 22.0f, tl, tr, br, bl);
            DrawRoundedPanel(vg, px, ly, pw, 72.0f, tl, tr, br, bl, theme_.surface_container);
            char hp[96], meta[64];
            std::snprintf(hp, sizeof(hp), "%s:%u", l.host.c_str(), l.port);
            std::snprintf(meta, sizeof(meta), "%s · %s · %s", l.proto.c_str(), l.app_name.c_str(), l.time_str.c_str());
            DrawTextClipped(vg, px + 16.0f, ly + 24.0f, pw - 290.0f, font_mono_, 13.5f, theme_.on_surface,
                            NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, hp);
            DrawTextClipped(vg, px + 16.0f, ly + 47.0f, pw - 290.0f, font_regular_, 12.0f, theme_.on_surface_variant,
                            NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, meta);

            const char* btns[3] = {"VPN", "Напр.", "Блок"};
            const float gx = px + pw - 246.0f - 14.0f;
            for (int a = 0; a < 3; ++a) {
                const bool sel = (l.route_action == a);
                float bt_tl, bt_tr, bt_br, bt_bl;
                DrawCbgRadii(a, 3, sel, 16.0f, bt_tl, bt_tr, bt_br, bt_bl);
                const ColorRgba fill = sel ? (a == 0 ? theme_.primary : (a == 1 ? theme_.secondary : theme_.error)) : theme_.surface_high;
                const ColorRgba fg = sel ? (a == 0 ? theme_.on_primary : (a == 1 ? theme_.on_secondary : theme_.on_error)) : theme_.on_surface_variant;
                DrawRoundedPanel(vg, gx + a * 83.0f, ly + 19.0f, 80.0f, 34.0f, bt_tl, bt_tr, bt_br, bt_bl, fill);
                DrawTextClipped(vg, gx + a * 83.0f + 40.0f, ly + 36.0f, 72.0f, font_semibold_, 12.0f,
                                fg, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, btns[a]);
                PushHit(gx + a * 83.0f, ly + 19.0f, 80.0f, 34.0f, HitAction::AddRule, static_cast<int>(i), a, true, bt_tl, bt_tr, bt_br, bt_bl);
            }
            ly += 76.0f;
        }
    } else {
        // Remote & System + Live Palette Strip
        DrawTextClipped(vg, px, kBodyY + 30.0f, 480.0f, font_display_, 21.0f, theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Пульт с телефона, замеры и тема");
        DrawRoundedBox(vg, px + pw - 96.0f, kBodyY + 14.0f, 96.0f, 32.0f, 16.0f, theme_.tertiary_container);
        DrawTextClipped(vg, px + pw - 48.0f, kBodyY + 30.0f, 84.0f, font_mono_, 12.5f,
                        theme_.on_tertiary_container, NVG_ALIGN_CENTER | NVG_ALIGN_MIDDLE, "HOS 20.0+");

        // 2x2 grid cards + bottom theme switcher strip
        const float cw = (pw - 12.0f) * 0.5f;
        constexpr float kCh = 216.0f;
        const float gy = kBodyY + 58.0f;

        // Card 1: QR yumi://remote
        DrawRoundedBox(vg, px, gy, cw, kCh, 22.0f, theme_.surface_container);
        DrawTextClipped(vg, px + 16.0f, gy + 24.0f, cw - 32.0f, font_semibold_, 16.0f, theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Пульт с телефона");
        const uint16_t rem_port = remote_server_.Port() > 0 ? remote_server_.Port() : logic::kRemoteDefaultPort;
        const std::string rem_sub = "yumi://remote · " + lan_ip_ + ":" + std::to_string(rem_port);
        DrawTextClipped(vg, px + 16.0f, gy + 46.0f, cw - 32.0f, font_mono_, 12.5f, theme_.on_surface_variant,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, rem_sub.c_str());
        DrawQrPlate(vg, px + 16.0f, gy + 82.0f, 112.0f, 14.0f, qr_remote_);
        DrawTextClipped(vg, px + 142.0f, gy + 114.0f, cw - 158.0f, font_regular_, 13.0f, theme_.on_surface_variant,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Откройте камеру или");
        DrawTextClipped(vg, px + 142.0f, gy + 134.0f, cw - 158.0f, font_regular_, 13.0f, theme_.on_surface_variant,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Yumi на телефоне для");
        DrawTextClipped(vg, px + 142.0f, gy + 154.0f, cw - 158.0f, font_regular_, 13.0f, theme_.on_surface_variant,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "управления и подписок");

        // Card 2: Sysmodule heap
        const float c2x = px + cw + 12.0f;
        DrawRoundedBox(vg, c2x, gy, cw, kCh, 22.0f, theme_.surface_container);
        DrawTextClipped(vg, c2x + 16.0f, gy + 24.0f, cw - 32.0f, font_semibold_, 16.0f, theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Память sysmodule");
        DrawTextClipped(vg, c2x + 16.0f, gy + 46.0f, cw - 32.0f, font_regular_, 12.5f, theme_.on_surface_variant,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Куча sysmodule (HOS 20.0+)");
        const float r_mb = ctl_connected_
            ? (static_cast<float>(stats_.sysmodule_heap_used_bytes) / (1024.0f * 1024.0f))
            : 0.0f;
        const float r_total = (ctl_connected_ && stats_.sysmodule_heap_total_bytes > 0)
            ? (static_cast<float>(stats_.sysmodule_heap_total_bytes) / (1024.0f * 1024.0f))
            : 1.5f;
        const float r_frac = ctl_connected_
            ? std::clamp(r_mb / std::max(0.5f, r_total), 0.0f, 1.0f)
            : 0.0f;
        char sram2[48], spct[16];
        if (ctl_connected_) {
            std::snprintf(sram2, sizeof(sram2), "Занято: %.2f / %.1f MB", r_mb, r_total);
            std::snprintf(spct, sizeof(spct), "%d%%", static_cast<int>(std::round(r_frac * 100.0f)));
        } else {
            std::snprintf(sram2, sizeof(sram2), "sysmodule не запущен");
            std::snprintf(spct, sizeof(spct), "—");
        }
        DrawTextClipped(vg, c2x + 16.0f, gy + 114.0f, 220.0f, font_mono_, 17.0f, theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, sram2);
        DrawTextClipped(vg, c2x + cw - 16.0f, gy + 114.0f, 70.0f, font_mono_, 16.0f, theme_.primary,
                        NVG_ALIGN_RIGHT | NVG_ALIGN_MIDDLE, spct);
        DrawRoundedBox(vg, c2x + 16.0f, gy + 138.0f, cw - 32.0f, 12.0f, 6.0f, theme_.surface_highest);
        DrawRoundedBox(vg, c2x + 16.0f, gy + 138.0f, (cw - 32.0f) * r_frac, 12.0f, 6.0f, theme_.primary);
        const bool has_bsd = (version_info_.mitm_active & ipc::mitm_flag::kBsdMitmActive) != 0;
        const bool has_dns = (version_info_.mitm_active & ipc::mitm_flag::kSfdnsresMitmActive) != 0;
        const char* mitm_lbl = !ctl_connected_       ? "нет связи"
                             : (has_bsd && has_dns)  ? "bsd:u + sfdnsres"
                             : has_bsd               ? "bsd:u"
                             : has_dns               ? "sfdnsres"
                                                     : "отключён";
        char sock_info[64];
        std::snprintf(sock_info, sizeof(sock_info), "Сокетов: %u · MITM: %s",
                      ctl_connected_ ? stats_.active_sockets : 0u, mitm_lbl);
        DrawTextClipped(vg, c2x + 16.0f, gy + 174.0f, cw - 32.0f, font_regular_, 12.5f,
                        theme_.on_surface_variant, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, sock_info);

        // Card 3: SpeedTest
        const float r2y = gy + kCh + 12.0f;
        constexpr float kCh2 = 198.0f;
        DrawRoundedBox(vg, px, r2y, cw, kCh2, 22.0f, theme_.surface_container);
        DrawTextClipped(vg, px + 16.0f, r2y + 26.0f, cw - 32.0f, font_semibold_, 16.0f, theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "SpeedTest через туннель");
        char spd_srv[64]; std::snprintf(spd_srv, sizeof(spd_srv), "Сервер: %s", ActiveServer().name.c_str());
        DrawTextClipped(vg, px + 16.0f, r2y + 49.0f, cw - 32.0f, font_regular_, 12.5f, theme_.on_surface_variant,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, spd_srv);
        DrawTextClipped(vg, px + 16.0f, r2y + 150.0f, cw - 156.0f, font_mono_, 16.5f, theme_.primary,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, speedtest_result_.c_str());
        DrawRoundedBox(vg, px + cw - 134.0f, r2y + 130.0f, 118.0f, 38.0f, 19.0f, theme_.primary);
        DrawVectorIcon(vg, UiIcon::Speed, px + cw - 114.0f, r2y + 149.0f, 16.0f, theme_.on_primary);
        DrawTextClipped(vg, px + cw - 98.0f, r2y + 149.0f, 76.0f, font_semibold_, 13.0f, theme_.on_primary,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Замерить");
        PushHit(px + cw - 134.0f, r2y + 130.0f, 118.0f, 38.0f, HitAction::RunSpeedTest, 0, 0, true, 19.0f, 19.0f, 19.0f, 19.0f);

        // Card 4: GitHub Updates
        DrawRoundedBox(vg, c2x, r2y, cw, kCh2, 22.0f, theme_.surface_container);
        DrawTextClipped(vg, c2x + 16.0f, r2y + 26.0f, cw - 32.0f, font_semibold_, 16.0f, theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Обновления GitHub");
        DrawTextClipped(vg, c2x + 16.0f, r2y + 49.0f, cw - 32.0f, font_regular_, 12.5f, theme_.on_surface_variant,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "GXUser7/YumiSwitch · Релизный канал");
        DrawTextClipped(vg, c2x + 16.0f, r2y + 150.0f, cw - 156.0f, font_mono_, 14.5f, theme_.on_surface,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, update_status_.c_str());
        DrawRoundedBox(vg, c2x + cw - 134.0f, r2y + 130.0f, 118.0f, 38.0f, 19.0f, theme_.primary_container);
        DrawVectorIcon(vg, UiIcon::Update, c2x + cw - 114.0f, r2y + 149.0f, 16.0f, theme_.on_primary_container);
        DrawTextClipped(vg, c2x + cw - 98.0f, r2y + 149.0f, 76.0f, font_semibold_, 13.0f, theme_.on_primary_container,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "Проверить");
        PushHit(c2x + cw - 134.0f, r2y + 130.0f, 118.0f, 38.0f, HitAction::CheckUpdate, 0, 0, true, 19.0f, 19.0f, 19.0f, 19.0f);

        // Bottom strip: 7 Yumi palettes + AMOLED toggle
        const float py = r2y + kCh2 + 12.0f;
        DrawRoundedBox(vg, px, py, pw, 62.0f, 20.0f, theme_.surface_container);
        const float p_bw = (pw - 136.0f - 18.0f) / 7.0f;
        for (int p = 0; p < 7; ++p) {
            const auto preview = BuildYumiTheme(static_cast<PaletteId>(p), false);
            const float bx = px + 14.0f + static_cast<float>(p) * (p_bw + 3.0f);
            const bool act = static_cast<int>(theme_.id) == p;
            float tl, tr, br, bl;
            DrawCbgRadii(p, 7, act, 16.0f, tl, tr, br, bl);
            DrawRoundedPanel(vg, bx, py + 13.0f, p_bw, 36.0f, tl, tr, br, bl,
                             act ? theme_.primary_container : theme_.surface_high);
            nvgBeginPath(vg);
            nvgCircle(vg, bx + 14.0f, py + 31.0f, 5.0f);
            nvgFillColor(vg, Nvg(preview.primary));
            nvgFill(vg);
            DrawTextClipped(vg, bx + 24.0f, py + 31.0f, p_bw - 28.0f, font_semibold_, 11.5f,
                            act ? theme_.on_primary_container : theme_.on_surface_variant,
                            NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, preview.name);
            PushHit(bx, py + 13.0f, p_bw, 36.0f, HitAction::SelectPalette, p, 0, true, tl, tr, br, bl);
        }

        const float ax = px + pw - 104.0f - 14.0f;
        DrawRoundedBox(vg, ax, py + 13.0f, 104.0f, 36.0f, 18.0f,
                       theme_.amoled ? theme_.primary : theme_.surface_high);
        DrawVectorIcon(vg, UiIcon::Contrast, ax + 18.0f, py + 31.0f, 15.0f,
                       theme_.amoled ? theme_.on_primary : theme_.on_surface_variant);
        DrawTextClipped(vg, ax + 32.0f, py + 31.0f, 64.0f, font_semibold_, 12.0f,
                        theme_.amoled ? theme_.on_primary : theme_.on_surface_variant,
                        NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, "AMOLED");
        PushHit(ax, py + 13.0f, 104.0f, 36.0f, HitAction::ToggleAmoled, 0, 0, true, 18.0f, 18.0f, 18.0f, 18.0f);
    }
}

void YumiUiApp::RenderToast(NVGcontext* vg) {
    if (toast_ttl_ <= 0.0 || toast_msg_.empty()) return;
    float tw = 220.0f;
    if (font_medium_ >= 0) {
        nvgFontFaceId(vg, font_medium_);
        nvgFontSize(vg, 13.5f);
        tw = std::min(680.0f, nvgTextBounds(vg, 0, 0, toast_msg_.c_str(), nullptr, nullptr) + 64.0f);
    }
    const float tx = 140.0f;
    const float ty = kCanvasH - 64.0f;
    DrawRoundedBox(vg, tx, ty, tw, 40.0f, 20.0f, theme_.surface_highest);
    DrawVectorIcon(vg, UiIcon::CheckCircle, tx + 22.0f, ty + 20.0f, 18.0f, theme_.primary);
    DrawTextClipped(vg, tx + 40.0f, ty + 20.0f, tw - 54.0f, font_medium_, 13.5f,
                    theme_.on_surface, NVG_ALIGN_LEFT | NVG_ALIGN_MIDDLE, toast_msg_.c_str());
}

void YumiUiApp::Render(NVGcontext* vg, int win_width, int win_height) {
    if (win_width <= 0 || win_height <= 0) return;

    hit_zones_.clear();

    const float scale = std::min(static_cast<float>(win_width) / kCanvasW,
                                 static_cast<float>(win_height) / kCanvasH);
    const float off_x = (static_cast<float>(win_width) - kCanvasW * scale) * 0.5f;
    const float off_y = (static_cast<float>(win_height) - kCanvasH * scale) * 0.5f;

    nvgBeginFrame(vg, static_cast<float>(win_width), static_cast<float>(win_height), 1.0f);
    nvgTranslate(vg, off_x, off_y);
    nvgScale(vg, scale, scale);

    // Background fill
    nvgBeginPath(vg);
    nvgRect(vg, 0.0f, 0.0f, kCanvasW, kCanvasH);
    nvgFillColor(vg, Nvg(theme_.surface));
    nvgFill(vg);

    RenderRail(vg);

    switch (active_tab_) {
        case UiTab::Connect:  RenderConnectTab(vg); break;
        case UiTab::Servers:  RenderServersTab(vg); break;
        case UiTab::Subs:     RenderSubsTab(vg); break;
        case UiTab::Rules:    RenderRulesTab(vg); break;
        case UiTab::Settings: RenderSettingsTab(vg); break;
    }

    // Active D-Pad focus ring on Switch (shown clearly on console or after D-Pad input)
    if (!is_desktop_preview_) {
        std::vector<int> focusables;
        for (size_t i = 0; i < hit_zones_.size(); ++i) {
            if (hit_zones_[i].focusable) focusables.push_back(static_cast<int>(i));
        }
        if (!focusables.empty()) {
            const int fi = std::clamp(focus_idx_, 0, static_cast<int>(focusables.size()) - 1);
            const auto& hz = hit_zones_[static_cast<size_t>(focusables[static_cast<size_t>(fi)])];
            DrawFocusStroke(vg, hz.x - 2.0f, hz.y - 2.0f, hz.w + 4.0f, hz.h + 4.0f,
                            hz.tl + 2.0f, hz.tr + 2.0f, hz.br + 2.0f, hz.bl + 2.0f, theme_.primary, 2.5f);
        }
    }

    RenderToast(vg);
    nvgEndFrame(vg);
}

}  // namespace yumi_nx::ui
