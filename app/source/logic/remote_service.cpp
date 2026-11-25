#include "remote_service.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <nlohmann/json.hpp>

#include "yumi_nx/config_store.hpp"

namespace yumi_nx::logic {

namespace {

std::string RandomTokenB64Url(size_t byte_len) {
    std::vector<uint8_t> rnd(byte_len, 0);
    if (!net::crypto::RandomBytes(rnd.data(), rnd.size())) {
        const uint64_t ticks = net::MonotonicMs();
        std::memcpy(rnd.data(), &ticks, std::min(sizeof(ticks), rnd.size()));
    }
    return net::crypto::Base64Encode(rnd.data(), rnd.size(), true, false);
}

std::string RandomHex8() {
    uint8_t rnd[4]{};
    if (!net::crypto::RandomBytes(rnd, sizeof(rnd))) {
        const uint32_t t = static_cast<uint32_t>(net::MonotonicMs());
        std::memcpy(rnd, &t, 4);
    }
    return net::crypto::HexEncode(rnd, sizeof(rnd));
}

bool SealRemoteFrame(const uint8_t key32[32],
                     std::string_view aad_str,
                     std::string_view plain_json,
                     std::string& out_iv_b64,
                     std::string& out_ct_b64) {
    uint8_t iv[12]{};
    if (!net::crypto::RandomBytes(iv, sizeof(iv))) return false;
    std::vector<uint8_t> ct(plain_json.size() + 16);
    uint8_t tag[16]{};
    if (!net::crypto::AesGcmEncrypt(
            key32,
            32,
            iv,
            reinterpret_cast<const uint8_t*>(aad_str.data()),
            aad_str.size(),
            reinterpret_cast<const uint8_t*>(plain_json.data()),
            plain_json.size(),
            ct.data(),
            tag)) {
        return false;
    }
    std::memcpy(ct.data() + plain_json.size(), tag, 16);
    out_iv_b64 = net::crypto::Base64Encode(iv, sizeof(iv), true, false);
    out_ct_b64 = net::crypto::Base64Encode(ct.data(), ct.size(), true, false);
    return true;
}

bool OpenRemoteFrame(const uint8_t key32[32],
                     std::string_view aad_str,
                     std::string_view iv_b64,
                     std::string_view ct_b64,
                     std::string& out_plain) {
    const auto iv = net::crypto::Base64Decode(iv_b64);
    const auto ct = net::crypto::Base64Decode(ct_b64);
    if (!iv.has_value() || iv->size() != 12) return false;
    if (!ct.has_value() || ct->size() < 16) return false;
    const size_t pt_len = ct->size() - 16;
    out_plain.resize(pt_len);
    uint8_t* dst = pt_len > 0 ? reinterpret_cast<uint8_t*>(out_plain.data()) : nullptr;
    return net::crypto::AesGcmDecrypt(
        key32,
        32,
        iv->data(),
        reinterpret_cast<const uint8_t*>(aad_str.data()),
        aad_str.size(),
        ct->data(),
        pt_len,
        ct->data() + pt_len,
        dst);
}

void AppendLengthPrefixedFrame(std::vector<uint8_t>& dst, const std::string& json_payload) {
    if (json_payload.empty() || json_payload.size() > kRemoteMaxFrameBytes) return;
    const uint32_t len = static_cast<uint32_t>(json_payload.size());
    dst.push_back(static_cast<uint8_t>((len >> 24) & 0xFFu));
    dst.push_back(static_cast<uint8_t>((len >> 16) & 0xFFu));
    dst.push_back(static_cast<uint8_t>((len >> 8) & 0xFFu));
    dst.push_back(static_cast<uint8_t>(len & 0xFFu));
    dst.insert(dst.end(), json_payload.begin(), json_payload.end());
}

bool TryPopLengthPrefixedFrame(std::vector<uint8_t>& buf, std::string& out_json, bool& out_fatal) {
    out_fatal = false;
    if (buf.size() < 4) return false;
    const uint32_t len = (uint32_t(buf[0]) << 24) | (uint32_t(buf[1]) << 16) |
                         (uint32_t(buf[2]) << 8) | uint32_t(buf[3]);
    if (len == 0 || len > kRemoteMaxFrameBytes) {
        out_fatal = true;
        return false;
    }
    if (buf.size() < 4u + len) return false;
    out_json.assign(reinterpret_cast<const char*>(buf.data() + 4), len);
    buf.erase(buf.begin(), buf.begin() + 4 + static_cast<ptrdiff_t>(len));
    return true;
}

bool BlockingWriteFrame(net::NetSocket& sock, const std::string& json_payload, int timeout_ms) noexcept {
    if (json_payload.empty() || json_payload.size() > kRemoteMaxFrameBytes) return false;
    const uint32_t len = static_cast<uint32_t>(json_payload.size());
    const uint8_t hdr[4]{
        static_cast<uint8_t>((len >> 24) & 0xFFu),
        static_cast<uint8_t>((len >> 16) & 0xFFu),
        static_cast<uint8_t>((len >> 8) & 0xFFu),
        static_cast<uint8_t>(len & 0xFFu),
    };
    return sock.SendAllBlocking(hdr, 4, timeout_ms) &&
           sock.SendAllBlocking(json_payload.data(), json_payload.size(), timeout_ms);
}

bool BlockingReadExact(net::NetSocket& sock, uint8_t* dst, size_t len, int timeout_ms) noexcept {
    size_t got = 0;
    const uint64_t dl = net::MonotonicMs() + static_cast<uint64_t>(std::max(1, timeout_ms));
    while (got < len) {
        const uint64_t now = net::MonotonicMs();
        if (now >= dl) return false;
        const int rem = static_cast<int>(std::clamp<uint64_t>(dl - now, 20ULL, 1000ULL));
        const auto res = sock.RecvSomeBlocking(dst + got, len - got, rem);
        if (res.status == net::IoStatus::Ok && res.bytes > 0) {
            got += res.bytes;
            continue;
        }
        if (res.status == net::IoStatus::WouldBlock) continue;
        return false;
    }
    return true;
}

bool BlockingReadFrame(net::NetSocket& sock, std::string& out_json, int timeout_ms) {
    uint8_t hdr[4]{};
    if (!BlockingReadExact(sock, hdr, 4, timeout_ms)) return false;
    const uint32_t len = (uint32_t(hdr[0]) << 24) | (uint32_t(hdr[1]) << 16) |
                         (uint32_t(hdr[2]) << 8) | uint32_t(hdr[3]);
    if (len == 0 || len > kRemoteMaxFrameBytes) return false;
    out_json.resize(len);
    return BlockingReadExact(sock, reinterpret_cast<uint8_t*>(out_json.data()), len, timeout_ms);
}

const char* ProtocolToAndroidString(Protocol p) noexcept {
    switch (p) {
        case Protocol::Vless:       return "VLESS";
        case Protocol::Vmess:       return "VMESS";
        case Protocol::Trojan:      return "TROJAN";
        case Protocol::Shadowsocks: return "SHADOWSOCKS";
        case Protocol::Hysteria2:   return "HYSTERIA2";
        case Protocol::WireGuard:   return "WIREGUARD";
        case Protocol::Socks5:      return "SOCKS";
        case Protocol::Http:        return "HTTP";
        case Protocol::Direct:      return "VLESS";
    }
    return "VLESS";
}

const char* RoutingModeString(RoutingMode m) noexcept {
    switch (m) {
        case RoutingMode::Global: return "Global";
        case RoutingMode::Rules:  return "Rules";
        case RoutingMode::Direct: return "Direct";
    }
    return "Rules";
}

const char* FingerprintString(TlsFingerprint fp) noexcept {
    switch (fp) {
        case TlsFingerprint::Auto:       return "Auto";
        case TlsFingerprint::Chrome:     return "Chrome";
        case TlsFingerprint::Firefox:    return "Firefox";
        case TlsFingerprint::Safari:     return "Safari";
        case TlsFingerprint::Edge:       return "Edge";
        case TlsFingerprint::Ios:        return "Ios";
        case TlsFingerprint::Android:    return "Android";
        case TlsFingerprint::Qq:         return "Qq";
        case TlsFingerprint::Browser360: return "Browser360";
        case TlsFingerprint::Random:     return "Random";
        case TlsFingerprint::Randomized: return "Randomized";
    }
    return "Auto";
}

const char* FragmentModeString(FragmentMode fm) noexcept {
    switch (fm) {
        case FragmentMode::Off:         return "Off";
        case FragmentMode::TlsHello:    return "TlsHello";
        case FragmentMode::TcpSegments: return "TcpSegments";
    }
    return "Off";
}

const char* FragmentScopeString(FragmentScope fs) noexcept {
    switch (fs) {
        case FragmentScope::TlsOnly:       return "TlsOnly";
        case FragmentScope::TlsAndReality: return "TlsAndReality";
        case FragmentScope::AllTcp:        return "AllTcp";
    }
    return "TlsAndReality";
}

bool EqualsCiRemote(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

std::string ExtractUrlHost(std::string_view url) {
    size_t pos = url.find("://");
    std::string_view rest = (pos == std::string_view::npos) ? url : url.substr(pos + 3);
    size_t end = rest.find_first_of("/?#");
    if (end != std::string_view::npos) rest = rest.substr(0, end);
    size_t at = rest.rfind('@');
    if (at != std::string_view::npos) rest = rest.substr(at + 1);
    size_t col = rest.rfind(':');
    if (col != std::string_view::npos && rest.find(']') == std::string_view::npos) {
        rest = rest.substr(0, col);
    }
    return std::string(rest);
}

}  // namespace

void DeriveRemoteSessionKey(const uint8_t shared32[32],
                            std::string_view session_id,
                            std::string_view secret_utf8,
                            uint8_t out_key32[32]) noexcept {
    std::vector<uint8_t> material;
    material.reserve(32 + secret_utf8.size());
    material.insert(material.end(), shared32, shared32 + 32);
    material.insert(material.end(), secret_utf8.begin(), secret_utf8.end());

    uint8_t salt[32]{};
    net::crypto::Sha256::Digest(session_id.data(), session_id.size(), salt);

    uint8_t extract[32]{};
    net::crypto::HmacSha256(salt, sizeof(salt), material.data(), material.size(), extract);

    static constexpr char kLabel[15] = {
        'y', 'u', 'm', 'i', '-', 'r', 'e', 'm', 'o', 't', 'e', '-', 'v', '1', ' '
    };
    net::crypto::HmacSha256(extract,
                             sizeof(extract),
                             reinterpret_cast<const uint8_t*>(kLabel),
                             sizeof(kLabel),
                             out_key32);
}

std::string BuildRemoteAad(std::string_view session_id, bool from_phone, uint64_t counter) {
    return "yumi-remote-v1:" + std::string(session_id) + ":" +
           (from_phone ? "up" : "down") + ":" + std::to_string(counter);
}

std::string BuildRemoteInviteUri(std::string_view host,
                                 uint16_t port,
                                 std::string_view code,
                                 const uint8_t host_pub65[65],
                                 std::string_view host_id,
                                 std::string_view host_name) {
    const auto spki = net::crypto::P256EncodeSpkiDer(host_pub65);
    const std::string key_b64 = net::crypto::Base64Encode(spki.data(), spki.size(), true, false);
    std::string out = "yumi://remote?v=" + std::to_string(kRemoteVersion);
    out += "&host=" + UrlEncode(host);
    out += "&port=" + std::to_string(port);
    out += "&code=" + UrlEncode(code);
    out += "&key=" + UrlEncode(key_b64);
    out += "&id=" + UrlEncode(host_id);
    out += "&name=" + UrlEncode(host_name.substr(0, 96));
    return out;
}

RemoteInviteInfo ParseRemoteInviteUri(std::string_view uri) {
    RemoteInviteInfo info;
    if (uri.rfind("yumi://remote", 0) != 0) return {};
    const size_t q = uri.find('?');
    if (q == std::string_view::npos) return {};
    std::string_view query = uri.substr(q + 1);
    const size_t hash = query.find('#');
    if (hash != std::string_view::npos) query = query.substr(0, hash);

    std::string key_b64;
    size_t pos = 0;
    while (pos < query.size()) {
        const size_t amp = query.find('&', pos);
        const std::string_view part = (amp == std::string_view::npos)
            ? query.substr(pos)
            : query.substr(pos, amp - pos);
        if (const size_t sep = part.find('='); sep != std::string_view::npos) {
            const std::string_view k = part.substr(0, sep);
            const std::string v = UrlDecode(part.substr(sep + 1));
            if (k == "v") {
                uint64_t ver = 0;
                if (!ParseUnsignedDecimal(v, ver) || ver != kRemoteVersion) return {};
                info.version = static_cast<int>(ver);
            } else if (k == "host") {
                info.host = v;
            } else if (k == "port") {
                uint64_t p = 0;
                if (!ParseUnsignedDecimal(v, p) || p == 0 || p > 65535) return {};
                info.port = static_cast<uint16_t>(p);
            } else if (k == "code") {
                info.code = v;
            } else if (k == "key") {
                key_b64 = v;
            } else if (k == "id") {
                info.host_id = v;
            } else if (k == "name") {
                info.host_name = v.substr(0, 96);
            }
        }
        if (amp == std::string_view::npos) break;
        pos = amp + 1;
    }

    if (info.host.empty() || info.port == 0 || info.host_id.empty() || key_b64.empty()) return {};
    const auto code_bytes = net::crypto::Base64Decode(info.code);
    if (!code_bytes.has_value() || code_bytes->size() < 18) return {};
    const auto spki = net::crypto::Base64Decode(key_b64);
    if (!spki.has_value() || !net::crypto::P256DecodeSpkiDer(spki->data(), spki->size(), info.host_pub65)) {
        return {};
    }
    info.valid = true;
    return info;
}

bool RemoteIdentityStore::LoadOrInit(std::string identity_path, std::string default_host_name) {
    path_ = std::move(identity_path);
    host_name_ = default_host_name.empty() ? std::string("Nintendo Switch") : std::move(default_host_name);
    peers_.clear();

    bool loaded = false;
    if (!path_.empty()) {
        if (auto txt = store::ReadTextFile(path_)) {
            auto doc = nlohmann::json::parse(*txt, nullptr, false);
            if (!doc.is_discarded() && doc.is_object()) {
                if (doc.contains("host_id") && doc["host_id"].is_string()) {
                    host_id_ = doc["host_id"].get<std::string>();
                }
                if (doc.contains("host_name") && doc["host_name"].is_string()) {
                    host_name_ = doc["host_name"].get<std::string>();
                }
                if (doc.contains("priv_b64") && doc["priv_b64"].is_string()) {
                    const auto priv = net::crypto::Base64Decode(doc["priv_b64"].get<std::string>());
                    if (priv.has_value() && priv->size() == 32) {
                        std::memcpy(keypair_.priv, priv->data(), 32);
                        if (net::crypto::P256PublicFromPrivate(keypair_.priv, keypair_.pub65) && !host_id_.empty()) {
                            loaded = true;
                        }
                    }
                }
                if (loaded && doc.contains("peers") && doc["peers"].is_array()) {
                    for (const auto& pj : doc["peers"]) {
                        if (!pj.is_object()) continue;
                        RemotePeer p;
                        if (pj.contains("id") && pj["id"].is_string()) p.id = pj["id"].get<std::string>();
                        if (pj.contains("name") && pj["name"].is_string()) p.name = pj["name"].get<std::string>();
                        if (pj.contains("secret") && pj["secret"].is_string()) p.secret = pj["secret"].get<std::string>();
                        p.paired_at_epoch_ms = pj.value("paired_at_ms", int64_t{0});
                        p.last_seen_epoch_ms = pj.value("last_seen_ms", int64_t{0});
                        if (!p.id.empty() && !p.secret.empty()) peers_.push_back(std::move(p));
                    }
                }
            }
        }
    }

    if (!loaded) {
        if (!net::crypto::P256GenerateKeyPair(keypair_)) return false;
        host_id_ = "sw-" + RandomHex8();
        Save();
    }
    return true;
}

bool RemoteIdentityStore::Save() const {
    if (path_.empty()) return true;
    nlohmann::json doc;
    doc["host_id"] = host_id_;
    doc["host_name"] = host_name_;
    doc["priv_b64"] = net::crypto::Base64Encode(keypair_.priv, 32, true, false);
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& p : peers_) {
        arr.push_back({
            {"id", p.id},
            {"name", p.name},
            {"secret", p.secret},
            {"paired_at_ms", p.paired_at_epoch_ms},
            {"last_seen_ms", p.last_seen_epoch_ms},
        });
    }
    doc["peers"] = std::move(arr);
    return store::WriteFileAtomic(path_, doc.dump(2));
}

std::string RemoteIdentityStore::FindPeerSecret(std::string_view peer_id) const {
    for (const auto& p : peers_) {
        if (p.id == peer_id) return p.secret;
    }
    return {};
}

void RemoteIdentityStore::TouchPeer(std::string_view peer_id, int64_t now_epoch_ms) {
    for (auto& p : peers_) {
        if (p.id == peer_id) {
            p.last_seen_epoch_ms = now_epoch_ms;
            Save();
            return;
        }
    }
}

RemotePeer RemoteIdentityStore::AddNewPeer(std::string_view device_name, int64_t now_epoch_ms) {
    RemotePeer p;
    p.id = "ph-" + RandomHex8();
    p.name = device_name.empty() ? std::string("Yumi Phone") : std::string(device_name.substr(0, 96));
    p.secret = RandomTokenB64Url(24);
    p.paired_at_epoch_ms = now_epoch_ms;
    p.last_seen_epoch_ms = now_epoch_ms;
    peers_.push_back(p);
    if (peers_.size() > 16) {
        peers_.erase(peers_.begin());
    }
    Save();
    return p;
}

// --- RemoteBeacon ---

bool RemoteBeacon::Start(std::string host_id,
                         std::string host_name,
                         uint16_t tcp_port,
                         bool loopback_only,
                         uint16_t bind_port) {
    Stop();
    net::SocketLayerInit();
    uint16_t actual_port = bind_port;
    net::NetSocket s = UdpBindSocket(loopback_only, actual_port, true);
    if (!s.IsValid()) return false;

    {
        SimpleLock lk(mu_);
        sock_ = std::move(s);
        host_id_ = std::move(host_id);
        host_name_ = host_name.empty() ? std::string("Nintendo Switch") : std::move(host_name);
    }
    tcp_port_.store(tcp_port);
    bound_port_.store(actual_port);
    stop_requested_.store(false);
    running_.store(true);
    if (!worker_.Start(&RemoteBeacon::ThreadEntry, this, 0x8000)) {
        Stop();
        return false;
    }
    return true;
}

void RemoteBeacon::Stop() noexcept {
    stop_requested_.store(true);
    {
        SimpleLock lk(mu_);
        sock_.Close();
    }
    worker_.Join();
    bound_port_.store(0);
    running_.store(false);
}

void RemoteBeacon::ThreadEntry(void* arg) {
    if (auto* self = static_cast<RemoteBeacon*>(arg)) {
        self->RunLoop();
    }
}

void RemoteBeacon::RunLoop() {
    uint8_t buf[256]{};
    while (!stop_requested_.load()) {
        net::SocketFd fd = net::kInvalidSocket;
        {
            SimpleLock lk(mu_);
            fd = sock_.Fd();
        }
        if (fd == net::kInvalidSocket) break;
        net::PollItem pi{};
        pi.fd = fd;
        pi.want_read = true;
        if (net::PollSockets(&pi, 1, 150) <= 0 || !pi.rev_read) continue;

        uint32_t from_ip = 0;
        uint16_t from_port = 0;
        net::IoResult rx{};
        std::string hid, hname;
        {
            SimpleLock lk(mu_);
            rx = sock_.UdpRecvFrom(buf, sizeof(buf), from_ip, from_port);
            hid = host_id_;
            hname = host_name_;
        }
        if (rx.status != net::IoStatus::Ok || rx.bytes == 0) continue;

        std::string_view msg(reinterpret_cast<const char*>(buf), rx.bytes);
        while (!msg.empty() && (msg.back() == '\r' || msg.back() == '\n' || msg.back() == ' ')) {
            msg.remove_suffix(1);
        }
        if (msg != "yumi-remote-probe-v1") continue;
        const uint16_t tp = tcp_port_.load();
        if (tp == 0) continue;

        nlohmann::json reply;
        reply["v"] = kRemoteVersion;
        reply["id"] = hid;
        reply["name"] = hname;
        reply["port"] = tp;
        const std::string wire = reply.dump();

        SimpleLock lk(mu_);
        sock_.UdpSendTo(from_ip, from_port, wire.data(), wire.size());
    }
    running_.store(false);
}

// --- RemoteServer ---

bool RemoteServer::Start(std::string advertise_host,
                         std::string identity_path,
                         std::string host_name,
                         bool loopback_only,
                         uint16_t preferred_port) {
    Stop();
    net::SocketLayerInit();

    if (!store_.LoadOrInit(std::move(identity_path), std::move(host_name))) return false;

    uint16_t port = preferred_port;
    net::NetSocket sock = TcpListenSocket(loopback_only, port);
    if (!sock.IsValid() && preferred_port != 0) {
        port = 0;
        sock = TcpListenSocket(loopback_only, port);
    }
    if (!sock.IsValid() || port == 0) return false;

    {
        SimpleLock lk(mu_);
        listener_ = std::move(sock);
        advertise_host_ = advertise_host.empty()
            ? (loopback_only ? std::string("127.0.0.1") : std::string("0.0.0.0"))
            : std::move(advertise_host);
        pairing_code_ = RandomTokenB64Url(24);
        pairing_expires_ms_ = static_cast<int64_t>(net::MonotonicMs()) + kRemotePairingLifetimeMs;
        snapshot_.host_name = store_.HostName();
        snapshot_dirty_ = false;
        clients_.clear();
        command_queue_.clear();
    }
    port_.store(port);
    active_clients_.store(0);
    stop_requested_.store(false);
    running_.store(true);
    if (!worker_.Start(&RemoteServer::ThreadEntry, this, 0x10000)) {
        Stop();
        return false;
    }
    return true;
}

void RemoteServer::Stop() noexcept {
    stop_requested_.store(true);
    {
        SimpleLock lk(mu_);
        listener_.Close();
    }
    worker_.Join();
    {
        SimpleLock lk(mu_);
        for (auto& c : clients_) c.sock.Close();
        clients_.clear();
    }
    port_.store(0);
    active_clients_.store(0);
    running_.store(false);
}

void RemoteServer::RotatePairingCode() {
    SimpleLock lk(mu_);
    pairing_code_ = RandomTokenB64Url(24);
    pairing_expires_ms_ = static_cast<int64_t>(net::MonotonicMs()) + kRemotePairingLifetimeMs;
}

void RemoteServer::SetSnapshot(const RemoteHostSnapshot& snapshot) {
    SimpleLock lk(mu_);
    snapshot_ = snapshot;
    if (snapshot_.host_name.empty()) snapshot_.host_name = store_.HostName();
    snapshot_dirty_ = true;
}

void RemoteServer::DrainCommands(std::vector<RemoteCommand>& out) {
    SimpleLock lk(mu_);
    if (command_queue_.empty()) return;
    out.insert(out.end(),
               std::make_move_iterator(command_queue_.begin()),
               std::make_move_iterator(command_queue_.end()));
    command_queue_.clear();
}

std::string RemoteServer::ShareUrl() {
    SimpleLock lk(mu_);
    if (pairing_code_.empty() || static_cast<int64_t>(net::MonotonicMs()) >= pairing_expires_ms_) {
        pairing_code_ = RandomTokenB64Url(24);
        pairing_expires_ms_ = static_cast<int64_t>(net::MonotonicMs()) + kRemotePairingLifetimeMs;
    }
    return BuildRemoteInviteUri(advertise_host_, port_.load(), pairing_code_,
                                store_.KeyPair().pub65, store_.HostId(), store_.HostName());
}

std::string RemoteServer::HostId() {
    SimpleLock lk(mu_);
    return store_.HostId();
}

std::string RemoteServer::HostName() {
    SimpleLock lk(mu_);
    return store_.HostName();
}

size_t RemoteServer::TrustedPeerCount() {
    SimpleLock lk(mu_);
    return store_.Peers().size();
}

void RemoteServer::ThreadEntry(void* arg) {
    if (auto* self = static_cast<RemoteServer*>(arg)) {
        self->RunLoop();
    }
}

void RemoteServer::AcceptNewClients() {
    while (true) {
        net::NetSocket cli;
        {
            SimpleLock lk(mu_);
            if (!listener_.IsValid() || clients_.size() >= kMaxClients) break;
            uint32_t pip = 0;
            uint16_t pport = 0;
            cli = listener_.Accept(pip, pport);
        }
        if (!cli.IsValid()) break;

        ClientSession cs;
        cs.sock = std::move(cli);
        cs.last_rx_ms = net::MonotonicMs();
        cs.last_send_ms = 0;
        SimpleLock lk(mu_);
        clients_.push_back(std::move(cs));
        active_clients_.store(clients_.size());
    }
}

void RemoteServer::CloseClient(size_t idx) {
    SimpleLock lk(mu_);
    if (idx < clients_.size()) {
        clients_[idx].sock.Close();
        clients_.erase(clients_.begin() + static_cast<ptrdiff_t>(idx));
        active_clients_.store(clients_.size());
    }
}

std::string RemoteServer::SerializeSnapshotJson(const RemoteHostSnapshot& s,
                                                bool include_nodes,
                                                bool include_subs) const {
    nlohmann::json j;
    j["hostName"] = s.host_name;
    j["state"] = s.state;
    j["message"] = s.message;
    j["needsConsentOnTv"] = s.needs_consent_on_tv;
    if (!s.selected_node_id.empty()) j["selectedNodeId"] = s.selected_node_id;
    j["connectedAtEpochMillis"] = s.connected_at_epoch_ms;
    j["downloadBytesPerSecond"] = s.download_bytes_per_sec;
    j["uploadBytesPerSecond"] = s.upload_bytes_per_sec;
    j["nodesRevision"] = s.nodes_revision;
    if (include_nodes) {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& n : s.nodes) {
            nlohmann::json nj;
            nj["id"] = n.id;
            nj["name"] = n.name;
            nj["group"] = n.group;
            if (n.latency_ms >= 0) nj["latencyMillis"] = n.latency_ms;
            nj["latencyFailed"] = n.latency_failed;
            nj["protocol"] = ProtocolToAndroidString(n.protocol);
            nj["badges"] = n.badges;
            if (!n.subscription_id.empty()) nj["subscriptionId"] = n.subscription_id;
            nj["memberProtocols"] = nlohmann::json::array();
            arr.push_back(std::move(nj));
        }
        j["nodes"] = std::move(arr);
    }
    j["pingingNodeIds"] = s.pinging_node_ids;
    j["subscriptionsRevision"] = s.subscriptions_revision;
    if (include_subs) {
        nlohmann::json sarr = nlohmann::json::array();
        for (const auto& sub : s.subscriptions) {
            nlohmann::json sj;
            sj["id"] = sub.id;
            sj["name"] = sub.name;
            if (!sub.remote_title.empty()) sj["remoteTitle"] = sub.remote_title;
            sj["urlHost"] = sub.url_host.empty() ? std::string("local") : ExtractUrlHost(sub.url_host);
            sj["enabled"] = sub.enabled;
            sj["nodeCount"] = sub.node_count;
            if (sub.last_updated_epoch_ms > 0) sj["lastUpdatedEpochMillis"] = sub.last_updated_epoch_ms;
            if (!sub.last_error.empty()) sj["lastError"] = sub.last_error;
            sj["refreshing"] = sub.refreshing;
            if (sub.user_info.has_value()) {
                nlohmann::json ui;
                if (sub.user_info->has_upload) ui["uploadBytes"] = sub.user_info->upload_bytes;
                if (sub.user_info->has_download) ui["downloadBytes"] = sub.user_info->download_bytes;
                if (sub.user_info->has_total) ui["totalBytes"] = sub.user_info->total_bytes;
                if (sub.user_info->has_expire) ui["expiresAtEpochMillis"] = sub.user_info->expires_at_epoch_sec * 1000LL;
                sj["userInfo"] = std::move(ui);
            }
            sarr.push_back(std::move(sj));
        }
        j["subscriptions"] = std::move(sarr);
    }
    j["settings"] = {
        {"autoConnectOnBoot", s.settings.auto_connect_on_boot},
        {"subscriptionAutoUpdate", s.settings.subscription_auto_update},
        {"subscriptionUpdateMinutes", s.settings.subscription_update_minutes},
        {"routingMode", RoutingModeString(s.settings.routing_mode)},
        {"bypassLan", s.settings.bypass_lan},
        {"blockAds", s.settings.block_ads},
        {"blockQuic", s.settings.block_quic},
        {"enableIpv6", s.settings.enable_ipv6},
        {"hijackDns", s.settings.hijack_dns},
        {"dnsFallback", s.settings.dns_fallback},
        {"remoteDns", s.settings.remote_dns},
        {"directDns", s.settings.direct_dns},
        {"tlsFingerprint", FingerprintString(s.settings.tls_fingerprint)},
        {"fragmentMode", FragmentModeString(s.settings.fragment_mode)},
        {"fragmentScope", FragmentScopeString(s.settings.fragment_scope)},
        {"fragmentLength", s.settings.fragment_length},
        {"fragmentInterval", s.settings.fragment_interval},
        {"fragmentMaxChunks", s.settings.fragment_max_chunks},
    };
    return j.dump();
}

bool RemoteServer::QueueEncryptedSnapshot(ClientSession& cs, const RemoteHostSnapshot& snap) {
    const bool inc_nodes = (snap.nodes_revision != cs.sent_nodes_rev);
    const bool inc_subs = (snap.subscriptions_revision != cs.sent_subs_rev);
    const std::string plain = SerializeSnapshotJson(snap, inc_nodes, inc_subs);
    const std::string aad = BuildRemoteAad(cs.session_id, false, cs.send_counter);
    std::string iv_b64, ct_b64;
    if (!SealRemoteFrame(cs.key, aad, plain, iv_b64, ct_b64)) return false;

    ++cs.send_counter;
    cs.sent_nodes_rev = snap.nodes_revision;
    cs.sent_subs_rev = snap.subscriptions_revision;
    cs.last_send_ms = net::MonotonicMs();

    nlohmann::json sealed;
    sealed["iv"] = iv_b64;
    sealed["ciphertext"] = ct_b64;
    AppendLengthPrefixedFrame(cs.tx_buf, sealed.dump());
    return true;
}

bool RemoteServer::HandleGreetingFrame(ClientSession& cs, const std::string& json_str) {
    auto gj = nlohmann::json::parse(json_str, nullptr, false);
    if (gj.is_discarded() || !gj.is_object()) return false;
    if (gj.value("version", 0) != kRemoteVersion) return false;
    if (!gj.contains("sessionId") || !gj["sessionId"].is_string() ||
        !gj.contains("senderPublicKey") || !gj["senderPublicKey"].is_string() ||
        !gj.contains("iv") || !gj["iv"].is_string() ||
        !gj.contains("ciphertext") || !gj["ciphertext"].is_string()) {
        return false;
    }

    const std::string sid = gj["sessionId"].get<std::string>();
    const std::string peer_id = gj.contains("peerId") && gj["peerId"].is_string()
        ? gj["peerId"].get<std::string>() : std::string{};
    const auto spki = net::crypto::Base64Decode(gj["senderPublicKey"].get<std::string>());
    uint8_t sender_pub65[65]{};
    if (!spki.has_value() || !net::crypto::P256DecodeSpkiDer(spki->data(), spki->size(), sender_pub65)) {
        return false;
    }

    const bool introducing = peer_id.empty();
    std::string auth_secret;
    net::crypto::P256KeyPair kp = store_.KeyPair();
    const std::string host_id = store_.HostId();
    const std::string host_name = store_.HostName();

    if (introducing) {
        if (pairing_code_.empty() || static_cast<int64_t>(net::MonotonicMs()) >= pairing_expires_ms_) {
            return false;
        }
        auth_secret = pairing_code_;
    } else {
        auth_secret = store_.FindPeerSecret(peer_id);
        if (auth_secret.empty()) return false;
    }

    uint8_t shared32[32]{};
    if (!net::crypto::P256Ecdh(shared32, kp.priv, sender_pub65)) return false;

    uint8_t key32[32]{};
    DeriveRemoteSessionKey(shared32, sid, auth_secret, key32);

    const std::string aad0_up = BuildRemoteAad(sid, true, 0);
    std::string opening_json;
    if (!OpenRemoteFrame(key32, aad0_up, gj["iv"].get<std::string>(),
                         gj["ciphertext"].get<std::string>(), opening_json)) {
        return false;
    }

    auto oj = nlohmann::json::parse(opening_json, nullptr, false);
    if (oj.is_discarded() || !oj.is_object()) return false;
    const std::string dev_name = oj.contains("deviceName") && oj["deviceName"].is_string()
        ? oj["deviceName"].get<std::string>() : std::string("Yumi Phone");

    RemotePeer peer;
    const int64_t now_ms = CurrentEpochMs();
    if (introducing) {
        peer = store_.AddNewPeer(dev_name, now_ms);
        pairing_code_.clear();  // single-use code consumed cleanly
    } else {
        store_.TouchPeer(peer_id, now_ms);
        peer.id = peer_id;
        peer.name = dev_name;
    }

    nlohmann::json access;
    access["accepted"] = true;
    access["reason"] = "";
    access["peerId"] = peer.id;
    access["secret"] = introducing ? peer.secret : std::string{};
    access["hostId"] = host_id;
    access["hostName"] = host_name;

    std::string w_iv, w_ct;
    const std::string aad0_down = BuildRemoteAad(sid, false, 0);
    if (!SealRemoteFrame(key32, aad0_down, access.dump(), w_iv, w_ct)) return false;

    nlohmann::json sealed_welcome;
    sealed_welcome["iv"] = w_iv;
    sealed_welcome["ciphertext"] = w_ct;
    AppendLengthPrefixedFrame(cs.tx_buf, sealed_welcome.dump());

    cs.handshaked = true;
    cs.session_id = sid;
    cs.peer_id = peer.id;
    std::memcpy(cs.key, key32, 32);
    cs.send_counter = 1;
    cs.recv_counter = 1;
    cs.sent_nodes_rev = -1;
    cs.sent_subs_rev = -1;
    QueueEncryptedSnapshot(cs, snapshot_);
    return true;
}

bool RemoteServer::HandleCommandFrame(ClientSession& cs, const std::string& json_str) {
    auto sj = nlohmann::json::parse(json_str, nullptr, false);
    if (sj.is_discarded() || !sj.is_object()) return false;
    if (!sj.contains("iv") || !sj["iv"].is_string() ||
        !sj.contains("ciphertext") || !sj["ciphertext"].is_string()) {
        return false;
    }

    const std::string aad = BuildRemoteAad(cs.session_id, true, cs.recv_counter);
    std::string plain;
    if (!OpenRemoteFrame(cs.key, aad, sj["iv"].get<std::string>(),
                         sj["ciphertext"].get<std::string>(), plain)) {
        return false;
    }
    ++cs.recv_counter;

    auto cj = nlohmann::json::parse(plain, nullptr, false);
    if (cj.is_discarded() || !cj.is_object()) return false;
    const std::string type_s = cj.contains("type") && cj["type"].is_string()
        ? cj["type"].get<std::string>() : std::string{};

    RemoteCommand cmd;
    if (type_s == "look") {
        cmd.type = RemoteCommand::Type::Look;
        cs.sent_nodes_rev = -1;
        cs.sent_subs_rev = -1;
        QueueEncryptedSnapshot(cs, snapshot_);
    } else if (type_s == "connect") {
        cmd.type = RemoteCommand::Type::Connect;
    } else if (type_s == "disconnect") {
        cmd.type = RemoteCommand::Type::Disconnect;
    } else if (type_s == "select") {
        cmd.type = RemoteCommand::Type::Select;
        if (cj.contains("nodeId") && cj["nodeId"].is_string()) cmd.node_id = cj["nodeId"].get<std::string>();
    } else if (type_s == "ping_all") {
        cmd.type = RemoteCommand::Type::PingAll;
        if (cj.contains("nodeIds") && cj["nodeIds"].is_array()) {
            for (const auto& nid : cj["nodeIds"]) {
                if (nid.is_string()) cmd.node_ids.push_back(nid.get<std::string>());
            }
        }
    } else if (type_s == "ping_one") {
        cmd.type = RemoteCommand::Type::PingOne;
        if (cj.contains("nodeId") && cj["nodeId"].is_string()) cmd.node_id = cj["nodeId"].get<std::string>();
    } else if (type_s == "add_sub") {
        cmd.type = RemoteCommand::Type::AddSub;
        if (cj.contains("url") && cj["url"].is_string()) cmd.url = cj["url"].get<std::string>();
        if (cj.contains("name") && cj["name"].is_string()) cmd.name = cj["name"].get<std::string>();
    } else if (type_s == "refresh_sub") {
        cmd.type = RemoteCommand::Type::RefreshSub;
        if (cj.contains("subscriptionId") && cj["subscriptionId"].is_string()) {
            cmd.subscription_id = cj["subscriptionId"].get<std::string>();
        }
    } else if (type_s == "remove_sub") {
        cmd.type = RemoteCommand::Type::RemoveSub;
        if (cj.contains("subscriptionId") && cj["subscriptionId"].is_string()) {
            cmd.subscription_id = cj["subscriptionId"].get<std::string>();
        }
    } else if (type_s == "toggle_sub") {
        cmd.type = RemoteCommand::Type::ToggleSub;
        if (cj.contains("subscriptionId") && cj["subscriptionId"].is_string()) {
            cmd.subscription_id = cj["subscriptionId"].get<std::string>();
        }
        cmd.enabled = cj.value("enabled", true);
    } else if (type_s == "update_settings") {
        cmd.type = RemoteCommand::Type::UpdateSettings;
        if (cj.contains("patch") && cj["patch"].is_object()) {
            cmd.settings_patch_json = cj["patch"].dump();
        }
    } else {
        return true;  // Unknown future command ignored safely
    }

    command_queue_.push_back(std::move(cmd));
    return true;
}

bool RemoteServer::ProcessClientRx(size_t idx) {
    uint8_t buf[4096];
    while (true) {
        net::IoResult rx{};
        {
            SimpleLock lk(mu_);
            if (idx >= clients_.size()) return false;
            rx = clients_[idx].sock.RecvSome(buf, sizeof(buf));
            if (rx.status == net::IoStatus::Ok && rx.bytes > 0) {
                if (clients_[idx].rx_buf.size() + rx.bytes > kRemoteMaxFrameBytes + 16) return false;
                clients_[idx].rx_buf.insert(clients_[idx].rx_buf.end(), buf, buf + rx.bytes);
                clients_[idx].last_rx_ms = net::MonotonicMs();
            }
        }
        if (rx.status == net::IoStatus::WouldBlock) break;
        if (rx.status == net::IoStatus::Eof || rx.status == net::IoStatus::Error) return false;
    }

    while (true) {
        std::string frame_json;
        bool fatal = false;
        {
            SimpleLock lk(mu_);
            if (idx >= clients_.size()) return false;
            if (!TryPopLengthPrefixedFrame(clients_[idx].rx_buf, frame_json, fatal)) {
                return !fatal;
            }
            if (!clients_[idx].handshaked) {
                if (!HandleGreetingFrame(clients_[idx], frame_json)) return false;
            } else {
                if (!HandleCommandFrame(clients_[idx], frame_json)) return false;
            }
        }
    }
}

bool RemoteServer::FlushClientTx(size_t idx) {
    SimpleLock lk(mu_);
    if (idx >= clients_.size()) return false;
    auto& cs = clients_[idx];
    while (cs.tx_off < cs.tx_buf.size()) {
        const auto res = cs.sock.SendSome(cs.tx_buf.data() + cs.tx_off, cs.tx_buf.size() - cs.tx_off);
        if (res.status == net::IoStatus::Ok && res.bytes > 0) {
            cs.tx_off += res.bytes;
            continue;
        }
        if (res.status == net::IoStatus::WouldBlock) break;
        return false;
    }
    if (cs.tx_off >= cs.tx_buf.size()) {
        cs.tx_buf.clear();
        cs.tx_off = 0;
    }
    return true;
}

void RemoteServer::RunLoop() {
    while (!stop_requested_.load()) {
        std::vector<net::PollItem> items;
        {
            SimpleLock lk(mu_);
            if (!listener_.IsValid()) break;
            items.push_back({listener_.Fd(), true, false, false, false, false});
            for (const auto& c : clients_) {
                items.push_back({c.sock.Fd(), true, c.tx_off < c.tx_buf.size(), false, false, false});
            }
        }

        net::PollSockets(items.data(), items.size(), 80);

        if (items[0].rev_read) {
            AcceptNewClients();
        }

        const uint64_t now_ms = net::MonotonicMs();
        std::vector<size_t> to_close;
        {
            SimpleLock lk(mu_);
            const bool broadcast_dirty = snapshot_dirty_;
            snapshot_dirty_ = false;
            for (size_t i = 0; i < clients_.size(); ++i) {
                auto& cs = clients_[i];
                const uint64_t timeout_limit = cs.handshaked ? 25000ULL : 8000ULL;
                if (now_ms - cs.last_rx_ms > timeout_limit) {
                    to_close.push_back(i);
                    continue;
                }
                if (cs.handshaked && (broadcast_dirty || now_ms - cs.last_send_ms >= 1000ULL)) {
                    QueueEncryptedSnapshot(cs, snapshot_);
                }
            }
        }

        for (size_t i = clients_.size(); i > 0; --i) {
            const size_t ci = i - 1;
            const bool closed = std::find(to_close.begin(), to_close.end(), ci) != to_close.end();
            if (closed) {
                CloseClient(ci);
                continue;
            }
            if (!ProcessClientRx(ci) || !FlushClientTx(ci)) {
                CloseClient(ci);
            }
        }
    }
    running_.store(false);
}

bool ApplyRemoteSettingsPatch(std::string_view patch_json, AppSettings& s) {
    auto pj = nlohmann::json::parse(patch_json, nullptr, false);
    if (pj.is_discarded() || !pj.is_object()) return false;

    if (pj.contains("routingMode")) {
        if (pj["routingMode"].is_string()) {
            const std::string rm = pj["routingMode"].get<std::string>();
            if (EqualsCiRemote(rm, "Global")) s.routing_mode = RoutingMode::Global;
            else if (EqualsCiRemote(rm, "Rules")) s.routing_mode = RoutingMode::Rules;
            else if (EqualsCiRemote(rm, "Direct")) s.routing_mode = RoutingMode::Direct;
        } else if (pj["routingMode"].is_number_unsigned()) {
            const uint8_t v = pj["routingMode"].get<uint8_t>();
            if (v <= 2) s.routing_mode = static_cast<RoutingMode>(v);
        }
    }
    if (pj.contains("autoConnectOnBoot") && pj["autoConnectOnBoot"].is_boolean()) {
        s.auto_connect_on_boot = pj["autoConnectOnBoot"].get<bool>();
    }
    if (pj.contains("subscriptionAutoUpdate") && pj["subscriptionAutoUpdate"].is_boolean()) {
        s.subscription_auto_update = pj["subscriptionAutoUpdate"].get<bool>();
    }
    if (pj.contains("subscriptionUpdateMinutes") && pj["subscriptionUpdateMinutes"].is_number_integer()) {
        s.subscription_update_minutes = std::clamp(pj["subscriptionUpdateMinutes"].get<int>(), 15, 10080);
    }
    if (pj.contains("bypassLan") && pj["bypassLan"].is_boolean()) s.bypass_lan = pj["bypassLan"].get<bool>();
    if (pj.contains("blockAds") && pj["blockAds"].is_boolean()) s.block_ads = pj["blockAds"].get<bool>();
    if (pj.contains("blockQuic") && pj["blockQuic"].is_boolean()) s.block_quic = pj["blockQuic"].get<bool>();
    if (pj.contains("enableIpv6") && pj["enableIpv6"].is_boolean()) s.enable_ipv6 = pj["enableIpv6"].get<bool>();
    if (pj.contains("hijackDns") && pj["hijackDns"].is_boolean()) s.hijack_dns = pj["hijackDns"].get<bool>();
    if (pj.contains("dnsFallback") && pj["dnsFallback"].is_boolean()) s.dns_fallback = pj["dnsFallback"].get<bool>();
    if (pj.contains("remoteDns") && pj["remoteDns"].is_string()) s.remote_dns = pj["remoteDns"].get<std::string>();
    if (pj.contains("directDns") && pj["directDns"].is_string()) s.direct_dns = pj["directDns"].get<std::string>();

    if (pj.contains("tlsFingerprint") && pj["tlsFingerprint"].is_string()) {
        const std::string fp = pj["tlsFingerprint"].get<std::string>();
        if (EqualsCiRemote(fp, "Auto")) s.tls_fingerprint = TlsFingerprint::Auto;
        else if (EqualsCiRemote(fp, "Chrome")) s.tls_fingerprint = TlsFingerprint::Chrome;
        else if (EqualsCiRemote(fp, "Firefox")) s.tls_fingerprint = TlsFingerprint::Firefox;
        else if (EqualsCiRemote(fp, "Safari")) s.tls_fingerprint = TlsFingerprint::Safari;
        else if (EqualsCiRemote(fp, "Edge")) s.tls_fingerprint = TlsFingerprint::Edge;
        else if (EqualsCiRemote(fp, "Ios")) s.tls_fingerprint = TlsFingerprint::Ios;
        else if (EqualsCiRemote(fp, "Android")) s.tls_fingerprint = TlsFingerprint::Android;
        else if (EqualsCiRemote(fp, "Qq")) s.tls_fingerprint = TlsFingerprint::Qq;
        else if (EqualsCiRemote(fp, "Random")) s.tls_fingerprint = TlsFingerprint::Random;
        else if (EqualsCiRemote(fp, "Randomized")) s.tls_fingerprint = TlsFingerprint::Randomized;
    }
    if (pj.contains("fragmentMode") && pj["fragmentMode"].is_string()) {
        const std::string fm = pj["fragmentMode"].get<std::string>();
        if (EqualsCiRemote(fm, "Off")) s.fragment_mode = FragmentMode::Off;
        else if (EqualsCiRemote(fm, "TlsHello")) s.fragment_mode = FragmentMode::TlsHello;
        else if (EqualsCiRemote(fm, "TcpSegments")) s.fragment_mode = FragmentMode::TcpSegments;
    }
    if (pj.contains("fragmentScope") && pj["fragmentScope"].is_string()) {
        const std::string fs = pj["fragmentScope"].get<std::string>();
        if (EqualsCiRemote(fs, "TlsOnly")) s.fragment_scope = FragmentScope::TlsOnly;
        else if (EqualsCiRemote(fs, "TlsAndReality")) s.fragment_scope = FragmentScope::TlsAndReality;
        else if (EqualsCiRemote(fs, "All") || EqualsCiRemote(fs, "AllTcp")) s.fragment_scope = FragmentScope::AllTcp;
    }
    if (pj.contains("fragmentLength") && pj["fragmentLength"].is_string()) {
        s.fragment_length = pj["fragmentLength"].get<std::string>();
    }
    if (pj.contains("fragmentInterval") && pj["fragmentInterval"].is_string()) {
        s.fragment_interval = pj["fragmentInterval"].get<std::string>();
    }
    if (pj.contains("fragmentMaxChunks") && pj["fragmentMaxChunks"].is_string()) {
        s.fragment_max_chunks = pj["fragmentMaxChunks"].get<std::string>();
    }
    return true;
}

// --- Client Helpers ---

RemoteBeaconSighting ProbeRemoteBeacon(uint32_t target_ipv4_host, uint16_t beacon_port, int timeout_ms) {
    RemoteBeaconSighting out;
    net::SocketLayerInit();
    net::NetSocket sock = net::NetSocket::CreateUdp(true);
    if (!sock.IsValid()) return {};

    static constexpr char kProbe[] = "yumi-remote-probe-v1";
    if (!sock.UdpSendTo(target_ipv4_host, beacon_port, kProbe, sizeof(kProbe) - 1)) return {};

    const uint64_t dl = net::MonotonicMs() + static_cast<uint64_t>(std::max(100, timeout_ms));
    uint8_t buf[512]{};
    while (net::MonotonicMs() < dl) {
        net::PollItem pi{sock.Fd(), true, false, false, false, false};
        if (net::PollSockets(&pi, 1, 100) <= 0 || !pi.rev_read) continue;
        uint32_t sip = 0;
        uint16_t sport = 0;
        const auto rx = sock.UdpRecvFrom(buf, sizeof(buf), sip, sport);
        if (rx.status != net::IoStatus::Ok || rx.bytes == 0) continue;
        auto bj = nlohmann::json::parse(std::string_view(reinterpret_cast<const char*>(buf), rx.bytes), nullptr, false);
        if (bj.is_discarded() || !bj.is_object()) continue;
        if (bj.value("v", 0) != kRemoteVersion) continue;
        out.host_id = bj.value("id", std::string{});
        out.host_name = bj.value("name", std::string{});
        out.port = static_cast<uint16_t>(bj.value("port", 0));
        out.host = FormatIpv4HostOrder(sip);
        out.valid = !out.host_id.empty() && out.port > 0;
        if (out.valid) break;
    }
    return out;
}

namespace {

bool PerformClientGreeting(net::NetSocket& sock,
                           const uint8_t host_pub65[65],
                           std::string_view secret_utf8,
                           std::string_view peer_id,
                           std::string_view device_name,
                           std::string& out_session_id,
                           uint8_t out_key32[32],
                           nlohmann::json& out_access,
                           int timeout_ms) {
    out_session_id = RandomTokenB64Url(18);
    net::crypto::P256KeyPair my_kp;
    if (!net::crypto::P256GenerateKeyPair(my_kp)) return false;

    uint8_t shared32[32]{};
    if (!net::crypto::P256Ecdh(shared32, my_kp.priv, host_pub65)) return false;
    DeriveRemoteSessionKey(shared32, out_session_id, secret_utf8, out_key32);

    nlohmann::json opening;
    opening["deviceName"] = std::string(device_name);
    std::string iv, ct;
    if (!SealRemoteFrame(out_key32, BuildRemoteAad(out_session_id, true, 0), opening.dump(), iv, ct)) {
        return false;
    }

    const auto my_spki = net::crypto::P256EncodeSpkiDer(my_kp.pub65);
    nlohmann::json greet;
    greet["version"] = kRemoteVersion;
    greet["sessionId"] = out_session_id;
    greet["peerId"] = std::string(peer_id);
    greet["senderPublicKey"] = net::crypto::Base64Encode(my_spki.data(), my_spki.size(), true, false);
    greet["iv"] = iv;
    greet["ciphertext"] = ct;

    if (!BlockingWriteFrame(sock, greet.dump(), timeout_ms)) return false;

    std::string reply_wire;
    if (!BlockingReadFrame(sock, reply_wire, timeout_ms)) return false;
    auto sw = nlohmann::json::parse(reply_wire, nullptr, false);
    if (sw.is_discarded() || !sw.is_object()) return false;
    if (!sw.contains("iv") || !sw["iv"].is_string() ||
        !sw.contains("ciphertext") || !sw["ciphertext"].is_string()) {
        return false;
    }

    std::string access_json;
    if (!OpenRemoteFrame(out_key32, BuildRemoteAad(out_session_id, false, 0),
                         sw["iv"].get<std::string>(), sw["ciphertext"].get<std::string>(), access_json)) {
        return false;
    }
    out_access = nlohmann::json::parse(access_json, nullptr, false);
    return !out_access.is_discarded() && out_access.is_object() && out_access.value("accepted", false);
}

}  // namespace

RemoteBond RemoteClientPair(std::string_view invite_uri, std::string_view device_name, int timeout_ms) {
    RemoteBond bond;
    const RemoteInviteInfo inv = ParseRemoteInviteUri(invite_uri);
    if (!inv.valid) return bond;

    uint32_t ip_host = 0;
    if (!ResolveHostIpv4Order(inv.host, nullptr, ip_host)) return bond;

    net::NetSocket sock;
    if (!sock.ConnectExactBlocking(ip_host, inv.port, timeout_ms)) return bond;

    std::string sid;
    uint8_t key32[32]{};
    nlohmann::json acc;
    if (!PerformClientGreeting(sock, inv.host_pub65, inv.code, "", device_name, sid, key32, acc, timeout_ms)) {
        return bond;
    }

    const auto host_spki = net::crypto::P256EncodeSpkiDer(inv.host_pub65);
    bond.host_id = acc.value("hostId", inv.host_id);
    bond.host_name = acc.value("hostName", inv.host_name);
    bond.host_public_key_b64 = net::crypto::Base64Encode(host_spki.data(), host_spki.size(), true, false);
    bond.peer_id = acc.value("peerId", std::string{});
    bond.secret = acc.value("secret", std::string{});
    bond.last_host = inv.host;
    bond.last_port = inv.port;
    bond.valid = !bond.peer_id.empty() && !bond.secret.empty();
    return bond;
}

bool RemoteClientSessionExchange(const RemoteBond& bond,
                                 uint32_t host_ipv4,
                                 uint16_t port,
                                 std::string_view device_name,
                                 const std::vector<std::string>& raw_command_jsons,
                                 std::vector<std::string>& out_snapshot_jsons,
                                 int timeout_ms) {
    out_snapshot_jsons.clear();
    if (!bond.valid || bond.peer_id.empty() || bond.secret.empty()) return false;

    const auto spki = net::crypto::Base64Decode(bond.host_public_key_b64);
    uint8_t host_pub65[65]{};
    if (!spki.has_value() || !net::crypto::P256DecodeSpkiDer(spki->data(), spki->size(), host_pub65)) {
        return false;
    }

    net::NetSocket sock;
    if (!sock.ConnectExactBlocking(host_ipv4, port, timeout_ms)) return false;

    std::string sid;
    uint8_t key32[32]{};
    nlohmann::json acc;
    if (!PerformClientGreeting(sock, host_pub65, bond.secret, bond.peer_id, device_name,
                               sid, key32, acc, timeout_ms)) {
        return false;
    }

    uint64_t tx_cnt = 1;
    uint64_t rx_cnt = 1;

    // Send requested commands
    for (const auto& cmd_json : raw_command_jsons) {
        std::string iv, ct;
        if (!SealRemoteFrame(key32, BuildRemoteAad(sid, true, tx_cnt++), cmd_json, iv, ct)) return false;
        nlohmann::json frame;
        frame["iv"] = iv;
        frame["ciphertext"] = ct;
        if (!BlockingWriteFrame(sock, frame.dump(), timeout_ms)) return false;
    }

    // Read initial snapshot (and one post-command snapshot if more arrive within short window)
    const uint64_t dl = net::MonotonicMs() + static_cast<uint64_t>(std::max(300, timeout_ms));
    const size_t want_cnt = std::max<size_t>(1, raw_command_jsons.size());
    while (net::MonotonicMs() < dl && out_snapshot_jsons.size() < want_cnt + 1) {
        std::string wire;
        const int rem = static_cast<int>(std::clamp<uint64_t>(dl - net::MonotonicMs(), 50ULL, 400ULL));
        if (!BlockingReadFrame(sock, wire, rem)) {
            if (!out_snapshot_jsons.empty()) break;
            return false;
        }
        auto sw = nlohmann::json::parse(wire, nullptr, false);
        if (sw.is_discarded() || !sw.is_object()) return false;
        if (!sw.contains("iv") || !sw["iv"].is_string() ||
            !sw.contains("ciphertext") || !sw["ciphertext"].is_string()) {
            return false;
        }
        std::string plain;
        if (!OpenRemoteFrame(key32, BuildRemoteAad(sid, false, rx_cnt++),
                             sw["iv"].get<std::string>(), sw["ciphertext"].get<std::string>(), plain)) {
            return false;
        }
        out_snapshot_jsons.push_back(std::move(plain));
    }
    return !out_snapshot_jsons.empty();
}

}  // namespace yumi_nx::logic
