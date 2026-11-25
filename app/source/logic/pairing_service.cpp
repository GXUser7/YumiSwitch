#include "pairing_service.hpp"

#include <algorithm>
#include <cstring>
#include <nlohmann/json.hpp>

namespace yumi_nx::logic {

namespace {

bool WriteLengthPrefixedFrame(net::NetSocket& sock, const std::string& json_payload, int timeout_ms) noexcept {
    if (json_payload.empty() || json_payload.size() > kPairingMaxFrameBytes) return false;
    const uint32_t len = static_cast<uint32_t>(json_payload.size());
    uint8_t hdr[4]{
        static_cast<uint8_t>((len >> 24) & 0xFFu),
        static_cast<uint8_t>((len >> 16) & 0xFFu),
        static_cast<uint8_t>((len >> 8) & 0xFFu),
        static_cast<uint8_t>(len & 0xFFu),
    };
    if (!sock.SendAllBlocking(hdr, 4, timeout_ms)) return false;
    return sock.SendAllBlocking(json_payload.data(), json_payload.size(), timeout_ms);
}

bool RecvExactBlocking(net::NetSocket& sock, uint8_t* out, size_t len, int timeout_ms) noexcept {
    size_t got = 0;
    const uint64_t dl = net::MonotonicMs() + static_cast<uint64_t>(std::max(1, timeout_ms));
    while (got < len) {
        const uint64_t now = net::MonotonicMs();
        if (now >= dl) return false;
        const int rem = static_cast<int>(std::clamp<uint64_t>(dl - now, 20ULL, 1000ULL));
        const auto res = sock.RecvSomeBlocking(out + got, len - got, rem);
        if (res.status == net::IoStatus::Ok && res.bytes > 0) {
            got += res.bytes;
            continue;
        }
        if (res.status == net::IoStatus::WouldBlock) continue;
        return false;
    }
    return true;
}

bool ReadLengthPrefixedFrame(net::NetSocket& sock, std::string& out_json, int timeout_ms) {
    uint8_t hdr[4]{};
    if (!RecvExactBlocking(sock, hdr, 4, timeout_ms)) return false;
    const uint32_t len = (uint32_t(hdr[0]) << 24) | (uint32_t(hdr[1]) << 16) |
                         (uint32_t(hdr[2]) << 8) | uint32_t(hdr[3]);
    if (len == 0 || len > kPairingMaxFrameBytes) return false;
    out_json.resize(len);
    return RecvExactBlocking(sock, reinterpret_cast<uint8_t*>(out_json.data()), len, timeout_ms);
}

bool SealGcmCombined(const uint8_t key32[32],
                     std::string_view aad_str,
                     std::string_view plaintext,
                     std::string& out_iv_b64,
                     std::string& out_ct_b64) {
    uint8_t iv[12]{};
    if (!net::crypto::RandomBytes(iv, sizeof(iv))) return false;
    std::vector<uint8_t> buf(plaintext.size() + 16);
    uint8_t tag[16]{};
    if (!net::crypto::AesGcmEncrypt(
            key32,
            32,
            iv,
            reinterpret_cast<const uint8_t*>(aad_str.data()),
            aad_str.size(),
            reinterpret_cast<const uint8_t*>(plaintext.data()),
            plaintext.size(),
            buf.data(),
            tag)) {
        return false;
    }
    std::memcpy(buf.data() + plaintext.size(), tag, 16);
    out_iv_b64 = net::crypto::Base64Encode(iv, sizeof(iv), true, false);
    out_ct_b64 = net::crypto::Base64Encode(buf.data(), buf.size(), true, false);
    return true;
}

bool OpenGcmCombined(const uint8_t key32[32],
                     std::string_view aad_str,
                     std::string_view iv_b64,
                     std::string_view ct_b64,
                     std::string& out_plaintext) {
    const auto iv = net::crypto::Base64Decode(iv_b64);
    const auto ct = net::crypto::Base64Decode(ct_b64);
    if (!iv.has_value() || iv->size() != 12) return false;
    if (!ct.has_value() || ct->size() < 16) return false;
    const size_t pt_len = ct->size() - 16;
    out_plaintext.resize(pt_len);
    uint8_t* pt_dst = pt_len > 0 ? reinterpret_cast<uint8_t*>(out_plaintext.data()) : nullptr;
    return net::crypto::AesGcmDecrypt(
        key32,
        32,
        iv->data(),
        reinterpret_cast<const uint8_t*>(aad_str.data()),
        aad_str.size(),
        ct->data(),
        pt_len,
        ct->data() + pt_len,
        pt_dst);
}

std::string RandomPairingSessionId() {
    uint8_t rnd[18]{};
    if (!net::crypto::RandomBytes(rnd, sizeof(rnd))) {
        const uint64_t ticks = net::MonotonicMs();
        std::memcpy(rnd, &ticks, sizeof(ticks));
    }
    return net::crypto::Base64Encode(rnd, sizeof(rnd), true, false);
}

bool StartsWithCi(std::string_view s, std::string_view prefix) noexcept {
    if (s.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        const char a = s[i];
        const char b = prefix[i];
        const char la = (a >= 'A' && a <= 'Z') ? static_cast<char>(a + ('a' - 'A')) : a;
        const char lb = (b >= 'A' && b <= 'Z') ? static_cast<char>(b + ('a' - 'A')) : b;
        if (la != lb) return false;
    }
    return true;
}

bool EqualsCiStr(std::string_view a, std::string_view b) noexcept {
    return a.size() == b.size() && StartsWithCi(a, b);
}

bool HasCrLf(std::string_view s) noexcept {
    return s.find('\r') != std::string_view::npos || s.find('\n') != std::string_view::npos;
}

bool ValidateTransfer(const SubscriptionTransfer& tr) noexcept {
    if (tr.version != kPairingProtocolVersion) return false;
    if (tr.name.empty() || tr.name.size() > 256) return false;
    if (tr.url.size() < 8 || tr.url.size() > 16384) return false;
    if (!StartsWithCi(tr.url, "https://") && !StartsWithCi(tr.url, "http://")) return false;
    if (tr.user_agent_override.size() > 1024 || HasCrLf(tr.user_agent_override)) return false;
    if (tr.headers.size() > 32) return false;
    for (const auto& kv : tr.headers) {
        if (kv.first.empty() || kv.first.size() > 128 || kv.second.size() > 4096) return false;
        if (EqualsCiStr(kv.first, "x-hwid") || HasCrLf(kv.first) || HasCrLf(kv.second)) return false;
    }
    return true;
}

}  // namespace

void DerivePairingKey(const uint8_t shared32[32],
                      std::string_view session_id,
                      uint8_t out_key32[32]) noexcept {
    uint8_t salt[32]{};
    net::crypto::Sha256::Digest(session_id.data(), session_id.size(), salt);
    uint8_t extract[32]{};
    net::crypto::HmacSha256(salt, sizeof(salt), shared32, 32, extract);
    static constexpr uint8_t kInfo[13] = {
        'y', 'u', 'm', 'i', '-', 'p', 'a', 'i', 'r', '-', 'v', '1', 0x01
    };
    net::crypto::HmacSha256(extract, sizeof(extract), kInfo, sizeof(kInfo), out_key32);
}

std::string BuildPairUri(std::string_view host,
                         uint16_t port,
                         std::string_view session_id,
                         const uint8_t pub65[65],
                         std::string_view host_name) {
    const auto spki = net::crypto::P256EncodeSpkiDer(pub65);
    const std::string key_b64 = net::crypto::Base64Encode(spki.data(), spki.size(), true, false);
    std::string out = "yumi://pair?v=" + std::to_string(kPairingProtocolVersion);
    out += "&host=" + UrlEncode(host);
    out += "&port=" + std::to_string(port);
    out += "&sid=" + UrlEncode(session_id);
    out += "&key=" + UrlEncode(key_b64);
    if (!host_name.empty()) {
        out += "&name=" + UrlEncode(host_name);
    }
    return out;
}

PairingLinkInfo ParsePairUri(std::string_view uri) {
    PairingLinkInfo info;
    if (uri.rfind("yumi://pair", 0) != 0) return {};
    const size_t q = uri.find('?');
    if (q == std::string_view::npos) return {};
    std::string_view query = uri.substr(q + 1);
    const size_t hash = query.find('#');
    if (hash != std::string_view::npos) query = query.substr(0, hash);

    std::string key_b64;
    size_t pos = 0;
    while (pos < query.size()) {
        const size_t amp = query.find('&', pos);
        const std::string_view pair = (amp == std::string_view::npos)
            ? query.substr(pos)
            : query.substr(pos, amp - pos);
        const size_t eq = pair.find('=');
        if (eq != std::string_view::npos) {
            const std::string_view k = pair.substr(0, eq);
            const std::string val = UrlDecode(pair.substr(eq + 1));
            if (k == "v") {
                uint64_t ver = 0;
                if (!ParseUnsignedDecimal(val, ver) || ver != kPairingProtocolVersion) return {};
                info.version = static_cast<int>(ver);
            } else if (k == "host") {
                info.host = val;
            } else if (k == "port") {
                uint64_t p = 0;
                if (!ParseUnsignedDecimal(val, p) || p == 0 || p > 65535) return {};
                info.port = static_cast<uint16_t>(p);
            } else if (k == "sid") {
                info.session_id = val;
            } else if (k == "key") {
                key_b64 = val;
            } else if (k == "name") {
                info.receiver_name = val;
            }
        }
        if (amp == std::string_view::npos) break;
        pos = amp + 1;
    }

    if (info.host.empty() || info.port == 0 || info.session_id.empty() || key_b64.empty()) {
        return {};
    }
    const auto spki = net::crypto::Base64Decode(key_b64);
    if (!spki.has_value() || !net::crypto::P256DecodeSpkiDer(spki->data(), spki->size(), info.receiver_pub65)) {
        return {};
    }
    info.valid = true;
    return info;
}

bool PairingServer::Start(std::string advertise_host,
                          std::string host_name,
                          bool loopback_only,
                          uint16_t preferred_port,
                          DecisionCallback on_transfer) {
    Stop();
    net::SocketLayerInit();

    net::crypto::P256KeyPair kp;
    if (!net::crypto::P256GenerateKeyPair(kp)) return false;

    uint16_t port = preferred_port;
    net::NetSocket sock = TcpListenSocket(loopback_only, port);
    if (!sock.IsValid() || port == 0) return false;

    const std::string sid = RandomPairingSessionId();
    const std::string host_adv = advertise_host.empty()
        ? (loopback_only ? std::string("127.0.0.1") : std::string("0.0.0.0"))
        : std::move(advertise_host);
    const std::string name_adv = host_name.empty() ? std::string("Nintendo Switch") : std::move(host_name);
    const std::string uri = BuildPairUri(host_adv, port, sid, kp.pub65, name_adv);

    {
        SimpleLock lk(mu_);
        listener_ = std::move(sock);
        port_ = port;
        advertise_host_ = host_adv;
        host_name_ = name_adv;
        session_id_ = sid;
        share_url_ = uri;
        keypair_ = kp;
        expires_at_ms_ = static_cast<int64_t>(net::MonotonicMs()) + kPairingLifetimeMs;
        on_transfer_ = std::move(on_transfer);
        pending_transfer_.reset();
        decision_ready_ = false;
        decision_accept_ = false;
        decision_status_.clear();
        state_ = PairingServerState::Listening;
        status_message_ = "Отсканируйте QR в Yumi на телефоне";
    }

    stop_requested_.store(false);
    running_.store(true);
    if (!worker_.Start(&PairingServer::ThreadEntry, this, 0x10000)) {
        Stop();
        return false;
    }
    return true;
}

void PairingServer::Stop() noexcept {
    stop_requested_.store(true);
    {
        SimpleLock lk(mu_);
        listener_.Close();
    }
    worker_.Join();
    running_.store(false);
    {
        SimpleLock lk(mu_);
        if (state_ == PairingServerState::Listening || state_ == PairingServerState::AwaitingConfirm) {
            state_ = PairingServerState::Idle;
        }
    }
}

void PairingServer::SubmitDecision(bool accept, std::string status_override) {
    SimpleLock lk(mu_);
    decision_accept_ = accept;
    decision_status_ = std::move(status_override);
    decision_ready_ = true;
}

PairingSessionSnapshot PairingServer::Snapshot() {
    SimpleLock lk(mu_);
    PairingSessionSnapshot s;
    s.state = state_;
    s.port = port_;
    s.session_id = session_id_;
    s.share_url = share_url_;
    s.expires_at_epoch_ms = expires_at_ms_;
    s.pending_transfer = pending_transfer_;
    s.status_message = status_message_;
    return s;
}

std::string PairingServer::ShareUrl() {
    SimpleLock lk(mu_);
    return share_url_;
}

void PairingServer::ThreadEntry(void* arg) {
    if (auto* self = static_cast<PairingServer*>(arg)) {
        self->RunLoop();
    }
}

void PairingServer::RunLoop() {
    while (!stop_requested_.load()) {
        int64_t exp = 0;
        net::SocketFd fd = net::kInvalidSocket;
        {
            SimpleLock lk(mu_);
            exp = expires_at_ms_;
            fd = listener_.Fd();
        }
        if (fd == net::kInvalidSocket) break;
        if (static_cast<int64_t>(net::MonotonicMs()) >= exp) {
            SimpleLock lk(mu_);
            state_ = PairingServerState::Expired;
            status_message_ = "Срок действия QR-кода истёк";
            break;
        }

        net::PollItem p{};
        p.fd = fd;
        p.want_read = true;
        if (net::PollSockets(&p, 1, 100) <= 0 || !p.rev_read) continue;

        net::NetSocket cli;
        {
            SimpleLock lk(mu_);
            uint32_t peer_ip = 0;
            uint16_t peer_port = 0;
            cli = listener_.Accept(peer_ip, peer_port);
        }
        if (cli.IsValid()) {
            HandleClient(std::move(cli));
            SimpleLock lk(mu_);
            if (state_ == PairingServerState::Completed ||
                state_ == PairingServerState::Rejected ||
                state_ == PairingServerState::Expired) {
                break;
            }
        }
    }
    running_.store(false);
}

void PairingServer::HandleClient(net::NetSocket client) {
    std::string raw_req;
    if (!ReadLengthPrefixedFrame(client, raw_req, 8000)) return;

    auto env = nlohmann::json::parse(raw_req, nullptr, false);
    if (env.is_discarded() || !env.is_object()) return;

    std::string req_sid;
    std::string sender_pub_b64;
    std::string iv_b64;
    std::string ct_b64;
    if (env.contains("sessionId") && env["sessionId"].is_string()) req_sid = env["sessionId"].get<std::string>();
    if (env.contains("senderPublicKey") && env["senderPublicKey"].is_string()) sender_pub_b64 = env["senderPublicKey"].get<std::string>();
    if (env.contains("iv") && env["iv"].is_string()) iv_b64 = env["iv"].get<std::string>();
    if (env.contains("ciphertext") && env["ciphertext"].is_string()) ct_b64 = env["ciphertext"].get<std::string>();

    std::string expected_sid;
    net::crypto::P256KeyPair kp{};
    int64_t exp = 0;
    DecisionCallback cb;
    {
        SimpleLock lk(mu_);
        expected_sid = session_id_;
        kp = keypair_;
        exp = expires_at_ms_;
        cb = on_transfer_;
    }

    if (req_sid.empty() || req_sid != expected_sid) {
        return;
    }

    const auto sender_spki = net::crypto::Base64Decode(sender_pub_b64);
    uint8_t sender_pub65[65]{};
    if (!sender_spki.has_value() ||
        !net::crypto::P256DecodeSpkiDer(sender_spki->data(), sender_spki->size(), sender_pub65)) {
        return;
    }

    uint8_t shared32[32]{};
    if (!net::crypto::P256Ecdh(shared32, kp.priv, sender_pub65)) {
        return;
    }
    uint8_t aes_key[32]{};
    DerivePairingKey(shared32, expected_sid, aes_key);

    auto send_reply = [&](const PairingResult& res) {
        nlohmann::json rj;
        rj["accepted"] = res.accepted;
        rj["status"] = res.status;
        if (!res.subscription_name.empty()) rj["subscriptionName"] = res.subscription_name;
        const std::string reply_aad = "yumi-pair-v1:" + expected_sid + ":reply";
        std::string r_iv, r_ct;
        if (SealGcmCombined(aes_key, reply_aad, rj.dump(), r_iv, r_ct)) {
            nlohmann::json re;
            re["iv"] = r_iv;
            re["ciphertext"] = r_ct;
            WriteLengthPrefixedFrame(client, re.dump(), 4000);
        }
    };

    if (static_cast<int64_t>(net::MonotonicMs()) >= exp) {
        send_reply({false, "expired", ""});
        SimpleLock lk(mu_);
        state_ = PairingServerState::Expired;
        status_message_ = "Сессия истекла";
        return;
    }

    const std::string req_aad = "yumi-pair-v1:" + expected_sid + ":request";
    std::string pt_json;
    if (!OpenGcmCombined(aes_key, req_aad, iv_b64, ct_b64, pt_json)) {
        send_reply({false, "decrypt_failed", ""});
        return;
    }

    auto pj = nlohmann::json::parse(pt_json, nullptr, false);
    if (pj.is_discarded() || !pj.is_object()) {
        send_reply({false, "invalid_payload", ""});
        return;
    }

    SubscriptionTransfer tr;
    tr.version = pj.value("version", 1);
    if (pj.contains("name") && pj["name"].is_string()) tr.name = pj["name"].get<std::string>();
    if (pj.contains("url") && pj["url"].is_string()) tr.url = pj["url"].get<std::string>();
    if (pj.contains("userAgentOverride") && pj["userAgentOverride"].is_string()) {
        tr.user_agent_override = pj["userAgentOverride"].get<std::string>();
    }
    if (pj.contains("headers") && pj["headers"].is_object()) {
        for (const auto& kv : pj["headers"].items()) {
            if (kv.value().is_string()) tr.headers.emplace_back(kv.key(), kv.value().get<std::string>());
        }
    }

    if (tr.name.empty()) tr.name = "Yumi Подписка";
    if (!ValidateTransfer(tr)) {
        send_reply({false, "invalid_transfer", tr.name});
        return;
    }

    PairingResult decision;
    if (cb) {
        decision = cb(tr);
    } else {
        {
            SimpleLock lk(mu_);
            pending_transfer_ = tr;
            decision_ready_ = false;
            state_ = PairingServerState::AwaitingConfirm;
            status_message_ = "Получена подписка: " + tr.name;
        }
        const uint64_t confirm_dl = net::MonotonicMs() + 60000ULL;
        bool decided = false;
        while (!stop_requested_.load() && net::MonotonicMs() < confirm_dl) {
            {
                SimpleLock lk(mu_);
                if (decision_ready_) {
                    decision.accepted = decision_accept_;
                    decision.status = decision_status_.empty()
                        ? (decision_accept_ ? "accepted" : "rejected")
                        : decision_status_;
                    decision.subscription_name = tr.name;
                    decided = true;
                    break;
                }
            }
            SleepMs(35);
        }
        if (!decided) {
            decision = {false, "timeout", tr.name};
        }
    }

    if (decision.subscription_name.empty()) decision.subscription_name = tr.name;
    if (decision.status.empty()) decision.status = decision.accepted ? "accepted" : "rejected";
    send_reply(decision);

    SimpleLock lk(mu_);
    pending_transfer_ = tr;
    state_ = decision.accepted ? PairingServerState::Completed : PairingServerState::Rejected;
    status_message_ = decision.accepted ? ("Импортировано: " + tr.name) : "Отклонено";
}

PairingResult SendPairingSubscription(std::string_view pair_uri,
                                      const SubscriptionTransfer& transfer,
                                      int timeout_ms) {
    PairingResult res;
    const PairingLinkInfo link = ParsePairUri(pair_uri);
    if (!link.valid) {
        res.status = "invalid_uri";
        return res;
    }

    net::SocketLayerInit();
    uint32_t ip_host = 0;
    if (!ResolveHostIpv4Order(link.host, nullptr, ip_host)) {
        res.status = "resolve_failed";
        return res;
    }

    net::NetSocket sock;
    if (!sock.ConnectExactBlocking(ip_host, link.port, timeout_ms)) {
        res.status = "connect_failed";
        return res;
    }

    net::crypto::P256KeyPair my_kp;
    if (!net::crypto::P256GenerateKeyPair(my_kp)) {
        res.status = "keygen_failed";
        return res;
    }

    uint8_t shared32[32]{};
    if (!net::crypto::P256Ecdh(shared32, my_kp.priv, link.receiver_pub65)) {
        res.status = "ecdh_failed";
        return res;
    }
    uint8_t aes_key[32]{};
    DerivePairingKey(shared32, link.session_id, aes_key);

    nlohmann::json payload;
    payload["version"] = transfer.version;
    payload["name"] = transfer.name;
    payload["url"] = transfer.url;
    if (!transfer.user_agent_override.empty()) {
        payload["userAgentOverride"] = transfer.user_agent_override;
    }
    nlohmann::json hdrs = nlohmann::json::object();
    for (const auto& kv : transfer.headers) {
        hdrs[kv.first] = kv.second;
    }
    payload["headers"] = hdrs;

    const std::string req_aad = "yumi-pair-v1:" + link.session_id + ":request";
    std::string iv_b64, ct_b64;
    if (!SealGcmCombined(aes_key, req_aad, payload.dump(), iv_b64, ct_b64)) {
        res.status = "encrypt_failed";
        return res;
    }

    const auto my_spki = net::crypto::P256EncodeSpkiDer(my_kp.pub65);
    nlohmann::json env;
    env["sessionId"] = link.session_id;
    env["senderPublicKey"] = net::crypto::Base64Encode(my_spki.data(), my_spki.size(), true, false);
    env["iv"] = iv_b64;
    env["ciphertext"] = ct_b64;

    if (!WriteLengthPrefixedFrame(sock, env.dump(), timeout_ms)) {
        res.status = "send_failed";
        return res;
    }

    std::string reply_wire;
    if (!ReadLengthPrefixedFrame(sock, reply_wire, timeout_ms)) {
        res.status = "recv_failed";
        return res;
    }

    auto renv = nlohmann::json::parse(reply_wire, nullptr, false);
    if (renv.is_discarded() || !renv.is_object()) {
        res.status = "bad_reply_frame";
        return res;
    }
    if (!renv.contains("iv") || !renv["iv"].is_string() ||
        !renv.contains("ciphertext") || !renv["ciphertext"].is_string()) {
        res.status = "bad_reply_fields";
        return res;
    }

    const std::string reply_aad = "yumi-pair-v1:" + link.session_id + ":reply";
    std::string pt_reply;
    if (!OpenGcmCombined(aes_key, reply_aad,
                         renv["iv"].get<std::string>(),
                         renv["ciphertext"].get<std::string>(),
                         pt_reply)) {
        res.status = "reply_decrypt_failed";
        return res;
    }

    auto rj = nlohmann::json::parse(pt_reply, nullptr, false);
    if (rj.is_discarded() || !rj.is_object()) {
        res.status = "bad_reply_json";
        return res;
    }
    res.accepted = rj.value("accepted", false);
    if (rj.contains("status") && rj["status"].is_string()) res.status = rj["status"].get<std::string>();
    if (rj.contains("subscriptionName") && rj["subscriptionName"].is_string()) {
        res.subscription_name = rj["subscriptionName"].get<std::string>();
    }
    return res;
}

}  // namespace yumi_nx::logic
