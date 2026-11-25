#include "yumi_nx/simple_dialers.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "yumi_nx/crypto.hpp"
#include "yumi_nx/hysteria2_dialer.hpp"
#include "yumi_nx/shadowsocks_dialer.hpp"
#include "yumi_nx/trojan_dialer.hpp"
#include "yumi_nx/vless_dialer.hpp"
#include "yumi_nx/vmess_dialer.hpp"
#include "yumi_nx/wireguard_dialer.hpp"

namespace yumi_nx::net {

namespace {

inline uint32_t Swap32(uint32_t v) noexcept {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

bool ReadExactBlocking(NetSocket& sock, uint8_t* dst, size_t n, int timeout_ms) noexcept {
    size_t got = 0;
    const uint64_t deadline = MonotonicMs() + static_cast<uint64_t>(timeout_ms);
    while (got < n) {
        const uint64_t now = MonotonicMs();
        if (now >= deadline) return false;
        const auto io = sock.RecvSomeBlocking(dst + got, n - got, static_cast<int>(deadline - now));
        if (io.status != IoStatus::Ok || io.bytes == 0) return false;
        got += io.bytes;
    }
    return true;
}

}  // namespace

// ---------------- DirectStream ----------------

bool DirectStream::Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms) noexcept {
    Close();
    uint32_t ip_be = 0;
    if (!resolver.ResolveIPv4(target.host, ip_be)) return false;
    return sock_.ConnectExactBlocking(Swap32(ip_be), target.port, timeout_ms);
}

IoResult DirectStream::WriteNonBlocking(const uint8_t* data, size_t len) noexcept {
    return sock_.SendSome(data, len);
}

IoResult DirectStream::ReadNonBlocking(uint8_t* out, size_t cap) noexcept {
    return sock_.RecvSome(out, cap);
}

// ---------------- Socks5Stream ----------------

bool Socks5Stream::Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms) noexcept {
    Close();
    uint32_t srv_be = 0;
    if (!resolver.ResolveIPv4(node_.server, srv_be)) return false;
    if (!sock_.ConnectExactBlocking(Swap32(srv_be), node_.port, timeout_ms)) return false;

    const bool has_auth = !node_.uuid_or_user.empty() || !node_.password_or_key.empty();
    uint8_t greet[4] = {0x05, static_cast<uint8_t>(has_auth ? 2 : 1), 0x00, 0x02};
    if (!sock_.SendAllBlocking(greet, has_auth ? 4u : 3u, timeout_ms)) {
        Close();
        return false;
    }

    uint8_t g_rep[2]{};
    if (!ReadExactBlocking(sock_, g_rep, 2, timeout_ms) || g_rep[0] != 0x05 || g_rep[1] == 0xFF) {
        Close();
        return false;
    }

    if (g_rep[1] == 0x02) {
        if (!has_auth) {
            Close();
            return false;
        }
        const size_t ulen = std::min<size_t>(node_.uuid_or_user.size(), 255);
        const size_t plen = std::min<size_t>(node_.password_or_key.size(), 255);
        std::vector<uint8_t> auth;
        auth.reserve(3 + ulen + plen);
        auth.push_back(0x01);
        auth.push_back(static_cast<uint8_t>(ulen));
        auth.insert(auth.end(), node_.uuid_or_user.begin(), node_.uuid_or_user.begin() + static_cast<ptrdiff_t>(ulen));
        auth.push_back(static_cast<uint8_t>(plen));
        auth.insert(auth.end(), node_.password_or_key.begin(), node_.password_or_key.begin() + static_cast<ptrdiff_t>(plen));
        if (!sock_.SendAllBlocking(auth.data(), auth.size(), timeout_ms)) {
            Close();
            return false;
        }
        uint8_t a_rep[2]{};
        if (!ReadExactBlocking(sock_, a_rep, 2, timeout_ms) || a_rep[1] != 0x00) {
            Close();
            return false;
        }
    } else if (g_rep[1] != 0x00) {
        Close();
        return false;
    }

    std::vector<uint8_t> req;
    req.reserve(10 + target.host.size());
    req.push_back(0x05);
    req.push_back(0x01);  // CONNECT
    req.push_back(0x00);

    uint32_t target_ip_host = 0;
    if (ParseIPv4Be(target.host, target_ip_host)) {
        req.push_back(0x01);
        req.push_back(static_cast<uint8_t>((target_ip_host >> 24) & 0xFFu));
        req.push_back(static_cast<uint8_t>((target_ip_host >> 16) & 0xFFu));
        req.push_back(static_cast<uint8_t>((target_ip_host >> 8) & 0xFFu));
        req.push_back(static_cast<uint8_t>(target_ip_host & 0xFFu));
    } else {
        req.push_back(0x03);
        const size_t dlen = std::min<size_t>(target.host.size(), 255);
        req.push_back(static_cast<uint8_t>(dlen));
        req.insert(req.end(), target.host.begin(), target.host.begin() + static_cast<ptrdiff_t>(dlen));
    }
    req.push_back(static_cast<uint8_t>((target.port >> 8) & 0xFFu));
    req.push_back(static_cast<uint8_t>(target.port & 0xFFu));

    if (!sock_.SendAllBlocking(req.data(), req.size(), timeout_ms)) {
        Close();
        return false;
    }

    uint8_t c_rep[4]{};
    if (!ReadExactBlocking(sock_, c_rep, 4, timeout_ms) || c_rep[0] != 0x05 || c_rep[1] != 0x00) {
        Close();
        return false;
    }
    size_t skip = 0;
    if (c_rep[3] == 0x01) skip = 6;
    else if (c_rep[3] == 0x04) skip = 18;
    else if (c_rep[3] == 0x03) {
        uint8_t dlen = 0;
        if (!ReadExactBlocking(sock_, &dlen, 1, timeout_ms)) {
            Close();
            return false;
        }
        skip = dlen + 2u;
    }
    if (skip > 0) {
        std::vector<uint8_t> drain(skip);
        if (!ReadExactBlocking(sock_, drain.data(), drain.size(), timeout_ms)) {
            Close();
            return false;
        }
    }
    return true;
}

IoResult Socks5Stream::WriteNonBlocking(const uint8_t* data, size_t len) noexcept {
    return sock_.SendSome(data, len);
}

IoResult Socks5Stream::ReadNonBlocking(uint8_t* out, size_t cap) noexcept {
    return sock_.RecvSome(out, cap);
}

// ---------------- HttpConnectStream ----------------

bool HttpConnectStream::Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms) noexcept {
    Close();
    uint32_t srv_be = 0;
    if (!resolver.ResolveIPv4(node_.server, srv_be)) return false;
    if (!sock_.ConnectExactBlocking(Swap32(srv_be), node_.port, timeout_ms)) return false;

    std::string req = "CONNECT " + target.host + ":" + std::to_string(target.port) + " HTTP/1.1\r\n"
                      "Host: " + target.host + ":" + std::to_string(target.port) + "\r\n";
    if (!node_.uuid_or_user.empty() || !node_.password_or_key.empty()) {
        const std::string creds = node_.uuid_or_user + ":" + node_.password_or_key;
        req += "Proxy-Authorization: Basic " +
               crypto::Base64Encode(reinterpret_cast<const uint8_t*>(creds.data()), creds.size()) + "\r\n";
    }
    req += "\r\n";

    if (!sock_.SendAllBlocking(req.data(), req.size(), timeout_ms)) {
        Close();
        return false;
    }

    std::string hdr;
    uint8_t ch[512];
    const uint64_t deadline = MonotonicMs() + static_cast<uint64_t>(timeout_ms);
    while (MonotonicMs() < deadline && hdr.size() < 4096) {
        const auto io = sock_.RecvSomeBlocking(ch, sizeof(ch), static_cast<int>(deadline - MonotonicMs()));
        if (io.status != IoStatus::Ok || io.bytes == 0) {
            Close();
            return false;
        }
        hdr.append(reinterpret_cast<const char*>(ch), io.bytes);
        const size_t end = hdr.find("\r\n\r\n");
        if (end != std::string::npos) {
            if (hdr.find(" 200") == std::string::npos && hdr.find(" 200 ") == std::string::npos) {
                Close();
                return false;
            }
            const size_t body_start = end + 4;
            if (body_start < hdr.size()) {
                rx_leftover_.assign(hdr.begin() + static_cast<ptrdiff_t>(body_start), hdr.end());
            }
            return true;
        }
    }
    Close();
    return false;
}

IoResult HttpConnectStream::WriteNonBlocking(const uint8_t* data, size_t len) noexcept {
    return sock_.SendSome(data, len);
}

IoResult HttpConnectStream::ReadNonBlocking(uint8_t* out, size_t cap) noexcept {
    if (rx_off_ < rx_leftover_.size()) {
        const size_t n = std::min(cap, rx_leftover_.size() - rx_off_);
        std::memcpy(out, rx_leftover_.data() + rx_off_, n);
        rx_off_ += n;
        if (rx_off_ >= rx_leftover_.size()) {
            rx_leftover_.clear();
            rx_off_ = 0;
        }
        return {IoStatus::Ok, n};
    }
    return sock_.RecvSome(out, cap);
}

void HttpConnectStream::Close() noexcept {
    sock_.Close();
    rx_leftover_.clear();
    rx_off_ = 0;
}

// ---------------- Factory ----------------

std::unique_ptr<IOutboundStream> CreateOutboundStream(const ProxyNode& node, const AppSettings& settings) {
    switch (node.protocol) {
        case Protocol::Vless:
            return std::unique_ptr<IOutboundStream>(new (std::nothrow) VlessStream(node, settings));
        case Protocol::Vmess:
            return std::unique_ptr<IOutboundStream>(new (std::nothrow) VmessStream(node, settings));
        case Protocol::Trojan:
            return std::unique_ptr<IOutboundStream>(new (std::nothrow) TrojanStream(node, settings));
        case Protocol::Shadowsocks:
            return std::unique_ptr<IOutboundStream>(new (std::nothrow) ShadowsocksStream(node));
        case Protocol::Hysteria2:
            return std::unique_ptr<IOutboundStream>(new (std::nothrow) Hysteria2Stream(node, settings));
        case Protocol::WireGuard:
            return std::unique_ptr<IOutboundStream>(new (std::nothrow) WireGuardStream(node));
        case Protocol::Socks5:
            return std::unique_ptr<IOutboundStream>(new (std::nothrow) Socks5Stream(node));
        case Protocol::Http:
            return std::unique_ptr<IOutboundStream>(new (std::nothrow) HttpConnectStream(node));
        case Protocol::Direct:
        default:
            return std::unique_ptr<IOutboundStream>(new (std::nothrow) DirectStream());
    }
}

}  // namespace yumi_nx::net
