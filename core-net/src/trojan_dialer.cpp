#include "yumi_nx/trojan_dialer.hpp"

#include "yumi_nx/crypto.hpp"
#include "yumi_nx/shadowsocks_dialer.hpp"

namespace yumi_nx::net {

std::vector<uint8_t> EncodeTrojanRequestHeader(std::string_view password,
                                               std::string_view host,
                                               uint16_t port,
                                               uint8_t cmd) {
    uint8_t digest[28]{};
    crypto::Sha224::Digest(password.data(), password.size(), digest);
    const std::string hex = crypto::HexEncode(digest, 28);
    const auto addr = EncodeSocksTargetAddress(host, port);

    std::vector<uint8_t> out;
    out.reserve(56 + 2 + 1 + addr.size() + 2);
    out.insert(out.end(), hex.begin(), hex.end());
    out.push_back('\r');
    out.push_back('\n');
    out.push_back(cmd);
    out.insert(out.end(), addr.begin(), addr.end());
    out.push_back('\r');
    out.push_back('\n');
    return out;
}

bool TrojanStream::Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms) noexcept {
    Close();
    if (node_.password_or_key.empty()) return false;
    // Trojan runs over TLS by default (`ParseProxyUri` sets `tls.enabled = true` unless `security=none`).
    if (!transport_.Connect(node_, settings_, resolver, timeout_ms, false)) return false;

    const auto hdr = EncodeTrojanRequestHeader(node_.password_or_key, target.host, target.port, 0x01);
    if (!transport_.WriteBlocking(hdr.data(), hdr.size(), timeout_ms)) {
        Close();
        return false;
    }
    return true;
}

IoResult TrojanStream::WriteNonBlocking(const uint8_t* data, size_t len) noexcept {
    return transport_.WriteNonBlocking(data, len);
}

IoResult TrojanStream::ReadNonBlocking(uint8_t* out, size_t cap) noexcept {
    return transport_.ReadNonBlocking(out, cap);
}

bool TrojanStream::FlushPending() noexcept {
    return transport_.FlushPending();
}

bool TrojanStream::HasPendingWrite() const noexcept {
    return transport_.HasPendingWrite();
}

void TrojanStream::Close() noexcept {
    transport_.Close();
}

}  // namespace yumi_nx::net
