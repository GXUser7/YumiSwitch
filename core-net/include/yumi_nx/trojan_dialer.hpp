#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "yumi_nx/models.hpp"
#include "yumi_nx/net_interfaces.hpp"
#include "yumi_nx/transports.hpp"

namespace yumi_nx::net {

/// Encodes Trojan request header: `hex(SHA224(password)) + "\r\n" + cmd(1) + SOCKS5_addr + "\r\n"`.
std::vector<uint8_t> EncodeTrojanRequestHeader(std::string_view password,
                                               std::string_view host,
                                               uint16_t port,
                                               uint8_t cmd = 0x01);

class TrojanStream final : public IOutboundStream {
public:
    explicit TrojanStream(ProxyNode node, AppSettings settings = {}) noexcept
        : node_(std::move(node)), settings_(std::move(settings)) {}
    ~TrojanStream() override { Close(); }

    Protocol Kind() const noexcept override { return Protocol::Trojan; }
    bool Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms = 6000) noexcept override;
    IoResult WriteNonBlocking(const uint8_t* data, size_t len) noexcept override;
    IoResult ReadNonBlocking(uint8_t* out, size_t cap) noexcept override;
    bool FlushPending() noexcept override;
    bool HasPendingWrite() const noexcept override;
    SocketFd NativeFd() const noexcept override { return transport_.NativeFd(); }
    void Close() noexcept override;

private:
    ProxyNode node_;
    AppSettings settings_;
    TransportPipeline transport_{};
};

}  // namespace yumi_nx::net
