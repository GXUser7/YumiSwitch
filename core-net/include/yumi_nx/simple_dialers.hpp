#pragma once

#include <string>
#include <vector>

#include "yumi_nx/net_interfaces.hpp"

namespace yumi_nx::net {

class DirectStream final : public IOutboundStream {
public:
    Protocol Kind() const noexcept override { return Protocol::Direct; }
    bool Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms = 6000) noexcept override;
    IoResult WriteNonBlocking(const uint8_t* data, size_t len) noexcept override;
    IoResult ReadNonBlocking(uint8_t* out, size_t cap) noexcept override;
    bool FlushPending() noexcept override { return true; }
    bool HasPendingWrite() const noexcept override { return false; }
    SocketFd NativeFd() const noexcept override { return sock_.Fd(); }
    void Close() noexcept override { sock_.Close(); }

private:
    NetSocket sock_{};
};

class Socks5Stream final : public IOutboundStream {
public:
    explicit Socks5Stream(ProxyNode node) noexcept : node_(std::move(node)) {}
    ~Socks5Stream() override { Close(); }

    Protocol Kind() const noexcept override { return Protocol::Socks5; }
    bool Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms = 6000) noexcept override;
    IoResult WriteNonBlocking(const uint8_t* data, size_t len) noexcept override;
    IoResult ReadNonBlocking(uint8_t* out, size_t cap) noexcept override;
    bool FlushPending() noexcept override { return true; }
    bool HasPendingWrite() const noexcept override { return false; }
    SocketFd NativeFd() const noexcept override { return sock_.Fd(); }
    void Close() noexcept override { sock_.Close(); }

private:
    ProxyNode node_;
    NetSocket sock_{};
};

class HttpConnectStream final : public IOutboundStream {
public:
    explicit HttpConnectStream(ProxyNode node) noexcept : node_(std::move(node)) {}
    ~HttpConnectStream() override { Close(); }

    Protocol Kind() const noexcept override { return Protocol::Http; }
    bool Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms = 6000) noexcept override;
    IoResult WriteNonBlocking(const uint8_t* data, size_t len) noexcept override;
    IoResult ReadNonBlocking(uint8_t* out, size_t cap) noexcept override;
    bool FlushPending() noexcept override { return true; }
    bool HasPendingWrite() const noexcept override { return false; }
    SocketFd NativeFd() const noexcept override { return sock_.Fd(); }
    void Close() noexcept override;

private:
    ProxyNode node_;
    NetSocket sock_{};
    std::vector<uint8_t> rx_leftover_;
    size_t rx_off_ = 0;
};

}  // namespace yumi_nx::net
