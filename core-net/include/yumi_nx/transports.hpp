#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "yumi_nx/models.hpp"
#include "yumi_nx/net_interfaces.hpp"
#include "yumi_nx/socket_io.hpp"
#include "yumi_nx/tls13_reality.hpp"

namespace yumi_nx::net {

/// Composable stream transport layer (`Raw`, `WebSocket`, `HttpUpgrade`, `Grpc`, `Xhttp`)
/// running over TCP + optional TLS 1.3 / XTLS-REALITY / uTLS / FragmentMode.
class TransportPipeline {
public:
    TransportPipeline() noexcept = default;
    ~TransportPipeline() { Close(); }

    TransportPipeline(const TransportPipeline&) = delete;
    TransportPipeline& operator=(const TransportPipeline&) = delete;

    /// Connects to `node.server:node.port`, performs TLS/REALITY handshake if enabled,
    /// then upgrades stream transport (`WebSocket` / `HttpUpgrade` / `Grpc` / `Xhttp`).
    bool Connect(const ProxyNode& node,
                 const AppSettings& settings,
                 IDnsResolver& resolver,
                 int timeout_ms = 6000,
                 bool force_tls_on = false) noexcept;

    bool WriteBlocking(const uint8_t* data, size_t len, int timeout_ms = 5000) noexcept;
    IoResult WriteNonBlocking(const uint8_t* data, size_t len) noexcept;
    IoResult ReadNonBlocking(uint8_t* out, size_t cap) noexcept;
    bool FlushPending() noexcept;

    [[nodiscard]] bool HasPendingWrite() const noexcept;
    [[nodiscard]] SocketFd NativeFd() const noexcept { return sock_.Fd(); }
    [[nodiscard]] bool IsTlsActive() const noexcept { return use_tls_; }

    /// Enables raw direct-copy mode for XTLS-Vision when TLS is active over Raw TCP.
    void SetTlsDirectCopy(bool enabled) noexcept {
        if (use_tls_) tls_.SetDirectCopy(enabled);
    }

    void Close() noexcept;

private:
    bool RawWriteBlocking(const uint8_t* data, size_t len, int timeout_ms) noexcept;
    IoResult RawWriteNonBlocking(const uint8_t* data, size_t len) noexcept;
    IoResult RawReadNonBlocking(uint8_t* out, size_t cap) noexcept;
    IoResult RawReadBlocking(uint8_t* out, size_t cap, int timeout_ms) noexcept;
    bool FlushTxBuf() noexcept;

    bool HandshakeWebSocket(const ProxyNode& node, int timeout_ms) noexcept;
    bool HandshakeHttpUpgrade(const ProxyNode& node, int timeout_ms) noexcept;
    bool HandshakeGrpc(const ProxyNode& node, int timeout_ms) noexcept;
    bool HandshakeXhttp(const ProxyNode& node, int timeout_ms) noexcept;

    void ProcessIncomingWs() noexcept;
    void ProcessIncomingGrpc() noexcept;
    void ProcessIncomingXhttp() noexcept;

    NetSocket sock_{};
    Tls13Client tls_{};
    TransportKind kind_ = TransportKind::Raw;
    bool use_tls_ = false;
    bool remote_eof_ = false;
    bool xhttp_chunked_rx_ = true;
    size_t xhttp_chunk_rem_ = 0;
    bool xhttp_need_crlf_ = false;

    std::vector<uint8_t> tx_buf_;
    size_t tx_off_ = 0;

    std::vector<uint8_t> raw_rx_buf_;
    std::vector<uint8_t> pt_rx_buf_;
    size_t pt_rx_off_ = 0;
};

}  // namespace yumi_nx::net
