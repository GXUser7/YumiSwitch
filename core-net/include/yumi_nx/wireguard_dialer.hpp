#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "yumi_nx/net_interfaces.hpp"

namespace yumi_nx::net {

struct WgSessionState {
    uint32_t local_index = 0;
    uint32_t peer_index = 0;
    uint8_t send_key[32]{};
    uint8_t recv_key[32]{};
    uint64_t send_counter = 0;
    uint64_t max_recv_counter = 0;
    bool established = false;
};

struct WgHandshakeScratch {
    uint8_t eph_priv[32]{};
    uint8_t chain_key[32]{};
    uint8_t hash[32]{};
    uint32_t local_index = 0;
    uint8_t peer_static_pub[32]{};
    uint8_t psk[32]{};
    bool has_psk = false;
};

/// WireGuard Noise_IKpsk2 protocol primitives (testable on host & embedded in WireGuardStream).
bool WgBuildHandshakeInitiation(const uint8_t local_static_priv[32],
                                const uint8_t peer_static_pub[32],
                                const uint8_t psk[32],
                                bool has_psk,
                                uint32_t local_index,
                                const uint8_t reserved[3],
                                const uint8_t tai64n[12],
                                WgHandshakeScratch& out_scratch,
                                uint8_t out_msg[148]) noexcept;

bool WgRespondHandshakeInitiation(const uint8_t responder_static_priv[32],
                                  const uint8_t expected_initiator_pub[32],
                                  const uint8_t psk[32],
                                  bool has_psk,
                                  uint32_t responder_index,
                                  const uint8_t msg[148],
                                  uint8_t out_resp[92],
                                  WgSessionState& out_session) noexcept;

bool WgProcessHandshakeResponse(const WgHandshakeScratch& scratch,
                                const uint8_t local_static_priv[32],
                                const uint8_t msg[92],
                                WgSessionState& out_session) noexcept;

std::vector<uint8_t> WgEncryptTransportPacket(WgSessionState& session,
                                              const uint8_t reserved[3],
                                              const uint8_t* ip_packet,
                                              size_t ip_len) noexcept;

bool WgDecryptTransportPacket(WgSessionState& session,
                              const uint8_t* pkt,
                              size_t pkt_len,
                              std::vector<uint8_t>& out_ip_packet) noexcept;

uint16_t IpChecksum16(const uint8_t* data, size_t len) noexcept;
uint16_t TcpChecksumIPv4(uint32_t src_ip_host, uint32_t dst_ip_host, const uint8_t* tcp_seg, size_t tcp_len) noexcept;

/// Compact userspace TCP/IPv4 client stream tunneled over WireGuard UDP Type-4 packets (zero lwIP heap overhead).
class WireGuardStream final : public IOutboundStream {
public:
    explicit WireGuardStream(ProxyNode node) noexcept : node_(std::move(node)) {}
    ~WireGuardStream() override { Close(); }

    Protocol Kind() const noexcept override { return Protocol::WireGuard; }
    bool Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms = 6000) noexcept override;
    IoResult WriteNonBlocking(const uint8_t* data, size_t len) noexcept override;
    IoResult ReadNonBlocking(uint8_t* out, size_t cap) noexcept override;
    bool FlushPending() noexcept override;
    bool HasPendingWrite() const noexcept override;
    SocketFd NativeFd() const noexcept override { return udp_.Fd(); }
    void Close() noexcept override;

private:
    bool SendTcpSegment(uint8_t flags, const uint8_t* payload, size_t len) noexcept;
    void HandleIncomingUdpPackets() noexcept;

    ProxyNode node_;
    NetSocket udp_{};
    WgSessionState session_{};
    uint32_t server_ip_host_ = 0;
    uint16_t server_port_ = 51820;

    uint32_t local_ip_host_ = 0x0A000002u;  // 10.0.0.2 fallback
    uint32_t remote_ip_host_ = 0;
    uint16_t local_tcp_port_ = 41000;
    uint16_t remote_tcp_port_ = 0;

    uint32_t tcp_snd_nxt_ = 1;
    uint32_t tcp_rcv_nxt_ = 0;
    bool tcp_connected_ = false;
    bool tcp_remote_fin_ = false;

    std::vector<uint8_t> app_rx_buf_;
    size_t app_rx_off_ = 0;
};

}  // namespace yumi_nx::net
