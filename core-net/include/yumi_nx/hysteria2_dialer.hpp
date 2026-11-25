#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "yumi_nx/models.hpp"
#include "yumi_nx/net_interfaces.hpp"
#include "yumi_nx/socket_io.hpp"
#include "yumi_nx/tls13_reality.hpp"

namespace yumi_nx::net {

struct QuicLevelKeys {
    uint16_t cipher_suite = 0x1301;
    size_t key_len = 16;
    uint8_t key[32]{};
    uint8_t iv[12]{};
    uint8_t hp[32]{};
    uint64_t next_pn = 0;
    uint64_t largest_rx_pn = 0;
    bool ready = false;
};

void QuicEncodeVarint(std::vector<uint8_t>& out, uint64_t v);
bool QuicDecodeVarint(const uint8_t* data, size_t len, size_t& out_consumed, uint64_t& out_val) noexcept;

/// RFC 9001 Section 5.2 QUIC v1 Initial key derivation (AES-128-GCM + HP).
bool QuicDeriveInitialKeys(const uint8_t* dcid,
                           size_t dcid_len,
                           bool is_client,
                           QuicLevelKeys& out_keys) noexcept;

bool QuicDeriveTrafficKeys(uint16_t cipher_suite,
                           bool use_sha384,
                           const uint8_t* secret,
                           QuicLevelKeys& out_keys) noexcept;

/// Hysteria2 Salamander UDP obfuscation: `[salt(8)] [payload ^ BLAKE2b_256(password || salt)]`.
std::vector<uint8_t> Hysteria2SalamanderWrap(std::string_view password,
                                             const uint8_t salt8[8],
                                             const uint8_t* payload,
                                             size_t len);

bool Hysteria2SalamanderUnwrap(std::string_view password,
                               const uint8_t* datagram,
                               size_t len,
                               std::vector<uint8_t>& out_payload);

/// Encodes Hysteria2 TCP stream request: `varint(0x401) + varint(addr_len) + addr + varint(pad_len) + pad`.
std::vector<uint8_t> Hysteria2EncodeTcpRequest(std::string_view host_port, size_t pad_len = 16);

class Hysteria2Stream final : public IOutboundStream {
public:
    explicit Hysteria2Stream(ProxyNode node, AppSettings settings = {}) noexcept
        : node_(std::move(node)), settings_(std::move(settings)) {}
    ~Hysteria2Stream() override { Close(); }

    Protocol Kind() const noexcept override { return Protocol::Hysteria2; }
    bool Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms = 6000) noexcept override;
    IoResult WriteNonBlocking(const uint8_t* data, size_t len) noexcept override;
    IoResult ReadNonBlocking(uint8_t* out, size_t cap) noexcept override;
    bool FlushPending() noexcept override;
    bool HasPendingWrite() const noexcept override { return !tx_queue_.empty(); }
    SocketFd NativeFd() const noexcept override { return sock_.Fd(); }
    void Close() noexcept override;

private:
    bool SendDatagram(const uint8_t* pkt, size_t len) noexcept;
    bool RecvDatagram(std::vector<uint8_t>& out_pkt, int timeout_ms, bool non_blocking) noexcept;

    std::vector<uint8_t> ProtectPacket(uint8_t header_byte,
                                       bool is_long,
                                       uint8_t packet_type_bits,
                                       QuicLevelKeys& keys,
                                       const std::vector<uint8_t>& payload,
                                       size_t min_total_len = 0) noexcept;
    bool UnprotectAndProcessPacket(const uint8_t* pkt, size_t len, bool& out_close) noexcept;
    bool ParseFrames(int level_idx, const uint8_t* pl, size_t len) noexcept;

    bool SendStreamBytes(uint64_t stream_id, const uint8_t* data, size_t len, bool fin) noexcept;
    void SendAckFrame(int level_idx, uint64_t largest_pn) noexcept;

    ProxyNode node_;
    AppSettings settings_;
    NetSocket sock_{};
    uint32_t peer_ip_host_ = 0;
    bool use_salamander_ = false;

    std::vector<uint8_t> dcid_{};
    std::vector<uint8_t> scid_{};
    std::vector<uint8_t> retry_token_{};

    QuicLevelKeys init_tx_{}, init_rx_{};
    QuicLevelKeys hs_tx_{}, hs_rx_{};
    QuicLevelKeys app_tx_{}, app_rx_{};
    Tls13QuicDriver tls_driver_{};

    uint64_t crypto_tx_off_[2]{};
    uint64_t auth_stream_off_ = 0;
    uint64_t tcp_tx_off_ = 0;
    uint64_t tcp_rx_next_off_ = 0;

    std::vector<uint8_t> auth_rx_buf_;
    std::vector<uint8_t> tcp_hdr_buf_;
    bool auth_ok_ = false;
    bool tcp_resp_ok_ = false;
    bool remote_eof_ = false;

    std::vector<std::vector<uint8_t>> tx_queue_;
    std::vector<uint8_t> pt_rx_;
    size_t pt_off_ = 0;
};

}  // namespace yumi_nx::net
