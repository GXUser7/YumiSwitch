#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "yumi_nx/crypto.hpp"
#include "yumi_nx/models.hpp"
#include "yumi_nx/net_interfaces.hpp"
#include "yumi_nx/transports.hpp"

namespace yumi_nx::net {

/// Derives VMess CmdKey = MD5(uuid16 || "c48619fe-8f02-49e0-b9e9-edf763e17e21").
void DeriveVmessCmdKey(const uint8_t uuid[16], uint8_t out_cmd_key[16]) noexcept;

/// VMess nested HMAC-SHA256 KDF ("VMess AEAD KDF" root salt).
void VmessAeadKdf(const uint8_t* key,
                  size_t key_len,
                  const uint8_t* const* path,
                  const size_t* path_lens,
                  size_t depth,
                  uint8_t out[32]) noexcept;

/// Builds a full VMess AEAD encrypted request header (`AuthID(16) + EncLen(18) + Nonce(8) + EncHeader(N+16)`).
std::vector<uint8_t> EncodeVmessAeadRequestHeader(const uint8_t cmd_key[16],
                                                  uint64_t timestamp_sec,
                                                  const uint8_t nonce8[8],
                                                  const uint8_t req_iv[16],
                                                  const uint8_t req_key[16],
                                                  uint8_t resp_auth_v,
                                                  uint8_t sec_type,
                                                  std::string_view host,
                                                  uint16_t port) noexcept;

class VmessStream final : public IOutboundStream {
public:
    explicit VmessStream(ProxyNode node, AppSettings settings = {}) noexcept
        : node_(std::move(node)), settings_(std::move(settings)) {}
    ~VmessStream() override { Close(); }

    Protocol Kind() const noexcept override { return Protocol::Vmess; }
    bool Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms = 6000) noexcept override;
    IoResult WriteNonBlocking(const uint8_t* data, size_t len) noexcept override;
    IoResult ReadNonBlocking(uint8_t* out, size_t cap) noexcept override;
    bool FlushPending() noexcept override;
    bool HasPendingWrite() const noexcept override;
    SocketFd NativeFd() const noexcept override { return transport_.NativeFd(); }
    void Close() noexcept override;

private:
    bool ProcessIncoming() noexcept;

    ProxyNode node_;
    AppSettings settings_;
    TransportPipeline transport_{};

    uint8_t cmd_key_[16]{};
    uint8_t req_key_[16]{};
    uint8_t req_iv_[16]{};
    uint8_t resp_key_[16]{};
    uint8_t resp_iv_[16]{};
    uint8_t resp_v_ = 0;
    uint8_t sec_type_ = 3;  // 3=AES-128-GCM, 4=ChaCha20-Poly1305, 5=None

    crypto::Shake128 tx_mask_{};
    crypto::Shake128 rx_mask_{};
    uint16_t tx_chunk_ctr_ = 0;
    uint16_t rx_chunk_ctr_ = 0;

    bool resp_len_parsed_ = false;
    bool resp_hdr_parsed_ = false;
    uint16_t resp_hdr_len_ = 0;
    bool chunk_len_parsed_ = false;
    uint16_t pending_chunk_len_ = 0;
    bool remote_eof_ = false;

    std::vector<uint8_t> raw_rx_;
    std::vector<uint8_t> pt_rx_;
    size_t pt_off_ = 0;
    std::vector<uint8_t> tx_buf_;
    size_t tx_off_ = 0;
};

}  // namespace yumi_nx::net
