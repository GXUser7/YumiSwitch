#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "yumi_nx/models.hpp"
#include "yumi_nx/net_interfaces.hpp"

namespace yumi_nx::net {

enum class SsCipher : uint8_t {
    Aes128Gcm = 0,
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
    Ss2022Aes128Gcm = 3,
    Ss2022Aes256Gcm = 4,
    Ss2022ChaCha20Poly1305 = 5,
};

bool ParseSsCipher(std::string_view method, SsCipher& out_cipher, size_t& out_key_len, bool& out_is_2022) noexcept;
bool DeriveSsSubkey(SsCipher cipher, std::string_view password, const uint8_t* salt, size_t salt_len, uint8_t out_subkey[32]) noexcept;
std::vector<uint8_t> EncodeSocksTargetAddress(std::string_view host, uint16_t port);

class ShadowsocksStream final : public IOutboundStream {
public:
    explicit ShadowsocksStream(ProxyNode node) noexcept : node_(std::move(node)) {}
    ~ShadowsocksStream() override { Close(); }

    Protocol Kind() const noexcept override { return Protocol::Shadowsocks; }
    bool Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms = 6000) noexcept override;
    IoResult WriteNonBlocking(const uint8_t* data, size_t len) noexcept override;
    IoResult ReadNonBlocking(uint8_t* out, size_t cap) noexcept override;
    bool FlushPending() noexcept override;
    bool HasPendingWrite() const noexcept override { return tx_off_ < tx_buf_.size(); }
    SocketFd NativeFd() const noexcept override { return sock_.Fd(); }
    void Close() noexcept override;

private:
    bool AeadSeal(const uint8_t key[32], uint64_t ctr, const uint8_t* pt, size_t pt_len, std::vector<uint8_t>& out_ct_tag) noexcept;
    bool AeadOpen(const uint8_t key[32], uint64_t ctr, const uint8_t* ct, size_t ct_len, const uint8_t tag[16], uint8_t* out_pt) noexcept;
    bool AppendEncryptedChunk(const uint8_t* pt, size_t pt_len) noexcept;
    bool ProcessIncoming() noexcept;

    ProxyNode node_;
    Endpoint target_{};
    NetSocket sock_{};

    SsCipher cipher_ = SsCipher::Aes128Gcm;
    size_t key_len_ = 16;
    bool is_2022_ = false;
    bool header_sent_ = false;
    bool rx_salt_seen_ = false;
    bool rx_2022_hdr_seen_ = false;
    bool rx_len_parsed_ = false;
    uint16_t pending_chunk_len_ = 0;
    bool remote_eof_ = false;

    uint8_t tx_salt_[32]{};
    uint8_t tx_subkey_[32]{};
    uint64_t tx_nonce_ctr_ = 0;

    uint8_t rx_subkey_[32]{};
    uint64_t rx_nonce_ctr_ = 0;

    std::vector<uint8_t> tx_buf_;
    size_t tx_off_ = 0;
    std::vector<uint8_t> rx_raw_;
    std::vector<uint8_t> pt_rx_;
    size_t pt_off_ = 0;
};

}  // namespace yumi_nx::net
