#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "yumi_nx/models.hpp"
#include "yumi_nx/socket_io.hpp"

namespace yumi_nx::net {

struct FragmentConfig {
    FragmentMode mode = FragmentMode::Off;
    FragmentScope scope = FragmentScope::TlsAndReality;
    uint16_t min_len = 20;
    uint16_t max_len = 50;
    uint16_t min_interval_ms = 2;
    uint16_t max_interval_ms = 5;
    uint16_t max_chunks = 0;  // 0 = unlimited
};

[[nodiscard]] bool ParseRangeMinMax(std::string_view range_str,
                                    uint16_t def_min,
                                    uint16_t def_max,
                                    uint16_t& out_min,
                                    uint16_t& out_max) noexcept;

[[nodiscard]] FragmentConfig MakeFragmentConfig(const AppSettings& settings) noexcept;

[[nodiscard]] TlsFingerprint ResolveEffectiveFingerprint(TlsFingerprint global_override,
                                                         std::string_view node_fp) noexcept;

/// Sends TCP bytes fragmented into `cfg.min_len..cfg.max_len` chunks with `cfg.min_interval_ms..cfg.max_interval_ms` pauses.
bool SendFragmentedBlocking(NetSocket& sock,
                            const uint8_t* data,
                            size_t len,
                            const FragmentConfig& cfg,
                            int timeout_ms) noexcept;

/// Derives XTLS-REALITY authentication key and encrypts the 16-byte client session ID token.
bool BuildRealitySessionId(const uint8_t eph_priv[32],
                           const uint8_t server_pub[32],
                           const uint8_t client_random[32],
                           const uint8_t short_id[8],
                           uint32_t timestamp_sec,
                           const uint8_t* raw_client_hello_zero_sid,
                           size_t raw_ch_len,
                           uint8_t out_session_id[32],
                           uint8_t out_auth_key[32]) noexcept;

/// Decodes `short_id` hex string (up to 16 hex chars -> 8 bytes, zero-padded on right).
bool ParseRealityShortId(std::string_view hex, uint8_t out_short_id[8]) noexcept;

/// Builds an RFC 8446 TLS 1.3 ClientHello with uTLS fingerprint mimicry + optional REALITY auth SessionId + optional extra extensions.
std::vector<uint8_t> BuildTls13ClientHello(std::string_view sni,
                                           const std::vector<std::string>& alpn,
                                           const uint8_t eph_priv[32],
                                           const uint8_t client_random[32],
                                           const RealityOptions* reality,
                                           uint32_t now_epoch_sec,
                                           uint8_t* out_auth_key_32 = nullptr,
                                           TlsFingerprint fingerprint = TlsFingerprint::Auto,
                                           const std::vector<uint8_t>* extra_extensions = nullptr) noexcept;

/// Record-free TLS 1.3 handshake state machine shared with QUIC (Hysteria2) CRYPTO frames.
class Tls13QuicDriver {
public:
    struct Secrets {
        uint16_t cipher_suite = 0x1301;
        bool use_sha384 = false;
        size_t hash_len = 32;
        uint8_t client_hs_traffic[48]{};
        uint8_t server_hs_traffic[48]{};
        uint8_t client_ap_traffic[48]{};
        uint8_t server_ap_traffic[48]{};
    };

    bool Start(std::string_view sni,
               const std::vector<std::string>& alpn,
               const std::vector<uint8_t>& quic_transport_params_ext,
               TlsFingerprint fp,
               std::vector<uint8_t>& out_client_hello) noexcept;

    /// Feeds QUIC Initial CRYPTO handshake bytes (ServerHello). Returns true when ServerHello processed.
    bool OnInitialServerBytes(const uint8_t* data, size_t len) noexcept;

    /// Feeds QUIC Handshake CRYPTO bytes (EncryptedExtensions..Finished). Sets `out_complete = true` when app secrets & ClientFinished are ready.
    bool OnHandshakeServerBytes(const uint8_t* data, size_t len,
                                std::vector<uint8_t>& out_client_finished,
                                bool& out_complete) noexcept;

    [[nodiscard]] bool HasHandshakeSecrets() const noexcept { return has_hs_; }
    [[nodiscard]] bool IsComplete() const noexcept { return complete_; }
    [[nodiscard]] const Secrets& Derived() const noexcept { return secrets_; }
    [[nodiscard]] const std::vector<uint8_t>& PeerTransportParams() const noexcept { return peer_tp_; }

private:
    uint8_t eph_priv_[32]{};
    uint8_t client_random_[32]{};
    std::vector<uint8_t> init_buf_;
    std::vector<uint8_t> hs_buf_;
    std::vector<uint8_t> transcript_;
    std::vector<uint8_t> peer_tp_;
    uint8_t hs_secret_[48]{};
    uint8_t empty_hash_[48]{};
    Secrets secrets_{};
    bool has_hs_ = false;
    bool complete_ = false;
};

/// Self-contained RFC 8446 TLS 1.3 Client (AES-128-GCM-SHA256, AES-256-GCM-SHA384, ChaCha20-Poly1305-SHA256)
/// with X25519 key exchange, XTLS-REALITY verification, global uTLS, fragmentation, and XTLS-Vision direct-copy support.
class Tls13Client {
public:
    Tls13Client() noexcept = default;
    ~Tls13Client() = default;

    Tls13Client(const Tls13Client&) = delete;
    Tls13Client& operator=(const Tls13Client&) = delete;

    /// Performs full blocking TLS 1.3 (or XTLS-REALITY) handshake over `sock`.
    bool Handshake(NetSocket& sock,
                   std::string_view sni,
                   const std::vector<std::string>& alpn,
                   const RealityOptions* reality,
                   uint32_t now_epoch_sec,
                   int timeout_ms = 8000,
                   TlsFingerprint fingerprint = TlsFingerprint::Auto,
                   const FragmentConfig* fragment = nullptr) noexcept;

    [[nodiscard]] bool IsEstablished() const noexcept { return established_; }
    [[nodiscard]] bool IsDirectCopy() const noexcept { return direct_copy_; }
    void SetDirectCopy(bool enabled) noexcept { direct_copy_ = enabled; }

    /// Sends plaintext application data (or raw bytes when `direct_copy_` is true).
    bool WriteBlocking(NetSocket& sock, const uint8_t* data, size_t len, int timeout_ms = 5000) noexcept;

    /// Non-blocking / single-step helpers for TunnelEngine poll loop.
    IoResult WriteNonBlocking(NetSocket& sock, const uint8_t* data, size_t len) noexcept;
    IoResult ReadNonBlocking(NetSocket& sock, uint8_t* out, size_t cap) noexcept;

    /// Blocking read helper for unary HTTP/DoH exchanges.
    IoResult ReadBlocking(NetSocket& sock, uint8_t* out, size_t cap, int timeout_ms = 5000) noexcept;

    [[nodiscard]] bool HasPendingPlaintext() const noexcept { return pt_off_ < pt_buf_.size(); }
    [[nodiscard]] bool HasPendingCipherWrite() const noexcept { return ct_write_off_ < ct_write_buf_.size(); }
    bool FlushPendingWrite(NetSocket& sock) noexcept;

    /// Sends TLS CloseNotify alert cleanly if connected and not in direct-copy mode.
    void SendCloseNotify(NetSocket& sock) noexcept;

private:
    struct KeySchedule {
        uint16_t cipher_suite = 0x1301;  // 0x1301=AES128-GCM-SHA256, 0x1302=AES256-GCM-SHA384, 0x1303=CHACHA20-SHA256
        bool use_sha384 = false;
        size_t hash_len = 32;
        size_t key_len = 16;

        uint8_t client_key[32]{};
        uint8_t client_iv[12]{};
        uint64_t client_seq = 0;

        uint8_t server_key[32]{};
        uint8_t server_iv[12]{};
        uint64_t server_seq = 0;
    };

    static void DeriveTrafficKeys(bool use_sha384, size_t key_len, const uint8_t* secret, uint8_t key[32], uint8_t iv[12]) noexcept;
    bool EncryptRecord(uint8_t content_type, const uint8_t* payload, size_t len, std::vector<uint8_t>& out_record) noexcept;
    bool DecryptRecord(const uint8_t* rec, size_t rec_len, uint8_t& out_content_type, std::vector<uint8_t>& out_pt) noexcept;
    bool ReadRawRecordBlocking(NetSocket& sock, uint8_t& out_type, std::vector<uint8_t>& out_body, int timeout_ms) noexcept;
    bool PullAndDecryptNonBlocking(NetSocket& sock, bool& out_eof, bool& out_would_block) noexcept;

    bool established_ = false;
    bool direct_copy_ = false;
    bool peer_closed_ = false;
    KeySchedule ks_{};

    std::vector<uint8_t> ct_read_buf_;
    std::vector<uint8_t> pt_buf_;
    size_t pt_off_ = 0;

    std::vector<uint8_t> ct_write_buf_;
    size_t ct_write_off_ = 0;
};

}  // namespace yumi_nx::net
