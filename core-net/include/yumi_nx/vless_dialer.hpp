#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "yumi_nx/net_interfaces.hpp"
#include "yumi_nx/transports.hpp"

namespace yumi_nx::net {

enum class VlessCmd : uint8_t {
    Tcp = 1,
    Udp = 2,
    Mux = 3,
};

enum class VisionCmd : uint8_t {
    Continue = 0,
    End = 1,
    Direct = 2,
};

/// Encodes VLESS v0 request header (`version(0) + uuid(16) + addons + cmd + port(BE) + addr`).
std::vector<uint8_t> EncodeVlessRequestHeader(const uint8_t uuid[16],
                                              std::string_view flow,
                                              VlessCmd cmd,
                                              std::string_view host,
                                              uint16_t port) noexcept;

/// Decodes VLESS v0 response header (`version(0) + addons_len + addons`). Returns total header bytes consumed, or 0 if incomplete.
size_t DecodeVlessResponseHeader(const uint8_t* data, size_t len, bool& out_valid) noexcept;

/// Encodes one XTLS-Vision frame `[optional uuid16] | cmd(1) | content_len(2 BE) | pad_len(2 BE) | content | zeros`.
std::vector<uint8_t> EncodeVisionPacket(const uint8_t* optional_uuid16,
                                        VisionCmd cmd,
                                        const uint8_t* content,
                                        size_t content_len,
                                        uint16_t pad_len = 0) noexcept;

/// Decodes one XTLS-Vision frame. Returns bytes consumed from input, or 0 if incomplete.
size_t DecodeVisionPacket(const uint8_t* data,
                          size_t len,
                          bool expect_uuid,
                          VisionCmd& out_cmd,
                          std::vector<uint8_t>& out_content) noexcept;

/// Encodes one XUDP frame (New/Keep UDP sub-frame with Target Address + payload).
std::vector<uint8_t> EncodeXudpFrame(uint16_t frame_id,
                                     uint8_t status,  // 1=New, 2=Keep
                                     std::string_view host,
                                     uint16_t port,
                                     const uint8_t* payload,
                                     size_t payload_len) noexcept;

bool DecodeXudpFrame(const uint8_t* data,
                     size_t len,
                     size_t& out_consumed,
                     uint16_t& out_frame_id,
                     uint8_t& out_status,
                     std::vector<uint8_t>& out_payload) noexcept;

class VlessStream final : public IOutboundStream {
public:
    explicit VlessStream(ProxyNode node, AppSettings settings = {}) noexcept
        : node_(std::move(node)), settings_(std::move(settings)) {}
    ~VlessStream() override { Close(); }

    Protocol Kind() const noexcept override { return Protocol::Vless; }
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
    bool use_vision_ = false;
    bool vless_resp_parsed_ = false;
    bool vision_tx_direct_ = false;
    bool vision_rx_direct_ = false;
    bool vision_tx_uuid_sent_ = false;
    bool vision_rx_uuid_seen_ = false;
    uint8_t uuid_[16]{};

    std::vector<uint8_t> vless_rx_hdr_buf_;
    std::vector<uint8_t> vision_rx_buf_;
    std::vector<uint8_t> pt_rx_buf_;
    size_t pt_rx_off_ = 0;
};

}  // namespace yumi_nx::net
