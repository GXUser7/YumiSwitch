#include "yumi_nx/vless_dialer.hpp"

#include <algorithm>
#include <cstring>

#include "yumi_nx/crypto.hpp"
#include "yumi_nx/net_interfaces.hpp"

namespace yumi_nx::net {

namespace {

inline uint16_t ReadBe16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>((uint16_t(p[0]) << 8) | p[1]);
}
inline void AppendBe16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
}

void AppendVlessAddress(std::vector<uint8_t>& out, std::string_view host, uint16_t port) {
    AppendBe16(out, port);
    uint32_t ip_host = 0;
    if (ParseIPv4Be(host, ip_host)) {
        out.push_back(1);  // IPv4
        out.push_back(static_cast<uint8_t>((ip_host >> 24) & 0xFFu));
        out.push_back(static_cast<uint8_t>((ip_host >> 16) & 0xFFu));
        out.push_back(static_cast<uint8_t>((ip_host >> 8) & 0xFFu));
        out.push_back(static_cast<uint8_t>(ip_host & 0xFFu));
    } else {
        out.push_back(2);  // Domain
        const size_t dlen = std::min<size_t>(host.size(), 255);
        out.push_back(static_cast<uint8_t>(dlen));
        out.insert(out.end(), host.begin(), host.begin() + static_cast<ptrdiff_t>(dlen));
    }
}

bool ContainsAscii(std::string_view haystack, std::string_view needle) noexcept {
    return haystack.find(needle) != std::string_view::npos;
}

}  // namespace

std::vector<uint8_t> EncodeVlessRequestHeader(const uint8_t uuid[16],
                                              std::string_view flow,
                                              VlessCmd cmd,
                                              std::string_view host,
                                              uint16_t port) noexcept {
    std::vector<uint8_t> hdr;
    hdr.reserve(64 + host.size());
    hdr.push_back(0x00);  // VLESS v0
    hdr.insert(hdr.end(), uuid, uuid + 16);

    if (!flow.empty() && flow.size() <= 64) {
        // Protobuf Addons { string Flow = 1; } -> field 1, wire type 2 (tag 0x0A)
        const uint8_t flen = static_cast<uint8_t>(flow.size());
        hdr.push_back(static_cast<uint8_t>(2u + flen));  // addons len
        hdr.push_back(0x0A);
        hdr.push_back(flen);
        hdr.insert(hdr.end(), flow.begin(), flow.end());
    } else {
        hdr.push_back(0x00);  // addons len = 0
    }

    hdr.push_back(static_cast<uint8_t>(cmd));
    if (cmd != VlessCmd::Mux) {
        AppendVlessAddress(hdr, host, port);
    }
    return hdr;
}

size_t DecodeVlessResponseHeader(const uint8_t* data, size_t len, bool& out_valid) noexcept {
    out_valid = false;
    if (!data || len < 2) return 0;
    if (data[0] != 0x00) return 0;
    const size_t addons_len = data[1];
    if (len < 2u + addons_len) return 0;
    out_valid = true;
    return 2u + addons_len;
}

std::vector<uint8_t> EncodeVisionPacket(const uint8_t* optional_uuid16,
                                        VisionCmd cmd,
                                        const uint8_t* content,
                                        size_t content_len,
                                        uint16_t pad_len) noexcept {
    std::vector<uint8_t> pkt;
    pkt.reserve((optional_uuid16 ? 16 : 0) + 5 + content_len + pad_len);
    if (optional_uuid16) {
        pkt.insert(pkt.end(), optional_uuid16, optional_uuid16 + 16);
    }
    pkt.push_back(static_cast<uint8_t>(cmd));
    AppendBe16(pkt, static_cast<uint16_t>(content_len));
    AppendBe16(pkt, pad_len);
    if (content && content_len > 0) {
        pkt.insert(pkt.end(), content, content + content_len);
    }
    if (pad_len > 0) {
        pkt.resize(pkt.size() + pad_len, 0);
    }
    return pkt;
}

size_t DecodeVisionPacket(const uint8_t* data,
                          size_t len,
                          bool expect_uuid,
                          VisionCmd& out_cmd,
                          std::vector<uint8_t>& out_content) noexcept {
    const size_t uuid_off = expect_uuid ? 16u : 0u;
    if (!data || len < uuid_off + 5u) return 0;
    const uint8_t* p = data + uuid_off;
    out_cmd = static_cast<VisionCmd>(p[0]);
    const uint16_t clen = ReadBe16(p + 1);
    const uint16_t plen = ReadBe16(p + 3);
    const size_t total = uuid_off + 5u + clen + plen;
    if (len < total) return 0;
    out_content.assign(p + 5u, p + 5u + clen);
    return total;
}

std::vector<uint8_t> EncodeXudpFrame(uint16_t frame_id,
                                     uint8_t status,
                                     std::string_view host,
                                     uint16_t port,
                                     const uint8_t* payload,
                                     size_t payload_len) noexcept {
    std::vector<uint8_t> meta;
    AppendBe16(meta, frame_id);
    meta.push_back(status);
    meta.push_back(0x00);  // Option: none unless Target included below
    if (status == 1 && !host.empty()) {
        meta.back() = 0x01;  // OptionData
        meta.push_back(0x02);  // UDP target
        AppendVlessAddress(meta, host, port);
    }

    std::vector<uint8_t> out;
    out.reserve(2 + meta.size() + 2 + payload_len);
    AppendBe16(out, static_cast<uint16_t>(meta.size()));
    out.insert(out.end(), meta.begin(), meta.end());
    AppendBe16(out, static_cast<uint16_t>(payload_len));
    if (payload && payload_len > 0) {
        out.insert(out.end(), payload, payload + payload_len);
    }
    return out;
}

bool DecodeXudpFrame(const uint8_t* data,
                     size_t len,
                     size_t& out_consumed,
                     uint16_t& out_frame_id,
                     uint8_t& out_status,
                     std::vector<uint8_t>& out_payload) noexcept {
    out_consumed = 0;
    if (!data || len < 4u) return false;
    const uint16_t meta_len = ReadBe16(data);
    if (meta_len < 4u || 2u + meta_len + 2u > len) return false;
    out_frame_id = ReadBe16(data + 2);
    out_status = data[4];
    const uint16_t plen = ReadBe16(data + 2u + meta_len);
    const size_t total = 2u + meta_len + 2u + plen;
    if (total > len) return false;
    out_payload.assign(data + 2u + meta_len + 2u, data + total);
    out_consumed = total;
    return true;
}

bool VlessStream::Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms) noexcept {
    Close();
    if (!crypto::ParseUuidBytes(node_.uuid_or_user, uuid_)) return false;
    if (!transport_.Connect(node_, settings_, resolver, timeout_ms, false)) return false;

    use_vision_ = (node_.transport.kind == TransportKind::Raw) && ContainsAscii(node_.flow, "vision");

    const auto vless_hdr = EncodeVlessRequestHeader(
        uuid_,
        use_vision_ ? "xtls-rprx-vision" : "",
        VlessCmd::Tcp,
        target.host,
        target.port);
    if (!transport_.WriteBlocking(vless_hdr.data(), vless_hdr.size(), timeout_ms)) {
        Close();
        return false;
    }

    return true;
}

IoResult VlessStream::WriteNonBlocking(const uint8_t* data, size_t len) noexcept {
    if (transport_.NativeFd() == kInvalidSocket) return {IoStatus::Error, 0};
    if (!use_vision_ || vision_tx_direct_) {
        return transport_.WriteNonBlocking(data, len);
    }
    if (len == 0) return {IoStatus::Ok, 0};

    // Vision framing: TLS handshake records stay in Vision frames until TLS ApplicationData (0x17 0x03 0x03).
    const bool is_tls_app = (len >= 3 && data[0] == 0x17 && data[1] == 0x03);
    const bool is_tls_hs = (len >= 3 && data[0] == 0x16 && data[1] == 0x03);
    const VisionCmd cmd = (is_tls_app || !is_tls_hs) ? VisionCmd::Direct : VisionCmd::Continue;
    const size_t chunk = std::min<size_t>(len, 16000u);
    const uint8_t* opt_uid = vision_tx_uuid_sent_ ? nullptr : uuid_;
    const auto pkt = EncodeVisionPacket(opt_uid, cmd, data, chunk, 0);
    const auto io = transport_.WriteNonBlocking(pkt.data(), pkt.size());
    if (io.status == IoStatus::Ok && io.bytes == pkt.size()) {
        vision_tx_uuid_sent_ = true;
        if (cmd == VisionCmd::Direct) {
            vision_tx_direct_ = true;
            transport_.SetTlsDirectCopy(true);
        }
        return {IoStatus::Ok, chunk};
    }
    if (io.status == IoStatus::WouldBlock) return {IoStatus::WouldBlock, 0};
    if (io.status == IoStatus::Ok) {
        vision_tx_uuid_sent_ = true;
        return {IoStatus::Ok, chunk};
    }
    return {IoStatus::Error, 0};
}

IoResult VlessStream::ReadNonBlocking(uint8_t* out, size_t cap) noexcept {
    if (transport_.NativeFd() == kInvalidSocket) return {IoStatus::Error, 0};
    if (pt_rx_off_ < pt_rx_buf_.size()) {
        const size_t n = std::min(cap, pt_rx_buf_.size() - pt_rx_off_);
        std::memcpy(out, pt_rx_buf_.data() + pt_rx_off_, n);
        pt_rx_off_ += n;
        if (pt_rx_off_ >= pt_rx_buf_.size()) {
            pt_rx_buf_.clear();
            pt_rx_off_ = 0;
        }
        return {IoStatus::Ok, n};
    }

    if (!vless_resp_parsed_ || (use_vision_ && !vision_rx_direct_)) {
        uint8_t tmp[8192];
        const auto io = transport_.ReadNonBlocking(tmp, sizeof(tmp));
        if (io.status == IoStatus::Ok && io.bytes > 0) {
            vless_rx_hdr_buf_.insert(vless_rx_hdr_buf_.end(), tmp, tmp + io.bytes);
        } else if (io.status != IoStatus::Ok) {
            return io;
        }

        if (!vless_resp_parsed_) {
            bool valid = false;
            const size_t hdr_len = DecodeVlessResponseHeader(vless_rx_hdr_buf_.data(), vless_rx_hdr_buf_.size(), valid);
            if (hdr_len == 0) {
                if (vless_rx_hdr_buf_.size() >= 2 && !valid) return {IoStatus::Error, 0};
                return {IoStatus::WouldBlock, 0};
            }
            vless_resp_parsed_ = true;
            vless_rx_hdr_buf_.erase(vless_rx_hdr_buf_.begin(), vless_rx_hdr_buf_.begin() + static_cast<ptrdiff_t>(hdr_len));
        }

        if (use_vision_ && !vision_rx_direct_) {
            vision_rx_buf_.insert(vision_rx_buf_.end(), vless_rx_hdr_buf_.begin(), vless_rx_hdr_buf_.end());
            vless_rx_hdr_buf_.clear();
            while (!vision_rx_buf_.empty() && !vision_rx_direct_) {
                VisionCmd cmd = VisionCmd::Continue;
                std::vector<uint8_t> content;
                const size_t used = DecodeVisionPacket(
                    vision_rx_buf_.data(), vision_rx_buf_.size(), !vision_rx_uuid_seen_, cmd, content);
                if (used == 0) break;
                vision_rx_uuid_seen_ = true;
                pt_rx_buf_.insert(pt_rx_buf_.end(), content.begin(), content.end());
                vision_rx_buf_.erase(vision_rx_buf_.begin(), vision_rx_buf_.begin() + static_cast<ptrdiff_t>(used));
                if (cmd == VisionCmd::Direct || cmd == VisionCmd::End) {
                    vision_rx_direct_ = true;
                    if (!vision_rx_buf_.empty()) {
                        pt_rx_buf_.insert(pt_rx_buf_.end(), vision_rx_buf_.begin(), vision_rx_buf_.end());
                        vision_rx_buf_.clear();
                    }
                    transport_.SetTlsDirectCopy(true);
                    break;
                }
            }
        } else {
            pt_rx_buf_.insert(pt_rx_buf_.end(), vless_rx_hdr_buf_.begin(), vless_rx_hdr_buf_.end());
            vless_rx_hdr_buf_.clear();
        }

        if (pt_rx_off_ < pt_rx_buf_.size()) {
            const size_t n = std::min(cap, pt_rx_buf_.size() - pt_rx_off_);
            std::memcpy(out, pt_rx_buf_.data() + pt_rx_off_, n);
            pt_rx_off_ += n;
            if (pt_rx_off_ >= pt_rx_buf_.size()) {
                pt_rx_buf_.clear();
                pt_rx_off_ = 0;
            }
            return {IoStatus::Ok, n};
        }
        return {IoStatus::WouldBlock, 0};
    }

    return transport_.ReadNonBlocking(out, cap);
}

bool VlessStream::FlushPending() noexcept {
    return transport_.FlushPending();
}

bool VlessStream::HasPendingWrite() const noexcept {
    return transport_.HasPendingWrite();
}

void VlessStream::Close() noexcept {
    transport_.Close();
    vless_resp_parsed_ = false;
    vision_tx_direct_ = false;
    vision_rx_direct_ = false;
    vision_tx_uuid_sent_ = false;
    vision_rx_uuid_seen_ = false;
    vless_rx_hdr_buf_.clear();
    vision_rx_buf_.clear();
    pt_rx_buf_.clear();
    pt_rx_off_ = 0;
}

}  // namespace yumi_nx::net
