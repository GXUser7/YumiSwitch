#include "yumi_nx/transports.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#include "yumi_nx/crypto.hpp"

namespace yumi_nx::net {

namespace {

inline uint32_t Swap32(uint32_t v) noexcept {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

inline uint16_t ReadBe16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>((uint16_t(p[0]) << 8) | p[1]);
}

inline uint32_t ReadBe24(const uint8_t* p) noexcept {
    return (uint32_t(p[0]) << 16) | (uint32_t(p[1]) << 8) | p[2];
}

inline uint32_t ReadBe32(const uint8_t* p) noexcept {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
}

inline void AppendBe16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
}

inline void AppendBe24(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
}

inline void AppendBe32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(v & 0xFFu));
}

void AppendVarintPb(std::vector<uint8_t>& out, size_t v) {
    while (v >= 0x80u) {
        out.push_back(static_cast<uint8_t>((v & 0x7Fu) | 0x80u));
        v >>= 7;
    }
    out.push_back(static_cast<uint8_t>(v & 0x7Fu));
}

void AppendHpackLiteral(std::vector<uint8_t>& out, std::string_view name, std::string_view value) {
    out.push_back(0x00);  // literal without indexing, new name
    AppendVarintPb(out, name.size());
    out.insert(out.end(), name.begin(), name.end());
    AppendVarintPb(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

void AppendHpackIndexedName(std::vector<uint8_t>& out, uint8_t static_idx, std::string_view value) {
    out.push_back(static_idx & 0x0Fu);  // literal without indexing, 4-bit static table name index
    AppendVarintPb(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

void AppendH2Frame(std::vector<uint8_t>& out, uint8_t type, uint8_t flags, uint32_t stream_id,
                   const uint8_t* payload, size_t len) {
    AppendBe24(out, static_cast<uint32_t>(len));
    out.push_back(type);
    out.push_back(flags);
    AppendBe32(out, stream_id & 0x7FFFFFFFu);
    if (payload && len > 0) out.insert(out.end(), payload, payload + len);
}

void AppendWsMaskedFrame(std::vector<uint8_t>& out, uint8_t opcode, const uint8_t* payload, size_t len) {
    uint8_t mask[4]{0x37, 0xFA, 0x21, 0x3D};
    crypto::RandomBytes(mask, 4);

    out.push_back(static_cast<uint8_t>(0x80u | (opcode & 0x0Fu)));
    if (len < 126u) {
        out.push_back(static_cast<uint8_t>(0x80u | len));
    } else if (len <= 65535u) {
        out.push_back(0x80u | 126u);
        AppendBe16(out, static_cast<uint16_t>(len));
    } else {
        out.push_back(0x80u | 127u);
        AppendBe32(out, 0);
        AppendBe32(out, static_cast<uint32_t>(len));
    }
    out.insert(out.end(), mask, mask + 4);
    const size_t base = out.size();
    out.resize(base + len);
    for (size_t i = 0; i < len; ++i) {
        out[base + i] = payload[i] ^ mask[i & 3u];
    }
}

bool ContainsAsciiLower(std::string_view hay, std::string_view needle) {
    if (hay.size() < needle.size()) return false;
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        bool ok = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (std::tolower(static_cast<unsigned char>(hay[i + j])) !=
                std::tolower(static_cast<unsigned char>(needle[j]))) {
                ok = false;
                break;
            }
        }
        if (ok) return true;
    }
    return false;
}

std::string NormalizePath(std::string_view p) {
    if (p.empty()) return "/";
    if (p.front() == '/') return std::string(p);
    return "/" + std::string(p);
}

std::string EffectiveHostHeader(const ProxyNode& node) {
    if (!node.transport.host.empty()) return node.transport.host;
    if (!node.tls.server_name.empty()) return node.tls.server_name;
    return node.server;
}

}  // namespace

bool TransportPipeline::Connect(const ProxyNode& node,
                                const AppSettings& settings,
                                IDnsResolver& resolver,
                                int timeout_ms,
                                bool force_tls_on) noexcept {
    Close();
    kind_ = node.transport.kind;

    uint32_t srv_be = 0;
    if (!resolver.ResolveIPv4(node.server, srv_be)) return false;
    if (!sock_.ConnectExactBlocking(Swap32(srv_be), node.port, timeout_ms)) return false;

    const FragmentConfig frag = MakeFragmentConfig(settings);
    use_tls_ = force_tls_on || node.tls.enabled || node.tls.reality.enabled;
    if (use_tls_) {
        std::string sni = !node.tls.server_name.empty() ? node.tls.server_name : node.server;
        std::vector<std::string> alpn = node.tls.alpn;
        if (kind_ == TransportKind::Grpc && alpn.empty()) alpn = {"h2"};
        else if ((kind_ == TransportKind::WebSocket || kind_ == TransportKind::HttpUpgrade ||
                  kind_ == TransportKind::Xhttp) && alpn.empty()) {
            alpn = {"http/1.1"};
        }
        const RealityOptions* r_opt = node.tls.reality.enabled ? &node.tls.reality : nullptr;
        const TlsFingerprint fp = ResolveEffectiveFingerprint(settings.tls_fingerprint, node.tls.fingerprint);
        const FragmentConfig* frag_ptr = (frag.mode != FragmentMode::Off) ? &frag : nullptr;
        if (!tls_.Handshake(sock_, sni, alpn, r_opt, static_cast<uint32_t>(MonotonicMs() / 1000ULL),
                            timeout_ms, fp, frag_ptr)) {
            Close();
            return false;
        }
    }

    bool ok = true;
    switch (kind_) {
        case TransportKind::Raw:
            ok = true;
            break;
        case TransportKind::WebSocket:
            ok = HandshakeWebSocket(node, timeout_ms);
            break;
        case TransportKind::HttpUpgrade:
            ok = HandshakeHttpUpgrade(node, timeout_ms);
            break;
        case TransportKind::Grpc:
            ok = HandshakeGrpc(node, timeout_ms);
            break;
        case TransportKind::Xhttp:
            ok = HandshakeXhttp(node, timeout_ms);
            break;
    }
    if (!ok) {
        Close();
        return false;
    }
    return true;
}

bool TransportPipeline::RawWriteBlocking(const uint8_t* data, size_t len, int timeout_ms) noexcept {
    if (use_tls_) return tls_.WriteBlocking(sock_, data, len, timeout_ms);
    return sock_.SendAllBlocking(data, len, timeout_ms);
}

IoResult TransportPipeline::RawWriteNonBlocking(const uint8_t* data, size_t len) noexcept {
    if (use_tls_) return tls_.WriteNonBlocking(sock_, data, len);
    return sock_.SendSome(data, len);
}

IoResult TransportPipeline::RawReadNonBlocking(uint8_t* out, size_t cap) noexcept {
    if (use_tls_) return tls_.ReadNonBlocking(sock_, out, cap);
    return sock_.RecvSome(out, cap);
}

IoResult TransportPipeline::RawReadBlocking(uint8_t* out, size_t cap, int timeout_ms) noexcept {
    if (use_tls_) return tls_.ReadBlocking(sock_, out, cap, timeout_ms);
    return sock_.RecvSomeBlocking(out, cap, timeout_ms);
}

bool TransportPipeline::HandshakeWebSocket(const ProxyNode& node, int timeout_ms) noexcept {
    uint8_t nonce16[16]{};
    crypto::RandomBytes(nonce16, 16);
    const std::string key_b64 = crypto::Base64Encode(nonce16, 16);
    const std::string host = EffectiveHostHeader(node);
    const std::string path = NormalizePath(node.transport.path);

    char req[1024];
    const int n = std::snprintf(
        req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n",
        path.c_str(), host.c_str(), key_b64.c_str());
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(req)) return false;
    if (!RawWriteBlocking(reinterpret_cast<const uint8_t*>(req), static_cast<size_t>(n), timeout_ms)) return false;

    std::string hdr;
    uint8_t tmp[1024];
    const uint64_t deadline = MonotonicMs() + static_cast<uint64_t>(timeout_ms);
    while (MonotonicMs() < deadline && hdr.size() < 8192u) {
        const auto io = RawReadBlocking(tmp, sizeof(tmp), static_cast<int>(deadline - MonotonicMs()));
        if (io.status != IoStatus::Ok || io.bytes == 0) return false;
        hdr.append(reinterpret_cast<const char*>(tmp), io.bytes);
        const size_t eoh = hdr.find("\r\n\r\n");
        if (eoh != std::string::npos) {
            if (hdr.find(" 101") == std::string::npos) return false;
            if (eoh + 4 < hdr.size()) {
                raw_rx_buf_.assign(hdr.begin() + static_cast<ptrdiff_t>(eoh + 4), hdr.end());
                ProcessIncomingWs();
            }
            return true;
        }
    }
    return false;
}

bool TransportPipeline::HandshakeHttpUpgrade(const ProxyNode& node, int timeout_ms) noexcept {
    const std::string host = EffectiveHostHeader(node);
    const std::string path = NormalizePath(node.transport.path);

    char req[768];
    const int n = std::snprintf(
        req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: websocket\r\n\r\n",
        path.c_str(), host.c_str());
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(req)) return false;
    if (!RawWriteBlocking(reinterpret_cast<const uint8_t*>(req), static_cast<size_t>(n), timeout_ms)) return false;

    std::string hdr;
    uint8_t tmp[1024];
    const uint64_t deadline = MonotonicMs() + static_cast<uint64_t>(timeout_ms);
    while (MonotonicMs() < deadline && hdr.size() < 8192u) {
        const auto io = RawReadBlocking(tmp, sizeof(tmp), static_cast<int>(deadline - MonotonicMs()));
        if (io.status != IoStatus::Ok || io.bytes == 0) return false;
        hdr.append(reinterpret_cast<const char*>(tmp), io.bytes);
        const size_t eoh = hdr.find("\r\n\r\n");
        if (eoh != std::string::npos) {
            if (hdr.find(" 101") == std::string::npos) return false;
            if (eoh + 4 < hdr.size()) {
                pt_rx_buf_.assign(hdr.begin() + static_cast<ptrdiff_t>(eoh + 4), hdr.end());
            }
            return true;
        }
    }
    return false;
}

bool TransportPipeline::HandshakeGrpc(const ProxyNode& node, int timeout_ms) noexcept {
    static constexpr char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    std::vector<uint8_t> init;
    init.insert(init.end(), kPreface, kPreface + sizeof(kPreface) - 1);

    // Client SETTINGS (ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=4194304)
    uint8_t settings_pl[12]{
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x40, 0x00, 0x00,
    };
    AppendH2Frame(init, 0x04 /*SETTINGS*/, 0x00, 0, settings_pl, sizeof(settings_pl));

    // HEADERS on stream 1
    std::vector<uint8_t> hpack;
    hpack.push_back(0x83);  // :method: POST
    hpack.push_back(use_tls_ ? 0x87 : 0x86);  // :scheme: https / http
    const std::string svc = node.transport.service_name.empty() ? "GunService" : node.transport.service_name;
    const std::string path = "/" + svc + (node.transport.grpc_multi_mode ? "/TunMulti" : "/Tun");
    AppendHpackIndexedName(hpack, 4 /* :path */, path);
    const std::string auth = !node.transport.grpc_authority.empty()
        ? node.transport.grpc_authority : EffectiveHostHeader(node);
    AppendHpackIndexedName(hpack, 1 /* :authority */, auth);
    AppendHpackLiteral(hpack, "content-type", "application/grpc");
    AppendHpackLiteral(hpack, "te", "trailers");
    AppendH2Frame(init, 0x01 /*HEADERS*/, 0x04 /*END_HEADERS*/, 1, hpack.data(), hpack.size());

    if (!RawWriteBlocking(init.data(), init.size(), timeout_ms)) return false;

    // Wait briefly for server SETTINGS / initial frames without stalling if server waits for first DATA
    uint8_t tmp[2048];
    const auto io = RawReadBlocking(tmp, sizeof(tmp), std::min(timeout_ms, 800));
    if (io.status == IoStatus::Ok && io.bytes > 0) {
        raw_rx_buf_.insert(raw_rx_buf_.end(), tmp, tmp + io.bytes);
        ProcessIncomingGrpc();
    } else if (io.status == IoStatus::Eof || io.status == IoStatus::Error) {
        return false;
    }
    return true;
}

bool TransportPipeline::HandshakeXhttp(const ProxyNode& node, int timeout_ms) noexcept {
    const std::string host = EffectiveHostHeader(node);
    const std::string path = NormalizePath(node.transport.path);

    char req[1024];
    const int n = std::snprintf(
        req, sizeof(req),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Cache-Control: no-store\r\n\r\n",
        path.c_str(), host.c_str());
    if (n <= 0 || static_cast<size_t>(n) >= sizeof(req)) return false;
    if (!RawWriteBlocking(reinterpret_cast<const uint8_t*>(req), static_cast<size_t>(n), timeout_ms)) return false;

    // Wait for server response headers (some splithttp servers flush response headers immediately, others lazily)
    uint8_t tmp[2048];
    std::string hdr;
    const auto io = RawReadBlocking(tmp, sizeof(tmp), std::min(timeout_ms, 800));
    if (io.status == IoStatus::Ok && io.bytes > 0) {
        hdr.assign(reinterpret_cast<const char*>(tmp), io.bytes);
        const size_t eoh = hdr.find("\r\n\r\n");
        if (eoh != std::string::npos) {
            const std::string_view hpart(hdr.data(), eoh);
            if (hpart.find(" 200") == std::string_view::npos && hpart.find(" 101") == std::string_view::npos) {
                return false;
            }
            xhttp_chunked_rx_ = ContainsAsciiLower(hpart, "transfer-encoding: chunked");
            if (eoh + 4 < hdr.size()) {
                raw_rx_buf_.assign(hdr.begin() + static_cast<ptrdiff_t>(eoh + 4), hdr.end());
                ProcessIncomingXhttp();
            }
        } else {
            raw_rx_buf_.assign(tmp, tmp + io.bytes);
        }
    } else if (io.status == IoStatus::Eof || io.status == IoStatus::Error) {
        return false;
    }
    return true;
}

void TransportPipeline::ProcessIncomingWs() noexcept {
    while (raw_rx_buf_.size() >= 2u) {
        const uint8_t b0 = raw_rx_buf_[0];
        const uint8_t b1 = raw_rx_buf_[1];
        const uint8_t opcode = b0 & 0x0Fu;
        const bool masked = (b1 & 0x80u) != 0;
        uint64_t plen = b1 & 0x7Fu;
        size_t hdr_len = 2u;
        if (plen == 126u) {
            if (raw_rx_buf_.size() < 4u) break;
            plen = ReadBe16(raw_rx_buf_.data() + 2);
            hdr_len = 4u;
        } else if (plen == 127u) {
            if (raw_rx_buf_.size() < 10u) break;
            plen = ReadBe32(raw_rx_buf_.data() + 6);
            hdr_len = 10u;
        }
        if (masked) hdr_len += 4u;
        if (raw_rx_buf_.size() < hdr_len + plen) break;

        std::vector<uint8_t> pl(raw_rx_buf_.begin() + static_cast<ptrdiff_t>(hdr_len),
                                raw_rx_buf_.begin() + static_cast<ptrdiff_t>(hdr_len + plen));
        if (masked) {
            const uint8_t* mkey = raw_rx_buf_.data() + (hdr_len - 4u);
            for (size_t i = 0; i < pl.size(); ++i) pl[i] ^= mkey[i & 3u];
        }
        raw_rx_buf_.erase(raw_rx_buf_.begin(), raw_rx_buf_.begin() + static_cast<ptrdiff_t>(hdr_len + plen));

        if (opcode == 0x08u) {
            remote_eof_ = true;
            break;
        } else if (opcode == 0x09u) {  // Ping -> queue Pong
            AppendWsMaskedFrame(tx_buf_, 0x0Au, pl.data(), pl.size());
        } else if (opcode == 0x02u || opcode == 0x01u || opcode == 0x00u) {
            pt_rx_buf_.insert(pt_rx_buf_.end(), pl.begin(), pl.end());
        }
    }
}

void TransportPipeline::ProcessIncomingGrpc() noexcept {
    // Strip optional HTTP/2 server preface/frames
    while (raw_rx_buf_.size() >= 9u) {
        const uint32_t flen = ReadBe24(raw_rx_buf_.data());
        const uint8_t ftype = raw_rx_buf_[3];
        const uint8_t fflags = raw_rx_buf_[4];
        const uint32_t sid = ReadBe32(raw_rx_buf_.data() + 5) & 0x7FFFFFFFu;
        if (flen > 1u << 20) {
            remote_eof_ = true;
            return;
        }
        if (raw_rx_buf_.size() < 9u + flen) break;

        const uint8_t* pl = raw_rx_buf_.data() + 9u;
        if (ftype == 0x04 /*SETTINGS*/ && (fflags & 0x01u) == 0) {
            AppendH2Frame(tx_buf_, 0x04, 0x01 /*ACK*/, 0, nullptr, 0);
        } else if (ftype == 0x06 /*PING*/ && (fflags & 0x01u) == 0 && flen == 8u) {
            AppendH2Frame(tx_buf_, 0x06, 0x01 /*ACK*/, 0, pl, 8);
        } else if (ftype == 0x07 /*GOAWAY*/ || (ftype == 0x03 /*RST_STREAM*/ && sid == 1)) {
            remote_eof_ = true;
        } else if (ftype == 0x00 /*DATA*/ && sid == 1) {
            size_t pos = 0;
            // Decode gRPC messages (5B header + protobuf field 1 Hunk 0x0A + varint + bytes)
            while (pos + 5u <= flen) {
                const uint32_t grpc_len = ReadBe32(pl + pos + 1);
                if (pos + 5u + grpc_len > flen) break;
                const uint8_t* pb = pl + pos + 5u;
                size_t ppos = 0;
                while (ppos < grpc_len) {
                    const uint8_t tag = pb[ppos++];
                    if (tag == 0x0Au) {
                        size_t dlen = 0, shift = 0;
                        while (ppos < grpc_len) {
                            const uint8_t b = pb[ppos++];
                            dlen |= static_cast<size_t>(b & 0x7Fu) << shift;
                            if ((b & 0x80u) == 0) break;
                            shift += 7;
                        }
                        if (ppos + dlen <= grpc_len) {
                            pt_rx_buf_.insert(pt_rx_buf_.end(), pb + ppos, pb + ppos + dlen);
                            ppos += dlen;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                pos += 5u + grpc_len;
            }
            if ((fflags & 0x01u) != 0) remote_eof_ = true;
        }
        raw_rx_buf_.erase(raw_rx_buf_.begin(), raw_rx_buf_.begin() + static_cast<ptrdiff_t>(9u + flen));
    }
}

void TransportPipeline::ProcessIncomingXhttp() noexcept {
    if (!xhttp_chunked_rx_) {
        pt_rx_buf_.insert(pt_rx_buf_.end(), raw_rx_buf_.begin(), raw_rx_buf_.end());
        raw_rx_buf_.clear();
        return;
    }
    while (!raw_rx_buf_.empty()) {
        if (xhttp_need_crlf_) {
            if (raw_rx_buf_.size() < 2u) break;
            raw_rx_buf_.erase(raw_rx_buf_.begin(), raw_rx_buf_.begin() + 2);
            xhttp_need_crlf_ = false;
            continue;
        }
        if (xhttp_chunk_rem_ > 0) {
            const size_t n = std::min(xhttp_chunk_rem_, raw_rx_buf_.size());
            pt_rx_buf_.insert(pt_rx_buf_.end(), raw_rx_buf_.begin(), raw_rx_buf_.begin() + static_cast<ptrdiff_t>(n));
            raw_rx_buf_.erase(raw_rx_buf_.begin(), raw_rx_buf_.begin() + static_cast<ptrdiff_t>(n));
            xhttp_chunk_rem_ -= n;
            if (xhttp_chunk_rem_ == 0) xhttp_need_crlf_ = true;
            continue;
        }
        auto it = std::search(raw_rx_buf_.begin(), raw_rx_buf_.end(), "\r\n", "\r\n" + 2);
        if (it == raw_rx_buf_.end()) break;
        const size_t line_len = static_cast<size_t>(it - raw_rx_buf_.begin());
        size_t sz = 0;
        for (size_t i = 0; i < line_len; ++i) {
            const char c = static_cast<char>(raw_rx_buf_[i]);
            if (c == ';') break;
            int v = -1;
            if (c >= '0' && c <= '9') v = c - '0';
            else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
            if (v >= 0) sz = (sz << 4) | static_cast<size_t>(v);
        }
        raw_rx_buf_.erase(raw_rx_buf_.begin(), it + 2);
        if (sz == 0) {
            remote_eof_ = true;
            break;
        }
        xhttp_chunk_rem_ = sz;
    }
}

bool TransportPipeline::FlushTxBuf() noexcept {
    while (tx_off_ < tx_buf_.size()) {
        const auto io = RawWriteNonBlocking(tx_buf_.data() + tx_off_, tx_buf_.size() - tx_off_);
        if (io.status == IoStatus::Ok && io.bytes > 0) {
            tx_off_ += io.bytes;
        } else if (io.status == IoStatus::WouldBlock) {
            return true;
        } else {
            return false;
        }
    }
    tx_buf_.clear();
    tx_off_ = 0;
    return FlushPending();
}

bool TransportPipeline::WriteBlocking(const uint8_t* data, size_t len, int timeout_ms) noexcept {
    if (kind_ == TransportKind::Raw || kind_ == TransportKind::HttpUpgrade) {
        return RawWriteBlocking(data, len, timeout_ms);
    }
    const uint64_t deadline = MonotonicMs() + static_cast<uint64_t>(std::max(1, timeout_ms));
    size_t off = 0;
    while (off < len || HasPendingWrite()) {
        const auto w = WriteNonBlocking(data + off, len - off);
        if (w.status == IoStatus::Ok) {
            off += w.bytes;
            if (off >= len && !HasPendingWrite()) return true;
        } else if (w.status != IoStatus::WouldBlock) {
            return false;
        }
        const uint64_t now = MonotonicMs();
        if (now >= deadline) return false;
        WaitSingleSocket(sock_.Fd(), false, true, static_cast<int>(std::min<uint64_t>(deadline - now, 200ULL)));
    }
    return true;
}

IoResult TransportPipeline::WriteNonBlocking(const uint8_t* data, size_t len) noexcept {
    if (!sock_.IsValid()) return {IoStatus::Error, 0};
    if (kind_ == TransportKind::Raw || kind_ == TransportKind::HttpUpgrade) {
        return RawWriteNonBlocking(data, len);
    }
    if (!FlushTxBuf()) return {IoStatus::Error, 0};
    if (tx_off_ < tx_buf_.size()) return {IoStatus::WouldBlock, 0};
    if (len == 0) return {IoStatus::Ok, 0};

    const size_t chunk = std::min<size_t>(len, 16384u);
    if (kind_ == TransportKind::WebSocket) {
        AppendWsMaskedFrame(tx_buf_, 0x02u, data, chunk);
    } else if (kind_ == TransportKind::Grpc) {
        std::vector<uint8_t> pb;
        pb.reserve(5 + chunk);
        pb.push_back(0x0Au);
        AppendVarintPb(pb, chunk);
        pb.insert(pb.end(), data, data + chunk);

        std::vector<uint8_t> grpc_msg(5u + pb.size());
        grpc_msg[0] = 0x00;
        grpc_msg[1] = static_cast<uint8_t>((pb.size() >> 24) & 0xFFu);
        grpc_msg[2] = static_cast<uint8_t>((pb.size() >> 16) & 0xFFu);
        grpc_msg[3] = static_cast<uint8_t>((pb.size() >> 8) & 0xFFu);
        grpc_msg[4] = static_cast<uint8_t>(pb.size() & 0xFFu);
        std::memcpy(grpc_msg.data() + 5, pb.data(), pb.size());
        AppendH2Frame(tx_buf_, 0x00 /*DATA*/, 0x00, 1, grpc_msg.data(), grpc_msg.size());
    } else if (kind_ == TransportKind::Xhttp) {
        char hdr[32];
        const int hn = std::snprintf(hdr, sizeof(hdr), "%zx\r\n", chunk);
        tx_buf_.insert(tx_buf_.end(), hdr, hdr + hn);
        tx_buf_.insert(tx_buf_.end(), data, data + chunk);
        tx_buf_.push_back('\r');
        tx_buf_.push_back('\n');
    }

    if (!FlushTxBuf()) return {IoStatus::Error, 0};
    return {IoStatus::Ok, chunk};
}

IoResult TransportPipeline::ReadNonBlocking(uint8_t* out, size_t cap) noexcept {
    if (!sock_.IsValid()) return {IoStatus::Error, 0};
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

    if (kind_ == TransportKind::Raw || kind_ == TransportKind::HttpUpgrade) {
        return RawReadNonBlocking(out, cap);
    }
    if (remote_eof_) return {IoStatus::Eof, 0};

    uint8_t tmp[8192];
    const auto io = RawReadNonBlocking(tmp, sizeof(tmp));
    if (io.status == IoStatus::Ok && io.bytes > 0) {
        raw_rx_buf_.insert(raw_rx_buf_.end(), tmp, tmp + io.bytes);
        if (kind_ == TransportKind::WebSocket) ProcessIncomingWs();
        else if (kind_ == TransportKind::Grpc) ProcessIncomingGrpc();
        else if (kind_ == TransportKind::Xhttp) ProcessIncomingXhttp();
    } else if (io.status == IoStatus::Eof) {
        remote_eof_ = true;
    } else if (io.status == IoStatus::Error) {
        return {IoStatus::Error, 0};
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
    if (remote_eof_) return {IoStatus::Eof, 0};
    return {IoStatus::WouldBlock, 0};
}

bool TransportPipeline::FlushPending() noexcept {
    if (use_tls_ && !tls_.FlushPendingWrite(sock_)) return false;
    while (tx_off_ < tx_buf_.size()) {
        const auto io = RawWriteNonBlocking(tx_buf_.data() + tx_off_, tx_buf_.size() - tx_off_);
        if (io.status == IoStatus::Ok && io.bytes > 0) {
            tx_off_ += io.bytes;
        } else if (io.status == IoStatus::WouldBlock) {
            break;
        } else {
            return false;
        }
    }
    if (tx_off_ >= tx_buf_.size()) {
        tx_buf_.clear();
        tx_off_ = 0;
    }
    return true;
}

bool TransportPipeline::HasPendingWrite() const noexcept {
    return (tx_off_ < tx_buf_.size()) || (use_tls_ && tls_.HasPendingCipherWrite());
}

void TransportPipeline::Close() noexcept {
    if (sock_.IsValid()) {
        if (use_tls_) tls_.SendCloseNotify(sock_);
        sock_.Close();
    }
    use_tls_ = false;
    remote_eof_ = false;
    xhttp_chunked_rx_ = true;
    xhttp_chunk_rem_ = 0;
    xhttp_need_crlf_ = false;
    tx_buf_.clear();
    tx_off_ = 0;
    raw_rx_buf_.clear();
    pt_rx_buf_.clear();
    pt_rx_off_ = 0;
}

}  // namespace yumi_nx::net
