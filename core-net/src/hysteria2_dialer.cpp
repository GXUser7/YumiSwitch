#include "yumi_nx/hysteria2_dialer.hpp"

#include <algorithm>
#include <cstring>

#include "yumi_nx/crypto.hpp"

namespace yumi_nx::net {

namespace {

constexpr uint8_t kQuicV1InitialSalt[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

inline void StoreBe32(uint8_t* p, uint32_t v) noexcept {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}

inline uint32_t LoadLe32(const uint8_t* p) noexcept {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

void BuildQuicNonce(const uint8_t iv[12], uint64_t pn, uint8_t out_nonce[12]) noexcept {
    std::memcpy(out_nonce, iv, 12);
    for (int i = 0; i < 8; ++i) {
        out_nonce[4 + i] ^= static_cast<uint8_t>((pn >> ((7 - i) * 8)) & 0xFFu);
    }
}

void ComputeHpMask(const QuicLevelKeys& k, const uint8_t sample16[16], uint8_t out_mask5[5]) noexcept {
    if (k.cipher_suite == 0x1303) {
        const uint32_t counter = LoadLe32(sample16);
        uint8_t zeros[5]{};
        uint8_t block[5]{};
        crypto::ChaCha20Xor(k.hp, counter, sample16 + 4, zeros, 5, block);
        std::memcpy(out_mask5, block, 5);
    } else {
        uint8_t enc[16]{};
        crypto::AesEcbEncryptBlock(k.hp, k.key_len, sample16, enc);
        std::memcpy(out_mask5, enc, 5);
    }
}

bool AeadEncryptQuic(const QuicLevelKeys& k, const uint8_t nonce[12],
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* pt, size_t pt_len,
                     uint8_t* ct_and_tag) noexcept {
    if (k.cipher_suite == 0x1303) {
        return crypto::ChaCha20Poly1305Encrypt(k.key, nonce, aad, aad_len, pt, pt_len, ct_and_tag, ct_and_tag + pt_len);
    }
    return crypto::AesGcmEncrypt(k.key, k.key_len, nonce, aad, aad_len, pt, pt_len, ct_and_tag, ct_and_tag + pt_len);
}

bool AeadDecryptQuic(const QuicLevelKeys& k, const uint8_t nonce[12],
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* ct, size_t ct_len,
                     const uint8_t tag[16], uint8_t* pt) noexcept {
    if (k.cipher_suite == 0x1303) {
        return crypto::ChaCha20Poly1305Decrypt(k.key, nonce, aad, aad_len, ct, ct_len, tag, pt);
    }
    return crypto::AesGcmDecrypt(k.key, k.key_len, nonce, aad, aad_len, ct, ct_len, tag, pt);
}

void AppendTpVarint(std::vector<uint8_t>& tp, uint64_t id, uint64_t val) {
    QuicEncodeVarint(tp, id);
    std::vector<uint8_t> vbytes;
    QuicEncodeVarint(vbytes, val);
    QuicEncodeVarint(tp, vbytes.size());
    tp.insert(tp.end(), vbytes.begin(), vbytes.end());
}

std::vector<uint8_t> BuildQuicTransportParamsExtension(const std::vector<uint8_t>& scid) {
    std::vector<uint8_t> tp;
    AppendTpVarint(tp, 0x01, 30000);       // max_idle_timeout (30s)
    AppendTpVarint(tp, 0x04, 4194304);     // initial_max_data (4MB)
    AppendTpVarint(tp, 0x05, 1048576);     // initial_max_stream_data_bidi_local
    AppendTpVarint(tp, 0x06, 1048576);     // initial_max_stream_data_bidi_remote
    AppendTpVarint(tp, 0x07, 1048576);     // initial_max_stream_data_uni
    AppendTpVarint(tp, 0x08, 16);          // initial_max_streams_bidi
    AppendTpVarint(tp, 0x09, 8);           // initial_max_streams_uni
    QuicEncodeVarint(tp, 0x0F);            // initial_source_connection_id
    QuicEncodeVarint(tp, scid.size());
    tp.insert(tp.end(), scid.begin(), scid.end());

    std::vector<uint8_t> ext;
    ext.push_back(0x00);
    ext.push_back(0x39);  // quic_transport_parameters extension
    ext.push_back(static_cast<uint8_t>((tp.size() >> 8) & 0xFFu));
    ext.push_back(static_cast<uint8_t>(tp.size() & 0xFFu));
    ext.insert(ext.end(), tp.begin(), tp.end());
    return ext;
}

void AppendQpackLiteral(std::vector<uint8_t>& out, std::string_view name, std::string_view value) {
    // RFC 9204 Literal Field Line with Name Reference/Literal (N=0, H=0)
    // Prefix 001 (0x20) + 3-bit name length (no Huffman)
    const size_t nlen = name.size();
    if (nlen < 7) {
        out.push_back(static_cast<uint8_t>(0x20u | nlen));
    } else {
        out.push_back(0x27u);
        size_t rem = nlen - 7;
        while (rem >= 128) {
            out.push_back(static_cast<uint8_t>((rem & 0x7Fu) | 0x80u));
            rem >>= 7;
        }
        out.push_back(static_cast<uint8_t>(rem));
    }
    out.insert(out.end(), name.begin(), name.end());

    const size_t vlen = value.size();
    if (vlen < 127) {
        out.push_back(static_cast<uint8_t>(vlen));
    } else {
        out.push_back(0x7Fu);
        size_t rem = vlen - 127;
        while (rem >= 128) {
            out.push_back(static_cast<uint8_t>((rem & 0x7Fu) | 0x80u));
            rem >>= 7;
        }
        out.push_back(static_cast<uint8_t>(rem));
    }
    out.insert(out.end(), value.begin(), value.end());
}

std::vector<uint8_t> BuildH3AuthRequest(std::string_view password, uint32_t down_mbps) {
    std::vector<uint8_t> qpack;
    qpack.push_back(0x00);  // Required Insert Count = 0
    qpack.push_back(0x00);  // Delta Base = 0
    qpack.push_back(0xD2);  // Indexed :method POST (static idx 18 -> 0xC0 | 18)
    qpack.push_back(0xD7);  // Indexed :scheme https (static idx 23 -> 0xC0 | 23)
    AppendQpackLiteral(qpack, ":authority", "hysteria");
    AppendQpackLiteral(qpack, ":path", "/auth");
    AppendQpackLiteral(qpack, "hysteria-auth", password);
    const std::string cc_rx = std::to_string(uint64_t(down_mbps) * 125000ULL);
    AppendQpackLiteral(qpack, "hysteria-cc-rx", cc_rx);
    AppendQpackLiteral(qpack, "hysteria-padding", "yumi-nx-pad-0123456789");

    std::vector<uint8_t> h3;
    QuicEncodeVarint(h3, 0x01);  // HEADERS frame
    QuicEncodeVarint(h3, qpack.size());
    h3.insert(h3.end(), qpack.begin(), qpack.end());
    return h3;
}

bool CheckH3Auth233Response(const std::vector<uint8_t>& buf) {
    size_t pos = 0;
    while (pos < buf.size()) {
        size_t c1 = 0, c2 = 0;
        uint64_t ftype = 0, flen = 0;
        if (!QuicDecodeVarint(buf.data() + pos, buf.size() - pos, c1, ftype)) return false;
        pos += c1;
        if (!QuicDecodeVarint(buf.data() + pos, buf.size() - pos, c2, flen)) return false;
        pos += c2;
        if (pos + flen > buf.size()) return false;
        if (ftype == 0x01) {
            // Check either literal "233" or HTTP status bytes
            std::string_view sv(reinterpret_cast<const char*>(buf.data() + pos), static_cast<size_t>(flen));
            if (sv.find("233") != std::string_view::npos) return true;
        }
        pos += static_cast<size_t>(flen);
    }
    return false;
}

uint64_t DecodePnReconstruct(uint64_t expected_pn, uint32_t trunc_pn, int pn_bits) noexcept {
    const uint64_t pn_win = 1ULL << pn_bits;
    const uint64_t pn_hwin = pn_win >> 1;
    const uint64_t pn_mask = pn_win - 1ULL;
    uint64_t cand = (expected_pn & ~pn_mask) | trunc_pn;
    if (cand + pn_hwin <= expected_pn && cand < (1ULL << 62) - pn_win) cand += pn_win;
    else if (cand > expected_pn + pn_hwin && cand >= pn_win) cand -= pn_win;
    return cand;
}

}  // namespace

void QuicEncodeVarint(std::vector<uint8_t>& out, uint64_t v) {
    if (v <= 63ULL) {
        out.push_back(static_cast<uint8_t>(v));
    } else if (v <= 16383ULL) {
        out.push_back(static_cast<uint8_t>(0x40u | ((v >> 8) & 0x3Fu)));
        out.push_back(static_cast<uint8_t>(v & 0xFFu));
    } else if (v <= 1073741823ULL) {
        out.push_back(static_cast<uint8_t>(0x80u | ((v >> 24) & 0x3Fu)));
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xFFu));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFu));
        out.push_back(static_cast<uint8_t>(v & 0xFFu));
    } else {
        out.push_back(static_cast<uint8_t>(0xC0u | ((v >> 56) & 0x3Fu)));
        for (int i = 6; i >= 0; --i) {
            out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFFu));
        }
    }
}

bool QuicDecodeVarint(const uint8_t* data, size_t len, size_t& out_consumed, uint64_t& out_val) noexcept {
    out_consumed = 0;
    out_val = 0;
    if (!data || len == 0) return false;
    const uint8_t tag = data[0] >> 6;
    const size_t nbytes = size_t(1) << tag;
    if (len < nbytes) return false;
    uint64_t v = data[0] & 0x3Fu;
    for (size_t i = 1; i < nbytes; ++i) {
        v = (v << 8) | data[i];
    }
    out_consumed = nbytes;
    out_val = v;
    return true;
}

bool QuicDeriveTrafficKeys(uint16_t cipher_suite, bool use_sha384,
                           const uint8_t* secret, QuicLevelKeys& out_keys) noexcept {
    if (!secret) return false;
    out_keys.cipher_suite = cipher_suite;
    out_keys.key_len = (cipher_suite == 0x1301) ? 16u : 32u;
    std::memset(out_keys.key, 0, 32);
    std::memset(out_keys.iv, 0, 12);
    std::memset(out_keys.hp, 0, 32);
    const bool ok1 = crypto::Tls13HkdfExpandLabel(use_sha384, secret, "quic key", nullptr, 0, out_keys.key, out_keys.key_len);
    const bool ok2 = crypto::Tls13HkdfExpandLabel(use_sha384, secret, "quic iv", nullptr, 0, out_keys.iv, 12);
    const bool ok3 = crypto::Tls13HkdfExpandLabel(use_sha384, secret, "quic hp", nullptr, 0, out_keys.hp, out_keys.key_len);
    out_keys.next_pn = 0;
    out_keys.largest_rx_pn = 0;
    out_keys.ready = ok1 && ok2 && ok3;
    return out_keys.ready;
}

bool QuicDeriveInitialKeys(const uint8_t* dcid, size_t dcid_len, bool is_client, QuicLevelKeys& out_keys) noexcept {
    uint8_t initial_secret[32]{};
    crypto::HkdfExtractSha256(kQuicV1InitialSalt, sizeof(kQuicV1InitialSalt), dcid, dcid_len, initial_secret);
    uint8_t traffic_secret[32]{};
    if (!crypto::Tls13HkdfExpandLabel(false, initial_secret, is_client ? "client in" : "server in", nullptr, 0, traffic_secret, 32)) {
        return false;
    }
    return QuicDeriveTrafficKeys(0x1301, false, traffic_secret, out_keys);
}

std::vector<uint8_t> Hysteria2SalamanderWrap(std::string_view password,
                                             const uint8_t salt8[8],
                                             const uint8_t* payload,
                                             size_t len) {
    std::vector<uint8_t> key_in;
    key_in.reserve(password.size() + 8u);
    key_in.insert(key_in.end(), password.begin(), password.end());
    key_in.insert(key_in.end(), salt8, salt8 + 8);
    uint8_t mask[32]{};
    crypto::Blake2b::Digest(nullptr, 0, key_in.data(), key_in.size(), mask, 32);

    std::vector<uint8_t> out(8u + len);
    std::memcpy(out.data(), salt8, 8);
    for (size_t i = 0; i < len; ++i) {
        out[8 + i] = payload[i] ^ mask[i & 31u];
    }
    return out;
}

bool Hysteria2SalamanderUnwrap(std::string_view password,
                               const uint8_t* datagram,
                               size_t len,
                               std::vector<uint8_t>& out_payload) {
    out_payload.clear();
    if (!datagram || len < 8u) return false;
    std::vector<uint8_t> key_in;
    key_in.reserve(password.size() + 8u);
    key_in.insert(key_in.end(), password.begin(), password.end());
    key_in.insert(key_in.end(), datagram, datagram + 8);
    uint8_t mask[32]{};
    crypto::Blake2b::Digest(nullptr, 0, key_in.data(), key_in.size(), mask, 32);

    out_payload.resize(len - 8u);
    for (size_t i = 0; i < out_payload.size(); ++i) {
        out_payload[i] = datagram[8 + i] ^ mask[i & 31u];
    }
    return true;
}

std::vector<uint8_t> Hysteria2EncodeTcpRequest(std::string_view host_port, size_t pad_len) {
    std::vector<uint8_t> out;
    out.reserve(16 + host_port.size() + pad_len);
    QuicEncodeVarint(out, 0x401ULL);
    QuicEncodeVarint(out, host_port.size());
    out.insert(out.end(), host_port.begin(), host_port.end());
    QuicEncodeVarint(out, pad_len);
    if (pad_len > 0) {
        const size_t base = out.size();
        out.resize(base + pad_len, 0);
        crypto::RandomBytes(out.data() + base, pad_len);
    }
    return out;
}

bool Hysteria2Stream::SendDatagram(const uint8_t* pkt, size_t len) noexcept {
    if (!sock_.IsValid()) return false;
    if (!use_salamander_) {
        return sock_.UdpSendTo(peer_ip_host_, node_.port, pkt, len);
    }
    uint8_t salt[8]{};
    if (!crypto::RandomBytes(salt, 8)) return false;
    const auto obfs = Hysteria2SalamanderWrap(node_.hysteria2.obfs_password, salt, pkt, len);
    return sock_.UdpSendTo(peer_ip_host_, node_.port, obfs.data(), obfs.size());
}

bool Hysteria2Stream::RecvDatagram(std::vector<uint8_t>& out_pkt, int timeout_ms, bool non_blocking) noexcept {
    uint8_t buf[4096];
    uint32_t rip = 0;
    uint16_t rport = 0;
    const uint64_t deadline = MonotonicMs() + static_cast<uint64_t>(std::max(1, timeout_ms));
    while (true) {
        const auto io = sock_.UdpRecvFrom(buf, sizeof(buf), rip, rport);
        if (io.status == IoStatus::Ok && io.bytes > 0) {
            if (use_salamander_) {
                if (!Hysteria2SalamanderUnwrap(node_.hysteria2.obfs_password, buf, io.bytes, out_pkt)) continue;
            } else {
                out_pkt.assign(buf, buf + io.bytes);
            }
            return true;
        }
        if (non_blocking || io.status != IoStatus::WouldBlock) return false;
        const uint64_t now = MonotonicMs();
        if (now >= deadline) return false;
        WaitSingleSocket(sock_.Fd(), true, false, static_cast<int>(std::min<uint64_t>(deadline - now, 100ULL)));
    }
}

std::vector<uint8_t> Hysteria2Stream::ProtectPacket(uint8_t,
                                                    bool is_long,
                                                    uint8_t packet_type_bits,
                                                    QuicLevelKeys& keys,
                                                    const std::vector<uint8_t>& payload,
                                                    size_t min_total_len) noexcept {
    const uint64_t pn = keys.next_pn++;
    constexpr uint8_t kPnLen = 2;  // 2-byte packet number encoding (pn_len - 1 == 1)

    std::vector<uint8_t> hdr;
    if (is_long) {
        hdr.push_back(static_cast<uint8_t>(0xC0u | ((packet_type_bits & 0x03u) << 4) | (kPnLen - 1u)));
        hdr.resize(5);
        StoreBe32(hdr.data() + 1, 0x00000001u);  // QUIC v1
        hdr.push_back(static_cast<uint8_t>(dcid_.size()));
        hdr.insert(hdr.end(), dcid_.begin(), dcid_.end());
        hdr.push_back(static_cast<uint8_t>(scid_.size()));
        hdr.insert(hdr.end(), scid_.begin(), scid_.end());
        if (packet_type_bits == 0x00) {  // Initial: token length + token
            QuicEncodeVarint(hdr, retry_token_.size());
            hdr.insert(hdr.end(), retry_token_.begin(), retry_token_.end());
        }
    } else {
        hdr.push_back(static_cast<uint8_t>(0x40u | (kPnLen - 1u)));
        hdr.insert(hdr.end(), dcid_.begin(), dcid_.end());
    }

    // Pad plaintext so protected packet satisfies min_total_len (e.g. 1200 for Initial) and >= 4B before PN for HP sample
    std::vector<uint8_t> pt = payload;
    while (pt.size() < 4u) pt.push_back(0x00);  // PADDING
    const size_t approx_hdr_len = hdr.size() + (is_long ? 2u : 0u) + kPnLen;
    if (min_total_len > approx_hdr_len + pt.size() + 16u) {
        pt.resize(min_total_len - approx_hdr_len - 16u, 0x00);
    }

    if (is_long) {
        // 2-byte varint payload length (kPnLen + pt.size() + 16)
        const uint64_t len_field = kPnLen + pt.size() + 16u;
        hdr.push_back(static_cast<uint8_t>(0x40u | ((len_field >> 8) & 0x3Fu)));
        hdr.push_back(static_cast<uint8_t>(len_field & 0xFFu));
    }

    const size_t pn_off = hdr.size();
    hdr.push_back(static_cast<uint8_t>((pn >> 8) & 0xFFu));
    hdr.push_back(static_cast<uint8_t>(pn & 0xFFu));

    std::vector<uint8_t> out(hdr.size() + pt.size() + 16u);
    std::memcpy(out.data(), hdr.data(), hdr.size());

    uint8_t nonce[12]{};
    BuildQuicNonce(keys.iv, pn, nonce);
    if (!AeadEncryptQuic(keys, nonce, hdr.data(), hdr.size(), pt.data(), pt.size(), out.data() + hdr.size())) {
        return {};
    }

    // Apply Header Protection (sample = out[pn_off + 4 .. pn_off + 20])
    uint8_t mask[5]{};
    ComputeHpMask(keys, out.data() + pn_off + 4u, mask);
    out[0] ^= is_long ? (mask[0] & 0x0Fu) : (mask[0] & 0x1Fu);
    for (uint8_t i = 0; i < kPnLen; ++i) {
        out[pn_off + i] ^= mask[1 + i];
    }
    return out;
}

void Hysteria2Stream::SendAckFrame(int level_idx, uint64_t largest_pn) noexcept {
    std::vector<uint8_t> f;
    f.push_back(0x02);  // ACK
    QuicEncodeVarint(f, largest_pn);
    QuicEncodeVarint(f, 0);  // ACK Delay
    QuicEncodeVarint(f, 0);  // Range Count
    QuicEncodeVarint(f, 0);  // First ACK Range
    if (level_idx == 0 && init_tx_.ready) {
        auto p = ProtectPacket(0xC0, true, 0x00, init_tx_, f);
        if (!p.empty()) SendDatagram(p.data(), p.size());
    } else if (level_idx == 1 && hs_tx_.ready) {
        auto p = ProtectPacket(0xE0, true, 0x02, hs_tx_, f);
        if (!p.empty()) SendDatagram(p.data(), p.size());
    } else if (level_idx == 2 && app_tx_.ready) {
        auto p = ProtectPacket(0x40, false, 0, app_tx_, f);
        if (!p.empty()) tx_queue_.push_back(std::move(p));
    }
}

bool Hysteria2Stream::ParseFrames(int level_idx, const uint8_t* pl, size_t len) noexcept {
    size_t pos = 0;
    while (pos < len) {
        const uint8_t ft = pl[pos++];
        if (ft == 0x00 || ft == 0x01) {  // PADDING / PING
            continue;
        }
        if (ft == 0x02 || ft == 0x03) {  // ACK / ACK_ECN
            size_t c = 0;
            uint64_t dummy = 0, rcnt = 0;
            if (!QuicDecodeVarint(pl + pos, len - pos, c, dummy)) return false;
            pos += c;
            if (!QuicDecodeVarint(pl + pos, len - pos, c, dummy)) return false;
            pos += c;
            if (!QuicDecodeVarint(pl + pos, len - pos, c, rcnt)) return false;
            pos += c;
            if (!QuicDecodeVarint(pl + pos, len - pos, c, dummy)) return false;
            pos += c;
            for (uint64_t i = 0; i < rcnt * 2ULL; ++i) {
                if (!QuicDecodeVarint(pl + pos, len - pos, c, dummy)) return false;
                pos += c;
            }
            if (ft == 0x03) {
                for (int i = 0; i < 3; ++i) {
                    if (!QuicDecodeVarint(pl + pos, len - pos, c, dummy)) return false;
                    pos += c;
                }
            }
        } else if (ft == 0x06) {  // CRYPTO
            size_t c1 = 0, c2 = 0;
            uint64_t off = 0, clen = 0;
            if (!QuicDecodeVarint(pl + pos, len - pos, c1, off)) return false;
            pos += c1;
            if (!QuicDecodeVarint(pl + pos, len - pos, c2, clen) || pos + clen > len) return false;
            const uint8_t* cdata = pl + pos;
            pos += static_cast<size_t>(clen);

            if (level_idx == 0) {
                if (tls_driver_.OnInitialServerBytes(cdata, static_cast<size_t>(clen)) &&
                    tls_driver_.HasHandshakeSecrets() && !hs_tx_.ready) {
                    const auto& sec = tls_driver_.Derived();
                    QuicDeriveTrafficKeys(sec.cipher_suite, sec.use_sha384, sec.client_hs_traffic, hs_tx_);
                    QuicDeriveTrafficKeys(sec.cipher_suite, sec.use_sha384, sec.server_hs_traffic, hs_rx_);
                }
            } else if (level_idx == 1 && tls_driver_.HasHandshakeSecrets()) {
                std::vector<uint8_t> c_fin;
                bool complete = false;
                if (!tls_driver_.OnHandshakeServerBytes(cdata, static_cast<size_t>(clen), c_fin, complete)) {
                    return false;
                }
                if (complete && !app_tx_.ready) {
                    const auto& sec = tls_driver_.Derived();
                    QuicDeriveTrafficKeys(sec.cipher_suite, sec.use_sha384, sec.client_ap_traffic, app_tx_);
                    QuicDeriveTrafficKeys(sec.cipher_suite, sec.use_sha384, sec.server_ap_traffic, app_rx_);
                    if (!c_fin.empty() && hs_tx_.ready) {
                        std::vector<uint8_t> cf_frame;
                        cf_frame.push_back(0x06);
                        QuicEncodeVarint(cf_frame, crypto_tx_off_[1]);
                        QuicEncodeVarint(cf_frame, c_fin.size());
                        cf_frame.insert(cf_frame.end(), c_fin.begin(), c_fin.end());
                        crypto_tx_off_[1] += c_fin.size();
                        auto pkt = ProtectPacket(0xE0, true, 0x02, hs_tx_, cf_frame);
                        if (!pkt.empty()) SendDatagram(pkt.data(), pkt.size());
                    }
                }
            }
        } else if (ft >= 0x08 && ft <= 0x0F) {  // STREAM
            const bool has_off = (ft & 0x04u) != 0;
            const bool has_len = (ft & 0x02u) != 0;
            const bool fin = (ft & 0x01u) != 0;
            size_t c = 0;
            uint64_t sid = 0, off = 0, slen = 0;
            if (!QuicDecodeVarint(pl + pos, len - pos, c, sid)) return false;
            pos += c;
            if (has_off) {
                if (!QuicDecodeVarint(pl + pos, len - pos, c, off)) return false;
                pos += c;
            }
            if (has_len) {
                if (!QuicDecodeVarint(pl + pos, len - pos, c, slen)) return false;
                pos += c;
            } else {
                slen = len - pos;
            }
            if (pos + slen > len) return false;
            const uint8_t* sdata = pl + pos;
            pos += static_cast<size_t>(slen);

            if (sid == 0) {
                auth_rx_buf_.insert(auth_rx_buf_.end(), sdata, sdata + slen);
                if (!auth_ok_ && CheckH3Auth233Response(auth_rx_buf_)) {
                    auth_ok_ = true;
                }
            } else if (sid == 4) {
                if (off <= tcp_rx_next_off_) {
                    const uint64_t skip = tcp_rx_next_off_ - off;
                    if (skip < slen) {
                        const uint8_t* newdata = sdata + skip;
                        const size_t nlen = static_cast<size_t>(slen - skip);
                        tcp_rx_next_off_ += nlen;
                        if (!tcp_resp_ok_) {
                            tcp_hdr_buf_.insert(tcp_hdr_buf_.end(), newdata, newdata + nlen);
                            // Parse TCPResponse: status(1B) + varint(msg_len) + msg + varint(pad_len) + pad
                            if (tcp_hdr_buf_.size() >= 3u) {
                                size_t p2 = 1;
                                size_t mc = 0, pc = 0;
                                uint64_t mlen = 0, plen = 0;
                                if (QuicDecodeVarint(tcp_hdr_buf_.data() + p2, tcp_hdr_buf_.size() - p2, mc, mlen)) {
                                    p2 += mc;
                                    if (p2 + mlen < tcp_hdr_buf_.size()) {
                                        p2 += static_cast<size_t>(mlen);
                                        if (QuicDecodeVarint(tcp_hdr_buf_.data() + p2, tcp_hdr_buf_.size() - p2, pc, plen)) {
                                            p2 += pc;
                                            if (p2 + plen <= tcp_hdr_buf_.size()) {
                                                if (tcp_hdr_buf_[0] != 0x00) return false;
                                                tcp_resp_ok_ = true;
                                                if (p2 + plen < tcp_hdr_buf_.size()) {
                                                    pt_rx_.insert(pt_rx_.end(),
                                                                  tcp_hdr_buf_.begin() + static_cast<ptrdiff_t>(p2 + plen),
                                                                  tcp_hdr_buf_.end());
                                                }
                                                tcp_hdr_buf_.clear();
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            pt_rx_.insert(pt_rx_.end(), newdata, newdata + nlen);
                        }
                    }
                }
                if (fin) remote_eof_ = true;
            }
        } else if (ft == 0x1C || ft == 0x1D) {  // CONNECTION_CLOSE
            remote_eof_ = true;
            return false;
        } else {
            // Other single-packet-control frames (HANDSHAKE_DONE 0x1E, NEW_TOKEN, MAX_DATA, etc.)
            if (ft == 0x1E) continue;
            break;
        }
    }
    return true;
}

bool Hysteria2Stream::UnprotectAndProcessPacket(const uint8_t* datagram, size_t total_len, bool& out_close) noexcept {
    out_close = false;
    size_t pos = 0;
    while (pos < total_len) {
        const uint8_t* pkt = datagram + pos;
        const size_t rem = total_len - pos;
        if (rem < 20u) break;

        const bool is_long = (pkt[0] & 0x80u) != 0;
        QuicLevelKeys* keys = nullptr;
        int level_idx = 2;
        size_t hdr_before_pn = 0;
        size_t pkt_total_len = rem;

        if (is_long) {
            const uint8_t ltype = (pkt[0] >> 4) & 0x03u;
            if (rem < 7u) break;
            if (ltype == 0x00) { keys = &init_rx_; level_idx = 0; }
            else if (ltype == 0x02) { keys = &hs_rx_; level_idx = 1; }
            else break;

            size_t p = 5u;
            const uint8_t dlen = pkt[p++];
            if (p + dlen >= rem) break;
            p += dlen;
            const uint8_t slen = pkt[p++];
            if (p + slen >= rem) break;
            // Capture server SCID on Initial/Handshake
            if (ltype == 0x00 && slen > 0) dcid_.assign(pkt + p, pkt + p + slen);
            p += slen;

            if (ltype == 0x00) {
                size_t tc = 0;
                uint64_t tlen = 0;
                if (!QuicDecodeVarint(pkt + p, rem - p, tc, tlen)) break;
                p += tc + static_cast<size_t>(tlen);
                if (p >= rem) break;
            }
            size_t lc = 0;
            uint64_t payload_len = 0;
            if (!QuicDecodeVarint(pkt + p, rem - p, lc, payload_len)) break;
            p += lc;
            if (p + payload_len > rem) break;
            hdr_before_pn = p;
            pkt_total_len = p + static_cast<size_t>(payload_len);
        } else {
            keys = &app_rx_;
            level_idx = 2;
            hdr_before_pn = 1u + scid_.size();
            pkt_total_len = rem;
        }

        pos += pkt_total_len;
        if (!keys || !keys->ready || hdr_before_pn + 20u > pkt_total_len) continue;

        uint8_t mask[5]{};
        ComputeHpMask(*keys, pkt + hdr_before_pn + 4u, mask);
        const uint8_t first_unmasked = pkt[0] ^ (is_long ? (mask[0] & 0x0Fu) : (mask[0] & 0x1Fu));
        const uint8_t pn_len = static_cast<uint8_t>((first_unmasked & 0x03u) + 1u);
        if (hdr_before_pn + pn_len + 16u > pkt_total_len) continue;

        std::vector<uint8_t> aad(pkt, pkt + hdr_before_pn + pn_len);
        aad[0] = first_unmasked;
        uint32_t trunc_pn = 0;
        for (uint8_t i = 0; i < pn_len; ++i) {
            aad[hdr_before_pn + i] ^= mask[1 + i];
            trunc_pn = (trunc_pn << 8) | aad[hdr_before_pn + i];
        }
        const uint64_t full_pn = DecodePnReconstruct(keys->largest_rx_pn + 1ULL, trunc_pn, pn_len * 8);
        if (full_pn > keys->largest_rx_pn) keys->largest_rx_pn = full_pn;

        uint8_t nonce[12]{};
        BuildQuicNonce(keys->iv, full_pn, nonce);

        const size_t ct_off = hdr_before_pn + pn_len;
        const size_t ct_len = pkt_total_len - ct_off - 16u;
        std::vector<uint8_t> pt(ct_len);
        if (!AeadDecryptQuic(*keys, nonce, aad.data(), aad.size(),
                             pkt + ct_off, ct_len, pkt + ct_off + ct_len, pt.data())) {
            continue;
        }

        if (!ParseFrames(level_idx, pt.data(), pt.size())) {
            out_close = true;
            return false;
        }
        SendAckFrame(level_idx, full_pn);
    }
    return true;
}

bool Hysteria2Stream::SendStreamBytes(uint64_t stream_id, const uint8_t* data, size_t len, bool fin) noexcept {
    if (!app_tx_.ready) return false;
    std::vector<uint8_t> frame;
    frame.push_back(static_cast<uint8_t>(0x08u | 0x04u | 0x02u | (fin ? 0x01u : 0x00u)));
    uint64_t& off = (stream_id == 0) ? auth_stream_off_ : tcp_tx_off_;
    QuicEncodeVarint(frame, stream_id);
    QuicEncodeVarint(frame, off);
    QuicEncodeVarint(frame, len);
    frame.insert(frame.end(), data, data + len);
    off += len;

    auto pkt = ProtectPacket(0x40, false, 0, app_tx_, frame);
    if (pkt.empty()) return false;
    tx_queue_.push_back(std::move(pkt));
    return true;
}

bool Hysteria2Stream::Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms) noexcept {
    Close();
    if (node_.password_or_key.empty()) return false;
    use_salamander_ = (node_.hysteria2.obfs_type == "salamander" && !node_.hysteria2.obfs_password.empty());

    uint32_t srv_be = 0;
    if (!resolver.ResolveIPv4(node_.server, srv_be)) return false;
    peer_ip_host_ = ((srv_be & 0xFFu) << 24) | ((srv_be & 0xFF00u) << 8) |
                    ((srv_be >> 8) & 0xFF00u) | ((srv_be >> 24) & 0xFFu);

    sock_ = NetSocket::CreateUdp(true);
    if (!sock_.IsValid()) return false;

    dcid_.resize(8);
    scid_.resize(8);
    if (!crypto::RandomBytes(dcid_.data(), 8) || !crypto::RandomBytes(scid_.data(), 8)) return false;
    if (!QuicDeriveInitialKeys(dcid_.data(), dcid_.size(), true, init_tx_) ||
        !QuicDeriveInitialKeys(dcid_.data(), dcid_.size(), false, init_rx_)) {
        return false;
    }

    const std::string& sni = !node_.tls.server_name.empty() ? node_.tls.server_name : node_.server;
    const TlsFingerprint fp = ResolveEffectiveFingerprint(settings_.tls_fingerprint, node_.tls.fingerprint);
    const auto tp_ext = BuildQuicTransportParamsExtension(scid_);
    std::vector<uint8_t> ch;
    if (!tls_driver_.Start(sni, {"h3"}, tp_ext, fp, ch)) return false;

    std::vector<uint8_t> crypto_f;
    crypto_f.push_back(0x06);
    QuicEncodeVarint(crypto_f, 0);
    QuicEncodeVarint(crypto_f, ch.size());
    crypto_f.insert(crypto_f.end(), ch.begin(), ch.end());
    crypto_tx_off_[0] = ch.size();

    auto init_pkt = ProtectPacket(0xC0, true, 0x00, init_tx_, crypto_f, 1200u);
    if (init_pkt.empty() || !SendDatagram(init_pkt.data(), init_pkt.size())) {
        Close();
        return false;
    }

    const uint64_t deadline = MonotonicMs() + static_cast<uint64_t>(timeout_ms);
    while (!app_tx_.ready && MonotonicMs() < deadline) {
        std::vector<uint8_t> rx_pkt;
        if (RecvDatagram(rx_pkt, 200, false)) {
            bool closed = false;
            UnprotectAndProcessPacket(rx_pkt.data(), rx_pkt.size(), closed);
            if (closed) { Close(); return false; }
        }
    }
    if (!app_tx_.ready) { Close(); return false; }

    // Flush Client Control stream (stream 2) + H3 Auth request (stream 0)
    {
        std::vector<uint8_t> ctrl;
        ctrl.push_back(0x08u | 0x04u | 0x02u);
        QuicEncodeVarint(ctrl, 2);  // uni stream 2
        QuicEncodeVarint(ctrl, 0);
        static constexpr uint8_t kH3Ctrl[3] = {0x00, 0x04, 0x00};  // H3 Control + SETTINGS(len=0)
        QuicEncodeVarint(ctrl, sizeof(kH3Ctrl));
        ctrl.insert(ctrl.end(), kH3Ctrl, kH3Ctrl + sizeof(kH3Ctrl));
        auto p = ProtectPacket(0x40, false, 0, app_tx_, ctrl);
        if (!p.empty()) tx_queue_.push_back(std::move(p));
    }

    const auto auth_h3 = BuildH3AuthRequest(node_.password_or_key, node_.hysteria2.down_mbps);
    if (!SendStreamBytes(0, auth_h3.data(), auth_h3.size(), true)) { Close(); return false; }
    if (!FlushPending()) { Close(); return false; }

    while (!auth_ok_ && MonotonicMs() < deadline) {
        std::vector<uint8_t> rx_pkt;
        if (RecvDatagram(rx_pkt, 200, false)) {
            bool closed = false;
            UnprotectAndProcessPacket(rx_pkt.data(), rx_pkt.size(), closed);
            if (closed) { Close(); return false; }
            FlushPending();
        }
    }
    if (!auth_ok_) { Close(); return false; }

    // Open Hysteria2 TCP stream 4
    const std::string addr = target.host + ":" + std::to_string(target.port);
    const auto tcp_req = Hysteria2EncodeTcpRequest(addr, 16);
    if (!SendStreamBytes(4, tcp_req.data(), tcp_req.size(), false) || !FlushPending()) {
        Close();
        return false;
    }

    while (!tcp_resp_ok_ && MonotonicMs() < deadline) {
        std::vector<uint8_t> rx_pkt;
        if (RecvDatagram(rx_pkt, 200, false)) {
            bool closed = false;
            UnprotectAndProcessPacket(rx_pkt.data(), rx_pkt.size(), closed);
            if (closed) { Close(); return false; }
            FlushPending();
        }
    }
    if (!tcp_resp_ok_) { Close(); return false; }
    return true;
}

bool Hysteria2Stream::FlushPending() noexcept {
    while (!tx_queue_.empty()) {
        const auto& pkt = tx_queue_.front();
        if (!SendDatagram(pkt.data(), pkt.size())) return false;
        tx_queue_.erase(tx_queue_.begin());
    }
    return true;
}

IoResult Hysteria2Stream::WriteNonBlocking(const uint8_t* data, size_t len) noexcept {
    if (!sock_.IsValid() || !tcp_resp_ok_) return {IoStatus::Error, 0};
    if (!FlushPending()) return {IoStatus::Error, 0};
    if (len == 0) return {IoStatus::Ok, 0};

    const size_t chunk = std::min<size_t>(len, 1150u);
    if (!SendStreamBytes(4, data, chunk, false)) return {IoStatus::Error, 0};
    if (!FlushPending()) return {IoStatus::Error, 0};
    return {IoStatus::Ok, chunk};
}

IoResult Hysteria2Stream::ReadNonBlocking(uint8_t* out, size_t cap) noexcept {
    if (!sock_.IsValid()) return {IoStatus::Error, 0};
    if (pt_off_ < pt_rx_.size()) {
        const size_t n = std::min(cap, pt_rx_.size() - pt_off_);
        std::memcpy(out, pt_rx_.data() + pt_off_, n);
        pt_off_ += n;
        if (pt_off_ >= pt_rx_.size()) { pt_rx_.clear(); pt_off_ = 0; }
        return {IoStatus::Ok, n};
    }
    if (remote_eof_) return {IoStatus::Eof, 0};

    for (int i = 0; i < 4; ++i) {
        std::vector<uint8_t> rx_pkt;
        if (!RecvDatagram(rx_pkt, 0, true)) break;
        bool closed = false;
        UnprotectAndProcessPacket(rx_pkt.data(), rx_pkt.size(), closed);
        if (closed) break;
    }
    FlushPending();

    if (pt_off_ < pt_rx_.size()) {
        const size_t n = std::min(cap, pt_rx_.size() - pt_off_);
        std::memcpy(out, pt_rx_.data() + pt_off_, n);
        pt_off_ += n;
        if (pt_off_ >= pt_rx_.size()) { pt_rx_.clear(); pt_off_ = 0; }
        return {IoStatus::Ok, n};
    }
    if (remote_eof_) return {IoStatus::Eof, 0};
    return {IoStatus::WouldBlock, 0};
}

void Hysteria2Stream::Close() noexcept {
    sock_.Close();
    peer_ip_host_ = 0;
    use_salamander_ = false;
    dcid_.clear();
    scid_.clear();
    retry_token_.clear();
    init_tx_ = {}; init_rx_ = {};
    hs_tx_ = {}; hs_rx_ = {};
    app_tx_ = {}; app_rx_ = {};
    std::memset(crypto_tx_off_, 0, sizeof(crypto_tx_off_));
    auth_stream_off_ = 0;
    tcp_tx_off_ = 0;
    tcp_rx_next_off_ = 0;
    auth_rx_buf_.clear();
    tcp_hdr_buf_.clear();
    auth_ok_ = false;
    tcp_resp_ok_ = false;
    remote_eof_ = false;
    tx_queue_.clear();
    pt_rx_.clear();
    pt_off_ = 0;
}

}  // namespace yumi_nx::net
