#include "yumi_nx/wireguard_dialer.hpp"

#include <algorithm>
#include <cstring>

#include "yumi_nx/crypto.hpp"

namespace yumi_nx::net {

namespace {

inline uint16_t LoadBe16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>((uint16_t(p[0]) << 8) | p[1]);
}
inline uint32_t LoadBe32(const uint8_t* p) noexcept {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
inline uint32_t LoadLe32(const uint8_t* p) noexcept {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline uint64_t LoadLe64(const uint8_t* p) noexcept {
    return uint64_t(LoadLe32(p)) | (uint64_t(LoadLe32(p + 4)) << 32);
}
inline void StoreBe16(uint8_t* p, uint16_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}
inline void StoreBe32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}
inline void StoreLe32(uint8_t* p, uint32_t v) noexcept {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}
inline void StoreLe64(uint8_t* p, uint64_t v) noexcept {
    StoreLe32(p, uint32_t(v));
    StoreLe32(p + 4, uint32_t(v >> 32));
}
inline uint32_t Swap32(uint32_t v) noexcept {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

void WgHash(const void* a, size_t alen, uint8_t out[32]) noexcept {
    crypto::Blake2s::Digest(nullptr, 0, a, alen, out, 32);
}

void WgMixHash(uint8_t h[32], const void* data, size_t len) noexcept {
    crypto::Blake2s b;
    b.Init(32);
    b.Update(h, 32);
    if (data && len > 0) b.Update(data, len);
    b.Final(h);
}

void HmacBlake2s(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t out[32]) noexcept {
    uint8_t k0[64]{};
    if (key && key_len > 64) WgHash(key, key_len, k0);
    else if (key && key_len > 0) std::memcpy(k0, key, key_len);

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k0[i] ^ 0x36u;
        opad[i] = k0[i] ^ 0x5cu;
    }
    uint8_t inner[32];
    crypto::Blake2s b;
    b.Init(32);
    b.Update(ipad, 64);
    if (data && data_len > 0) b.Update(data, data_len);
    b.Final(inner);

    b.Init(32);
    b.Update(opad, 64);
    b.Update(inner, 32);
    b.Final(out);
}

void WgKdf1(const uint8_t key[32], const uint8_t* input, size_t len, uint8_t t1[32]) noexcept {
    uint8_t tau0[32];
    HmacBlake2s(key, 32, input, len, tau0);
    const uint8_t c = 0x01;
    HmacBlake2s(tau0, 32, &c, 1, t1);
}

void WgKdf2(const uint8_t key[32], const uint8_t* input, size_t len, uint8_t t1[32], uint8_t t2[32]) noexcept {
    uint8_t tau0[32];
    HmacBlake2s(key, 32, input, len, tau0);
    const uint8_t c1 = 0x01;
    HmacBlake2s(tau0, 32, &c1, 1, t1);
    uint8_t buf[33];
    std::memcpy(buf, t1, 32);
    buf[32] = 0x02;
    HmacBlake2s(tau0, 32, buf, 33, t2);
}

void WgKdf3(const uint8_t key[32], const uint8_t* input, size_t len, uint8_t t1[32], uint8_t t2[32], uint8_t t3[32]) noexcept {
    uint8_t tau0[32];
    HmacBlake2s(key, 32, input, len, tau0);
    const uint8_t c1 = 0x01;
    HmacBlake2s(tau0, 32, &c1, 1, t1);
    uint8_t buf[33];
    std::memcpy(buf, t1, 32);
    buf[32] = 0x02;
    HmacBlake2s(tau0, 32, buf, 33, t2);
    std::memcpy(buf, t2, 32);
    buf[32] = 0x03;
    HmacBlake2s(tau0, 32, buf, 33, t3);
}

void ComputeMac1(const uint8_t peer_pub[32], const uint8_t* msg_prefix, size_t prefix_len, uint8_t out_mac1[16]) noexcept {
    uint8_t mac_input[40];
    static constexpr uint8_t kLabelMac1[8] = {'m', 'a', 'c', '1', '-', '-', '-', '-'};
    std::memcpy(mac_input, kLabelMac1, 8);
    std::memcpy(mac_input + 8, peer_pub, 32);
    uint8_t key[32];
    WgHash(mac_input, 40, key);
    crypto::Blake2s::Digest(key, 32, msg_prefix, prefix_len, out_mac1, 16);
}

void WgInitNoisePreamble(const uint8_t responder_pub[32], uint8_t out_ck[32], uint8_t out_h[32]) noexcept {
    static constexpr const char kConstruction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    static constexpr const char kIdentifier[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
    WgHash(kConstruction, sizeof(kConstruction) - 1, out_ck);
    std::memcpy(out_h, out_ck, 32);
    WgMixHash(out_h, kIdentifier, sizeof(kIdentifier) - 1);
    WgMixHash(out_h, responder_pub, 32);
}

}  // namespace

bool WgBuildHandshakeInitiation(const uint8_t local_static_priv[32],
                                const uint8_t peer_static_pub[32],
                                const uint8_t psk[32],
                                bool has_psk,
                                uint32_t local_index,
                                const uint8_t reserved[3],
                                const uint8_t tai64n[12],
                                WgHandshakeScratch& out_scratch,
                                uint8_t out_msg[148]) noexcept {
    out_scratch = {};
    if (!crypto::RandomBytes(out_scratch.eph_priv, 32)) return false;
    out_scratch.local_index = local_index;
    std::memcpy(out_scratch.peer_static_pub, peer_static_pub, 32);
    out_scratch.has_psk = has_psk;
    if (has_psk && psk) std::memcpy(out_scratch.psk, psk, 32);

    uint8_t local_static_pub[32]{};
    crypto::X25519Base(local_static_pub, local_static_priv);
    uint8_t eph_pub[32]{};
    crypto::X25519Base(eph_pub, out_scratch.eph_priv);

    WgInitNoisePreamble(peer_static_pub, out_scratch.chain_key, out_scratch.hash);
    std::memset(out_msg, 0, 148);
    out_msg[0] = 1;  // Handshake Initiation
    if (reserved) std::memcpy(out_msg + 1, reserved, 3);
    StoreLe32(out_msg + 4, local_index);
    std::memcpy(out_msg + 8, eph_pub, 32);

    WgKdf1(out_scratch.chain_key, eph_pub, 32, out_scratch.chain_key);
    WgMixHash(out_scratch.hash, eph_pub, 32);

    uint8_t es[32]{};
    if (!crypto::X25519(es, out_scratch.eph_priv, peer_static_pub)) return false;
    uint8_t key1[32]{};
    WgKdf2(out_scratch.chain_key, es, 32, out_scratch.chain_key, key1);

    static constexpr uint8_t kZeroNonce[12]{};
    crypto::ChaCha20Poly1305Encrypt(key1, kZeroNonce, out_scratch.hash, 32, local_static_pub, 32,
                                    out_msg + 40, out_msg + 72);
    WgMixHash(out_scratch.hash, out_msg + 40, 48);

    uint8_t ss[32]{};
    if (!crypto::X25519(ss, local_static_priv, peer_static_pub)) return false;
    uint8_t key2[32]{};
    WgKdf2(out_scratch.chain_key, ss, 32, out_scratch.chain_key, key2);

    crypto::ChaCha20Poly1305Encrypt(key2, kZeroNonce, out_scratch.hash, 32, tai64n, 12,
                                    out_msg + 88, out_msg + 100);
    WgMixHash(out_scratch.hash, out_msg + 88, 28);

    ComputeMac1(peer_static_pub, out_msg, 116, out_msg + 116);
    return true;
}

bool WgRespondHandshakeInitiation(const uint8_t responder_static_priv[32],
                                  const uint8_t expected_initiator_pub[32],
                                  const uint8_t psk[32],
                                  bool has_psk,
                                  uint32_t responder_index,
                                  const uint8_t msg[148],
                                  uint8_t out_resp[92],
                                  WgSessionState& out_session) noexcept {
    if (!msg || msg[0] != 1) return false;

    uint8_t responder_pub[32]{};
    crypto::X25519Base(responder_pub, responder_static_priv);
    uint8_t expected_mac1[16]{};
    ComputeMac1(responder_pub, msg, 116, expected_mac1);
    if (!crypto::ConstantTimeEqual(expected_mac1, msg + 116, 16)) return false;

    uint8_t ck[32]{}, h[32]{};
    WgInitNoisePreamble(responder_pub, ck, h);
    const uint32_t init_index = LoadLe32(msg + 4);
    const uint8_t* peer_eph = msg + 8;

    WgKdf1(ck, peer_eph, 32, ck);
    WgMixHash(h, peer_eph, 32);

    uint8_t es[32]{};
    if (!crypto::X25519(es, responder_static_priv, peer_eph)) return false;
    uint8_t key1[32]{};
    WgKdf2(ck, es, 32, ck, key1);

    static constexpr uint8_t kZeroNonce[12]{};
    uint8_t init_static[32]{};
    if (!crypto::ChaCha20Poly1305Decrypt(key1, kZeroNonce, h, 32, msg + 40, 32, msg + 72, init_static)) return false;
    if (expected_initiator_pub && !crypto::ConstantTimeEqual(init_static, expected_initiator_pub, 32)) return false;
    WgMixHash(h, msg + 40, 48);

    uint8_t ss[32]{};
    if (!crypto::X25519(ss, responder_static_priv, init_static)) return false;
    uint8_t key2[32]{};
    WgKdf2(ck, ss, 32, ck, key2);

    uint8_t ts[12]{};
    if (!crypto::ChaCha20Poly1305Decrypt(key2, kZeroNonce, h, 32, msg + 88, 12, msg + 100, ts)) return false;
    WgMixHash(h, msg + 88, 28);

    // Response construction
    uint8_t eph_priv[32]{};
    if (!crypto::RandomBytes(eph_priv, 32)) return false;
    uint8_t eph_pub[32]{};
    crypto::X25519Base(eph_pub, eph_priv);

    std::memset(out_resp, 0, 92);
    out_resp[0] = 2;
    StoreLe32(out_resp + 4, responder_index);
    StoreLe32(out_resp + 8, init_index);
    std::memcpy(out_resp + 12, eph_pub, 32);

    WgKdf1(ck, eph_pub, 32, ck);
    WgMixHash(h, eph_pub, 32);

    uint8_t ee[32]{};
    if (!crypto::X25519(ee, eph_priv, peer_eph)) return false;
    WgKdf1(ck, ee, 32, ck);

    uint8_t se[32]{};
    if (!crypto::X25519(se, eph_priv, init_static)) return false;
    WgKdf1(ck, se, 32, ck);

    uint8_t zero_psk[32]{};
    const uint8_t* effective_psk = (has_psk && psk) ? psk : zero_psk;
    uint8_t tau[32]{}, k3[32]{};
    WgKdf3(ck, effective_psk, 32, ck, tau, k3);
    WgMixHash(h, tau, 32);

    crypto::ChaCha20Poly1305Encrypt(k3, kZeroNonce, h, 32, nullptr, 0, nullptr, out_resp + 44);
    ComputeMac1(init_static, out_resp, 60, out_resp + 60);

    out_session = {};
    out_session.local_index = responder_index;
    out_session.peer_index = init_index;
    // Responder receives on t1, sends on t2 (inverse of initiator's send=t1, recv=t2).
    WgKdf2(ck, nullptr, 0, out_session.recv_key, out_session.send_key);
    out_session.established = true;
    return true;
}

bool WgProcessHandshakeResponse(const WgHandshakeScratch& scratch,
                                const uint8_t local_static_priv[32],
                                const uint8_t msg[92],
                                WgSessionState& out_session) noexcept {
    if (!msg || msg[0] != 2) return false;
    const uint32_t peer_index = LoadLe32(msg + 4);
    const uint32_t recv_index = LoadLe32(msg + 8);
    if (recv_index != scratch.local_index) return false;

    uint8_t ck[32], h[32];
    std::memcpy(ck, scratch.chain_key, 32);
    std::memcpy(h, scratch.hash, 32);

    const uint8_t* peer_eph = msg + 12;
    WgKdf1(ck, peer_eph, 32, ck);
    WgMixHash(h, peer_eph, 32);

    uint8_t ee[32]{};
    if (!crypto::X25519(ee, scratch.eph_priv, peer_eph)) return false;
    WgKdf1(ck, ee, 32, ck);

    uint8_t se[32]{};
    if (!crypto::X25519(se, local_static_priv, peer_eph)) return false;
    WgKdf1(ck, se, 32, ck);

    uint8_t zero_psk[32]{};
    const uint8_t* effective_psk = scratch.has_psk ? scratch.psk : zero_psk;
    uint8_t tau[32]{}, k3[32]{};
    WgKdf3(ck, effective_psk, 32, ck, tau, k3);
    WgMixHash(h, tau, 32);

    static constexpr uint8_t kZeroNonce[12]{};
    if (!crypto::ChaCha20Poly1305Decrypt(k3, kZeroNonce, h, 32, msg + 44, 0, msg + 44, nullptr)) return false;

    out_session = {};
    out_session.local_index = scratch.local_index;
    out_session.peer_index = peer_index;
    WgKdf2(ck, nullptr, 0, out_session.send_key, out_session.recv_key);
    out_session.established = true;
    return true;
}

std::vector<uint8_t> WgEncryptTransportPacket(WgSessionState& session,
                                              const uint8_t reserved[3],
                                              const uint8_t* ip_packet,
                                              size_t ip_len) noexcept {
    if (ip_len > 65535u || (ip_len > 0 && !ip_packet)) return {};
    // Pad payload to 16-byte multiple per WireGuard spec.
    const size_t padded_len = (ip_len + 15u) & ~size_t(15);
    std::vector<uint8_t> pt(padded_len, 0);
    if (ip_len > 0) std::memcpy(pt.data(), ip_packet, ip_len);

    std::vector<uint8_t> out(16u + padded_len + 16u, 0);
    out[0] = 4;
    if (reserved) std::memcpy(out.data() + 1, reserved, 3);
    StoreLe32(out.data() + 4, session.peer_index);
    const uint64_t ctr = session.send_counter++;
    StoreLe64(out.data() + 8, ctr);

    uint8_t nonce[12]{};
    StoreLe64(nonce + 4, ctr);
    crypto::ChaCha20Poly1305Encrypt(session.send_key, nonce, nullptr, 0, pt.data(), padded_len,
                                    out.data() + 16, out.data() + 16 + padded_len);
    return out;
}

bool WgDecryptTransportPacket(WgSessionState& session,
                              const uint8_t* pkt,
                              size_t pkt_len,
                              std::vector<uint8_t>& out_ip_packet) noexcept {
    out_ip_packet.clear();
    if (!session.established || !pkt || pkt_len < 32u || pkt[0] != 4) return false;
    if (LoadLe32(pkt + 4) != session.local_index) return false;
    const uint64_t ctr = LoadLe64(pkt + 8);
    if (ctr < session.max_recv_counter && (session.max_recv_counter - ctr) > 2048ULL) return false;

    const size_t ct_len = pkt_len - 32u;
    uint8_t nonce[12]{};
    StoreLe64(nonce + 4, ctr);
    out_ip_packet.resize(ct_len);
    if (!crypto::ChaCha20Poly1305Decrypt(session.recv_key, nonce, nullptr, 0, pkt + 16, ct_len, pkt + 16 + ct_len, out_ip_packet.data())) {
        out_ip_packet.clear();
        return false;
    }
    if (ctr > session.max_recv_counter) session.max_recv_counter = ctr;
    return true;
}

uint16_t IpChecksum16(const uint8_t* data, size_t len) noexcept {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (uint32_t(data[i]) << 8) | data[i + 1];
    }
    if (len & 1u) sum += uint32_t(data[len - 1]) << 8;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return static_cast<uint16_t>(~sum & 0xFFFFu);
}

uint16_t TcpChecksumIPv4(uint32_t src_ip_host, uint32_t dst_ip_host, const uint8_t* tcp_seg, size_t tcp_len) noexcept {
    uint32_t sum = 0;
    sum += (src_ip_host >> 16) & 0xFFFFu;
    sum += src_ip_host & 0xFFFFu;
    sum += (dst_ip_host >> 16) & 0xFFFFu;
    sum += dst_ip_host & 0xFFFFu;
    sum += 6u;  // IPPROTO_TCP
    sum += static_cast<uint32_t>(tcp_len);
    for (size_t i = 0; i + 1 < tcp_len; i += 2) {
        sum += (uint32_t(tcp_seg[i]) << 8) | tcp_seg[i + 1];
    }
    if (tcp_len & 1u) sum += uint32_t(tcp_seg[tcp_len - 1]) << 8;
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return static_cast<uint16_t>(~sum & 0xFFFFu);
}

bool WireGuardStream::SendTcpSegment(uint8_t flags, const uint8_t* payload, size_t len) noexcept {
    std::vector<uint8_t> pkt(40u + len, 0);
    // IPv4 Header (20B)
    pkt[0] = 0x45;
    StoreBe16(pkt.data() + 2, static_cast<uint16_t>(pkt.size()));
    StoreBe16(pkt.data() + 4, static_cast<uint16_t>(tcp_snd_nxt_ & 0xFFFFu));
    pkt[6] = 0x40;  // DF
    pkt[8] = 64;    // TTL
    pkt[9] = 6;     // TCP
    StoreBe32(pkt.data() + 12, local_ip_host_);
    StoreBe32(pkt.data() + 16, remote_ip_host_);
    StoreBe16(pkt.data() + 10, IpChecksum16(pkt.data(), 20));

    // TCP Header (20B)
    uint8_t* tcp = pkt.data() + 20;
    StoreBe16(tcp + 0, local_tcp_port_);
    StoreBe16(tcp + 2, remote_tcp_port_);
    StoreBe32(tcp + 4, tcp_snd_nxt_);
    StoreBe32(tcp + 8, tcp_rcv_nxt_);
    tcp[12] = 0x50;  // Data offset = 5 (20B)
    tcp[13] = flags;
    StoreBe16(tcp + 14, 65535);
    if (payload && len > 0) std::memcpy(tcp + 20, payload, len);
    StoreBe16(tcp + 16, TcpChecksumIPv4(local_ip_host_, remote_ip_host_, tcp, 20u + len));

    if (len > 0) tcp_snd_nxt_ += static_cast<uint32_t>(len);
    if (flags & 0x03u) ++tcp_snd_nxt_;  // SYN or FIN consumes 1 seq

    const uint8_t* res = node_.wireguard.has_reserved ? node_.wireguard.reserved : nullptr;
    const auto wire = WgEncryptTransportPacket(session_, res, pkt.data(), pkt.size());
    return udp_.UdpSendTo(server_ip_host_, server_port_, wire.data(), wire.size());
}

void WireGuardStream::HandleIncomingUdpPackets() noexcept {
    uint8_t buf[2048];
    for (int iter = 0; iter < 16; ++iter) {
        uint32_t from_ip = 0;
        uint16_t from_port = 0;
        const auto io = udp_.UdpRecvFrom(buf, sizeof(buf), from_ip, from_port);
        if (io.status != IoStatus::Ok || io.bytes < 32u) break;

        if (buf[0] != 4) continue;
        std::vector<uint8_t> ip;
        if (!WgDecryptTransportPacket(session_, buf, io.bytes, ip)) continue;
        if (ip.size() < 20u || (ip[0] >> 4) != 4 || ip[9] != 6) continue;
        const size_t ihl = (ip[0] & 0x0Fu) * 4u;
        const uint16_t tot_len = LoadBe16(ip.data() + 2);
        if (ihl < 20u || tot_len > ip.size() || tot_len < ihl + 20u) continue;

        const uint8_t* tcp = ip.data() + ihl;
        const size_t tcp_len = tot_len - ihl;
        const uint16_t sport = LoadBe16(tcp + 0);
        const uint16_t dport = LoadBe16(tcp + 2);
        if (sport != remote_tcp_port_ || dport != local_tcp_port_) continue;

        const uint32_t seq = LoadBe32(tcp + 4);
        const size_t doff = (tcp[12] >> 4) * 4u;
        const uint8_t flags = tcp[13];
        if (doff < 20u || doff > tcp_len) continue;
        const size_t data_len = tcp_len - doff;

        if ((flags & 0x12u) == 0x12u && !tcp_connected_) {  // SYN+ACK
            tcp_rcv_nxt_ = seq + 1u;
            tcp_connected_ = true;
            SendTcpSegment(0x10u /*ACK*/, nullptr, 0);
            continue;
        }
        if ((flags & 0x04u) != 0) {  // RST
            tcp_remote_fin_ = true;
            continue;
        }
        if (data_len > 0 && seq == tcp_rcv_nxt_) {
            app_rx_buf_.insert(app_rx_buf_.end(), tcp + doff, tcp + doff + data_len);
            tcp_rcv_nxt_ += static_cast<uint32_t>(data_len);
            SendTcpSegment(0x10u /*ACK*/, nullptr, 0);
        }
        if (flags & 0x01u) {  // FIN
            if (seq + data_len == tcp_rcv_nxt_) ++tcp_rcv_nxt_;
            tcp_remote_fin_ = true;
            SendTcpSegment(0x10u /*ACK*/, nullptr, 0);
        }
    }
}

bool WireGuardStream::Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms) noexcept {
    Close();

    auto priv_opt = crypto::Base64Decode(node_.wireguard.private_key);
    auto peer_opt = crypto::Base64Decode(node_.wireguard.peer_public_key);
    if (!priv_opt || priv_opt->size() != 32 || !peer_opt || peer_opt->size() != 32) return false;

    uint8_t psk[32]{};
    bool has_psk = false;
    if (!node_.wireguard.pre_shared_key.empty()) {
        auto psk_opt = crypto::Base64Decode(node_.wireguard.pre_shared_key);
        if (psk_opt && psk_opt->size() == 32) {
            std::memcpy(psk, psk_opt->data(), 32);
            has_psk = true;
        }
    }

    if (!node_.wireguard.local_addresses.empty()) {
        std::string_view cidr = node_.wireguard.local_addresses[0];
        const size_t slash = cidr.find('/');
        if (slash != std::string_view::npos) cidr = cidr.substr(0, slash);
        uint32_t ip_h = 0;
        if (ParseIPv4Be(cidr, ip_h) && ip_h != 0) local_ip_host_ = ip_h;
    }

    uint32_t srv_be = 0;
    if (!resolver.ResolveIPv4(node_.server, srv_be)) return false;
    server_ip_host_ = Swap32(srv_be);
    server_port_ = node_.port;

    uint32_t dst_be = 0;
    if (!resolver.ResolveIPv4(target.host, dst_be)) return false;
    remote_ip_host_ = Swap32(dst_be);
    remote_tcp_port_ = target.port;

    uint8_t rb[6]{};
    crypto::RandomBytes(rb, sizeof(rb));
    const uint32_t local_idx = 0x59550000u | (uint32_t(rb[0]) << 8) | rb[1];
    local_tcp_port_ = static_cast<uint16_t>(32768u + (((uint16_t(rb[2]) << 8) | rb[3]) % 28000u));
    tcp_snd_nxt_ = 0x12000000u | (uint32_t(rb[4]) << 8) | rb[5];
    tcp_rcv_nxt_ = 0;

    udp_ = NetSocket::CreateUdp(true);
    if (!udp_.IsValid()) return false;

    uint8_t tai64n[12]{};
    const uint64_t sec = 0x400000000000000AULL + (MonotonicMs() / 1000ULL + 1764000000ULL);
    for (int i = 0; i < 8; ++i) tai64n[i] = static_cast<uint8_t>((sec >> ((7 - i) * 8)) & 0xFFu);

    WgHandshakeScratch scratch{};
    uint8_t init_msg[148]{};
    const uint8_t* res = node_.wireguard.has_reserved ? node_.wireguard.reserved : nullptr;
    if (!WgBuildHandshakeInitiation(priv_opt->data(), peer_opt->data(), psk, has_psk, local_idx, res, tai64n, scratch, init_msg)) {
        Close();
        return false;
    }
    if (!udp_.UdpSendTo(server_ip_host_, server_port_, init_msg, sizeof(init_msg))) {
        Close();
        return false;
    }

    const uint64_t hs_deadline = MonotonicMs() + static_cast<uint64_t>(timeout_ms);
    while (!session_.established) {
        const uint64_t now = MonotonicMs();
        if (now >= hs_deadline) {
            Close();
            return false;
        }
        if (!WaitSingleSocket(udp_.Fd(), true, false, static_cast<int>(std::min<uint64_t>(hs_deadline - now, 250ULL)))) continue;
        uint8_t resp[256];
        uint32_t rip = 0;
        uint16_t rport = 0;
        const auto io = udp_.UdpRecvFrom(resp, sizeof(resp), rip, rport);
        if (io.status == IoStatus::Ok && io.bytes == 92u && resp[0] == 2) {
            if (WgProcessHandshakeResponse(scratch, priv_opt->data(), resp, session_)) break;
        }
    }

    // 3-way TCP handshake inside WireGuard tunnel
    if (!SendTcpSegment(0x02u /*SYN*/, nullptr, 0)) {
        Close();
        return false;
    }
    while (!tcp_connected_ && !tcp_remote_fin_) {
        const uint64_t now = MonotonicMs();
        if (now >= hs_deadline) {
            Close();
            return false;
        }
        WaitSingleSocket(udp_.Fd(), true, false, static_cast<int>(std::min<uint64_t>(hs_deadline - now, 120ULL)));
        HandleIncomingUdpPackets();
    }
    if (!tcp_connected_) {
        Close();
        return false;
    }
    return true;
}

IoResult WireGuardStream::WriteNonBlocking(const uint8_t* data, size_t len) noexcept {
    if (!session_.established || !tcp_connected_) return {IoStatus::Error, 0};
    if (len == 0) return {IoStatus::Ok, 0};
    const size_t mss = 1280u;  // Fits inside MTU 1408 cleanly
    const size_t chunk = std::min(len, mss);
    if (!SendTcpSegment(0x18u /*PSH|ACK*/, data, chunk)) return {IoStatus::WouldBlock, 0};
    return {IoStatus::Ok, chunk};
}

IoResult WireGuardStream::ReadNonBlocking(uint8_t* out, size_t cap) noexcept {
    if (!session_.established) return {IoStatus::Error, 0};
    HandleIncomingUdpPackets();
    if (app_rx_off_ < app_rx_buf_.size()) {
        const size_t n = std::min(cap, app_rx_buf_.size() - app_rx_off_);
        std::memcpy(out, app_rx_buf_.data() + app_rx_off_, n);
        app_rx_off_ += n;
        if (app_rx_off_ >= app_rx_buf_.size()) {
            app_rx_buf_.clear();
            app_rx_off_ = 0;
        }
        return {IoStatus::Ok, n};
    }
    if (tcp_remote_fin_) return {IoStatus::Eof, 0};
    return {IoStatus::WouldBlock, 0};
}

bool WireGuardStream::FlushPending() noexcept { return true; }
bool WireGuardStream::HasPendingWrite() const noexcept { return false; }

void WireGuardStream::Close() noexcept {
    if (session_.established && tcp_connected_ && !tcp_remote_fin_) {
        SendTcpSegment(0x11u /*FIN|ACK*/, nullptr, 0);
    }
    udp_.Close();
    session_ = {};
    tcp_connected_ = false;
    tcp_remote_fin_ = false;
    app_rx_buf_.clear();
    app_rx_off_ = 0;
}

}  // namespace yumi_nx::net
