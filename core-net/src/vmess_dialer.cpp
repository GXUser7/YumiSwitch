#include "yumi_nx/vmess_dialer.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace yumi_nx::net {

namespace {

// Recursive nested HMAC matching Go crypto/hmac + xray-core/proxy/vmess/aead/kdf.go
void VmessNestedHmac(const uint8_t* const* path,
                     const size_t* path_lens,
                     size_t depth,
                     const uint8_t* msg,
                     size_t msg_len,
                     uint8_t out[32]) noexcept {
    static constexpr uint8_t kRootKey[14] = {'V', 'M', 'e', 's', 's', ' ', 'A', 'E', 'A', 'D', ' ', 'K', 'D', 'F'};
    if (depth == 0) {
        crypto::HmacSha256(kRootKey, sizeof(kRootKey), msg, msg_len, out);
        return;
    }

    const uint8_t* key = path[depth - 1];
    const size_t klen = path_lens[depth - 1];
    uint8_t k0[64]{};
    if (klen > 64) {
        VmessNestedHmac(path, path_lens, depth - 1, key, klen, k0);
    } else if (key && klen > 0) {
        std::memcpy(k0, key, klen);
    }

    std::vector<uint8_t> inner_msg(64 + msg_len);
    for (int i = 0; i < 64; ++i) inner_msg[i] = k0[i] ^ 0x36u;
    if (msg && msg_len > 0) std::memcpy(inner_msg.data() + 64, msg, msg_len);

    uint8_t inner_dig[32]{};
    VmessNestedHmac(path, path_lens, depth - 1, inner_msg.data(), inner_msg.size(), inner_dig);

    uint8_t outer_msg[64 + 32]{};
    for (int i = 0; i < 64; ++i) outer_msg[i] = k0[i] ^ 0x5Cu;
    std::memcpy(outer_msg + 64, inner_dig, 32);
    VmessNestedHmac(path, path_lens, depth - 1, outer_msg, sizeof(outer_msg), out);
}

void Kdf1(const uint8_t* ikm, size_t ikm_len, const char* s0, uint8_t out[32]) noexcept {
    const uint8_t* p[1] = {reinterpret_cast<const uint8_t*>(s0)};
    const size_t l[1] = {std::strlen(s0)};
    VmessAeadKdf(ikm, ikm_len, p, l, 1, out);
}

void Kdf3(const uint8_t* ikm, size_t ikm_len, const char* s0,
          const uint8_t* s1, size_t s1_len,
          const uint8_t* s2, size_t s2_len,
          uint8_t out[32]) noexcept {
    const uint8_t* p[3] = {reinterpret_cast<const uint8_t*>(s0), s1, s2};
    const size_t l[3] = {std::strlen(s0), s1_len, s2_len};
    VmessAeadKdf(ikm, ikm_len, p, l, 3, out);
}

inline void StoreBe16(uint8_t* p, uint16_t v) noexcept { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v); }
inline void StoreBe32(uint8_t* p, uint32_t v) noexcept {
    p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v);
}
inline void StoreBe64(uint8_t* p, uint64_t v) noexcept {
    StoreBe32(p, uint32_t(v >> 32));
    StoreBe32(p + 4, uint32_t(v));
}

void MakeVmessBodyNonce(uint16_t cnt, const uint8_t body_iv[16], uint8_t out_nonce[12]) noexcept {
    out_nonce[0] = static_cast<uint8_t>((cnt >> 8) & 0xFFu);
    out_nonce[1] = static_cast<uint8_t>(cnt & 0xFFu);
    std::memcpy(out_nonce + 2, body_iv + 2, 10);
}

void DeriveChaChaPolyKey(const uint8_t key16[16], uint8_t out32[32]) noexcept {
    crypto::Md5::Digest(key16, 16, out32);
    crypto::Md5::Digest(out32, 16, out32 + 16);
}

uint16_t NextShakeMask(crypto::Shake128& sh) noexcept {
    uint8_t b[2]{};
    sh.Squeeze(b, 2);
    return static_cast<uint16_t>((uint16_t(b[0]) << 8) | b[1]);
}

uint8_t ParseVmessSecByte(std::string_view m) noexcept {
    std::string low;
    for (char c : m) low.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (low == "chacha20-poly1305") return 4;
    if (low == "none" || low == "zero") return 5;
    return 3;  // auto / aes-128-gcm default
}

}  // namespace

void DeriveVmessCmdKey(const uint8_t uuid[16], uint8_t out_cmd_key[16]) noexcept {
    static constexpr uint8_t kMagic[36] = {
        'c','4','8','6','1','9','f','e','-','8','f','0','2','-','4','9','e','0','-',
        'b','9','e','9','-','e','d','f','7','6','3','e','1','7','e','2','1'
    };
    uint8_t msg[16 + 36]{};
    std::memcpy(msg, uuid, 16);
    std::memcpy(msg + 16, kMagic, 36);
    crypto::Md5::Digest(msg, sizeof(msg), out_cmd_key);
}

void VmessAeadKdf(const uint8_t* key, size_t key_len,
                  const uint8_t* const* path, const size_t* path_lens,
                  size_t depth, uint8_t out[32]) noexcept {
    VmessNestedHmac(path, path_lens, depth, key, key_len, out);
}

std::vector<uint8_t> EncodeVmessAeadRequestHeader(const uint8_t cmd_key[16],
                                                  uint64_t timestamp_sec,
                                                  const uint8_t nonce8[8],
                                                  const uint8_t req_iv[16],
                                                  const uint8_t req_key[16],
                                                  uint8_t resp_auth_v,
                                                  uint8_t sec_type,
                                                  std::string_view host,
                                                  uint16_t port) noexcept {
    // 1. AuthID = AES-128-ECB(KDF(cmd_key, "AES Auth ID Encryption")[:16], ts8 || rand4 || crc32_ieee)
    uint8_t auth_aes_key[32]{};
    Kdf1(cmd_key, 16, "AES Auth ID Encryption", auth_aes_key);
    uint8_t auth_pt[16]{};
    StoreBe64(auth_pt, timestamp_sec);
    crypto::RandomBytes(auth_pt + 8, 4);
    StoreBe32(auth_pt + 12, crypto::Crc32Ieee(auth_pt, 12));
    uint8_t auth_id[16]{};
    crypto::AesEcbEncryptBlock(auth_aes_key, 16, auth_pt, auth_id);

    // 2. Plaintext VMess request header
    std::vector<uint8_t> hdr;
    hdr.reserve(80 + host.size());
    hdr.push_back(0x01);  // version 1
    hdr.insert(hdr.end(), req_iv, req_iv + 16);
    hdr.insert(hdr.end(), req_key, req_key + 16);
    hdr.push_back(resp_auth_v);
    hdr.push_back(0x01);  // Opt: standard format stream
    hdr.push_back(static_cast<uint8_t>(sec_type & 0x0Fu));  // P=0, Sec
    hdr.push_back(0x00);  // reserved
    hdr.push_back(0x01);  // Cmd: TCP
    hdr.push_back(static_cast<uint8_t>((port >> 8) & 0xFFu));
    hdr.push_back(static_cast<uint8_t>(port & 0xFFu));

    uint32_t ip_be = 0;
    if (ParseIPv4Be(host, ip_be)) {
        hdr.push_back(0x01);  // IPv4
        hdr.push_back(uint8_t(ip_be >> 24));
        hdr.push_back(uint8_t(ip_be >> 16));
        hdr.push_back(uint8_t(ip_be >> 8));
        hdr.push_back(uint8_t(ip_be));
    } else {
        hdr.push_back(0x02);  // Domain
        const size_t dlen = std::min<size_t>(host.size(), 255u);
        hdr.push_back(static_cast<uint8_t>(dlen));
        hdr.insert(hdr.end(), host.begin(), host.begin() + static_cast<ptrdiff_t>(dlen));
    }

    const uint32_t fnv = crypto::Fnv1a32(hdr.data(), hdr.size());
    const size_t fpos = hdr.size();
    hdr.resize(fpos + 4);
    StoreBe32(hdr.data() + fpos, fnv);

    // 3. Encrypt length (2B BE) + header payload
    uint8_t len_key[32]{}, len_iv[32]{}, hdr_key[32]{}, hdr_iv[32]{};
    Kdf3(cmd_key, 16, "VMess Header AEAD Key_Length", auth_id, 16, nonce8, 8, len_key);
    Kdf3(cmd_key, 16, "VMess Header AEAD Nonce_Length", auth_id, 16, nonce8, 8, len_iv);
    Kdf3(cmd_key, 16, "VMess Header AEAD Key", auth_id, 16, nonce8, 8, hdr_key);
    Kdf3(cmd_key, 16, "VMess Header AEAD Nonce", auth_id, 16, nonce8, 8, hdr_iv);

    uint8_t len_be[2];
    StoreBe16(len_be, static_cast<uint16_t>(hdr.size()));
    uint8_t len_ct[2]{}, len_tag[16]{};
    crypto::AesGcmEncrypt(len_key, 16, len_iv, auth_id, 16, len_be, 2, len_ct, len_tag);

    std::vector<uint8_t> hdr_ct(hdr.size());
    uint8_t hdr_tag[16]{};
    crypto::AesGcmEncrypt(hdr_key, 16, hdr_iv, auth_id, 16, hdr.data(), hdr.size(), hdr_ct.data(), hdr_tag);

    std::vector<uint8_t> out;
    out.reserve(16 + 18 + 8 + hdr_ct.size() + 16);
    out.insert(out.end(), auth_id, auth_id + 16);
    out.insert(out.end(), len_ct, len_ct + 2);
    out.insert(out.end(), len_tag, len_tag + 16);
    out.insert(out.end(), nonce8, nonce8 + 8);
    out.insert(out.end(), hdr_ct.begin(), hdr_ct.end());
    out.insert(out.end(), hdr_tag, hdr_tag + 16);
    return out;
}

bool VmessStream::Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms) noexcept {
    Close();
    uint8_t uuid[16]{};
    if (!crypto::ParseUuidBytes(node_.uuid_or_user, uuid)) return false;
    DeriveVmessCmdKey(uuid, cmd_key_);

    sec_type_ = ParseVmessSecByte(node_.method);
    uint8_t nonce8[8]{};
    if (!crypto::RandomBytes(req_key_, 16) || !crypto::RandomBytes(req_iv_, 16) ||
        !crypto::RandomBytes(nonce8, 8) || !crypto::RandomBytes(&resp_v_, 1)) {
        return false;
    }

    uint8_t rk_full[32]{}, ri_full[32]{};
    crypto::Sha256::Digest(req_key_, 16, rk_full);
    crypto::Sha256::Digest(req_iv_, 16, ri_full);
    std::memcpy(resp_key_, rk_full, 16);
    std::memcpy(resp_iv_, ri_full, 16);

    tx_mask_.Init();
    tx_mask_.Update(req_iv_, 16);
    tx_mask_.Final();

    rx_mask_.Init();
    rx_mask_.Update(resp_iv_, 16);
    rx_mask_.Final();

    if (!transport_.Connect(node_, settings_, resolver, timeout_ms, false)) return false;

    const uint64_t ts = 1700000000ULL + (MonotonicMs() / 1000ULL);
    const auto hdr = EncodeVmessAeadRequestHeader(
        cmd_key_, ts, nonce8, req_iv_, req_key_, resp_v_, sec_type_, target.host, target.port);
    if (!transport_.WriteBlocking(hdr.data(), hdr.size(), timeout_ms)) {
        Close();
        return false;
    }
    return true;
}

bool VmessStream::FlushPending() noexcept {
    if (!transport_.FlushPending()) return false;
    while (tx_off_ < tx_buf_.size()) {
        const auto io = transport_.WriteNonBlocking(tx_buf_.data() + tx_off_, tx_buf_.size() - tx_off_);
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
    return true;
}

IoResult VmessStream::WriteNonBlocking(const uint8_t* data, size_t len) noexcept {
    if (transport_.NativeFd() == kInvalidSocket) return {IoStatus::Error, 0};
    if (!FlushPending()) return {IoStatus::Error, 0};
    if (HasPendingWrite()) return {IoStatus::WouldBlock, 0};
    if (len == 0) return {IoStatus::Ok, 0};

    const size_t chunk = std::min<size_t>(len, 16000u);
    const uint16_t mask = NextShakeMask(tx_mask_);

    if (sec_type_ == 5) {  // none
        const uint16_t enc_len = static_cast<uint16_t>(chunk) ^ mask;
        uint8_t lbuf[2];
        StoreBe16(lbuf, enc_len);
        tx_buf_.insert(tx_buf_.end(), lbuf, lbuf + 2);
        tx_buf_.insert(tx_buf_.end(), data, data + chunk);
    } else {
        const uint16_t enc_len = static_cast<uint16_t>(chunk + 16u) ^ mask;
        uint8_t lbuf[2];
        StoreBe16(lbuf, enc_len);
        tx_buf_.insert(tx_buf_.end(), lbuf, lbuf + 2);

        uint8_t nonce[12]{};
        MakeVmessBodyNonce(tx_chunk_ctr_++, req_iv_, nonce);
        const size_t base = tx_buf_.size();
        tx_buf_.resize(base + chunk + 16u);
        if (sec_type_ == 4) {
            uint8_t ckey[32]{};
            DeriveChaChaPolyKey(req_key_, ckey);
            crypto::ChaCha20Poly1305Encrypt(ckey, nonce, nullptr, 0, data, chunk,
                                            tx_buf_.data() + base, tx_buf_.data() + base + chunk);
        } else {
            crypto::AesGcmEncrypt(req_key_, 16, nonce, nullptr, 0, data, chunk,
                                  tx_buf_.data() + base, tx_buf_.data() + base + chunk);
        }
    }
    if (!FlushPending()) return {IoStatus::Error, 0};
    return {IoStatus::Ok, chunk};
}

bool VmessStream::ProcessIncoming() noexcept {
    if (!resp_len_parsed_) {
        if (raw_rx_.size() < 18u) return true;
        uint8_t k[32]{}, iv[32]{};
        Kdf1(resp_key_, 16, "AEAD Resp Header Len Key", k);
        Kdf1(resp_iv_, 16, "AEAD Resp Header Len IV", iv);
        uint8_t len_pt[2]{};
        if (!crypto::AesGcmDecrypt(k, 16, iv, nullptr, 0, raw_rx_.data(), 2, raw_rx_.data() + 2, len_pt)) {
            return false;
        }
        resp_hdr_len_ = static_cast<uint16_t>((uint16_t(len_pt[0]) << 8) | len_pt[1]);
        raw_rx_.erase(raw_rx_.begin(), raw_rx_.begin() + 18);
        resp_len_parsed_ = true;
    }

    if (!resp_hdr_parsed_) {
        if (raw_rx_.size() < static_cast<size_t>(resp_hdr_len_) + 16u) return true;
        uint8_t k[32]{}, iv[32]{};
        Kdf1(resp_key_, 16, "AEAD Resp Header Key", k);
        Kdf1(resp_iv_, 16, "AEAD Resp Header IV", iv);
        std::vector<uint8_t> hpt(resp_hdr_len_);
        if (!crypto::AesGcmDecrypt(k, 16, iv, nullptr, 0, raw_rx_.data(), resp_hdr_len_,
                                   raw_rx_.data() + resp_hdr_len_, hpt.data())) {
            return false;
        }
        if (hpt.size() < 4u || hpt[0] != resp_v_) return false;
        raw_rx_.erase(raw_rx_.begin(), raw_rx_.begin() + static_cast<ptrdiff_t>(resp_hdr_len_ + 16u));
        resp_hdr_parsed_ = true;
    }

    while (true) {
        if (!chunk_len_parsed_) {
            if (raw_rx_.size() < 2u) break;
            const uint16_t wire_len = static_cast<uint16_t>((uint16_t(raw_rx_[0]) << 8) | raw_rx_[1]);
            pending_chunk_len_ = wire_len ^ NextShakeMask(rx_mask_);
            raw_rx_.erase(raw_rx_.begin(), raw_rx_.begin() + 2);
            chunk_len_parsed_ = true;
            if (pending_chunk_len_ == 0 || (sec_type_ != 5 && pending_chunk_len_ == 16u)) {
                // Zero-length EOF chunk
                if (sec_type_ != 5 && pending_chunk_len_ == 16u) {
                    if (raw_rx_.size() < 16u) return true;
                    raw_rx_.erase(raw_rx_.begin(), raw_rx_.begin() + 16);
                }
                remote_eof_ = true;
                chunk_len_parsed_ = false;
                break;
            }
        }
        if (raw_rx_.size() < pending_chunk_len_) break;
        if (sec_type_ == 5) {
            pt_rx_.insert(pt_rx_.end(), raw_rx_.begin(), raw_rx_.begin() + pending_chunk_len_);
        } else {
            if (pending_chunk_len_ < 16u) return false;
            const size_t pt_len = pending_chunk_len_ - 16u;
            uint8_t nonce[12]{};
            MakeVmessBodyNonce(rx_chunk_ctr_++, resp_iv_, nonce);
            const size_t base = pt_rx_.size();
            pt_rx_.resize(base + pt_len);
            bool ok = false;
            if (sec_type_ == 4) {
                uint8_t ckey[32]{};
                DeriveChaChaPolyKey(resp_key_, ckey);
                ok = crypto::ChaCha20Poly1305Decrypt(ckey, nonce, nullptr, 0, raw_rx_.data(), pt_len,
                                                     raw_rx_.data() + pt_len, pt_rx_.data() + base);
            } else {
                ok = crypto::AesGcmDecrypt(resp_key_, 16, nonce, nullptr, 0, raw_rx_.data(), pt_len,
                                           raw_rx_.data() + pt_len, pt_rx_.data() + base);
            }
            if (!ok) return false;
        }
        raw_rx_.erase(raw_rx_.begin(), raw_rx_.begin() + pending_chunk_len_);
        chunk_len_parsed_ = false;
        pending_chunk_len_ = 0;
    }
    return true;
}

IoResult VmessStream::ReadNonBlocking(uint8_t* out, size_t cap) noexcept {
    if (transport_.NativeFd() == kInvalidSocket) return {IoStatus::Error, 0};
    if (pt_off_ < pt_rx_.size()) {
        const size_t n = std::min(cap, pt_rx_.size() - pt_off_);
        std::memcpy(out, pt_rx_.data() + pt_off_, n);
        pt_off_ += n;
        if (pt_off_ >= pt_rx_.size()) { pt_rx_.clear(); pt_off_ = 0; }
        return {IoStatus::Ok, n};
    }
    if (remote_eof_) return {IoStatus::Eof, 0};

    uint8_t tmp[8192];
    const auto io = transport_.ReadNonBlocking(tmp, sizeof(tmp));
    if (io.status == IoStatus::Ok && io.bytes > 0) {
        raw_rx_.insert(raw_rx_.end(), tmp, tmp + io.bytes);
        if (!ProcessIncoming()) return {IoStatus::Error, 0};
    } else if (io.status == IoStatus::Eof) {
        remote_eof_ = true;
    } else if (io.status == IoStatus::Error) {
        return {IoStatus::Error, 0};
    }

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

bool VmessStream::HasPendingWrite() const noexcept {
    return (tx_off_ < tx_buf_.size()) || transport_.HasPendingWrite();
}

void VmessStream::Close() noexcept {
    transport_.Close();
    tx_chunk_ctr_ = 0;
    rx_chunk_ctr_ = 0;
    resp_len_parsed_ = false;
    resp_hdr_parsed_ = false;
    resp_hdr_len_ = 0;
    chunk_len_parsed_ = false;
    pending_chunk_len_ = 0;
    remote_eof_ = false;
    raw_rx_.clear();
    pt_rx_.clear();
    pt_off_ = 0;
    tx_buf_.clear();
    tx_off_ = 0;
}

}  // namespace yumi_nx::net
