#include "yumi_nx/shadowsocks_dialer.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

#include "yumi_nx/crypto.hpp"

namespace yumi_nx::net {

namespace {

inline uint32_t Swap32(uint32_t v) noexcept {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

inline void StoreNonceLe64(uint64_t ctr, uint8_t nonce[12]) noexcept {
    std::memset(nonce, 0, 12);
    for (int i = 0; i < 8; ++i) {
        nonce[i] = static_cast<uint8_t>((ctr >> (i * 8)) & 0xFFu);
    }
}

std::string ToLowerAscii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

bool IsChaCha(SsCipher c) noexcept {
    return c == SsCipher::ChaCha20Poly1305 || c == SsCipher::Ss2022ChaCha20Poly1305;
}

}  // namespace

std::vector<uint8_t> EncodeSocksTargetAddress(std::string_view host, uint16_t port) {
    std::vector<uint8_t> out;
    uint32_t ip_be = 0;
    if (ParseIPv4Be(host, ip_be)) {
        out.push_back(0x01);  // IPv4
        out.push_back(static_cast<uint8_t>((ip_be >> 24) & 0xFFu));
        out.push_back(static_cast<uint8_t>((ip_be >> 16) & 0xFFu));
        out.push_back(static_cast<uint8_t>((ip_be >> 8) & 0xFFu));
        out.push_back(static_cast<uint8_t>(ip_be & 0xFFu));
    } else {
        out.push_back(0x03);  // Domain
        const size_t dlen = std::min<size_t>(host.size(), 255u);
        out.push_back(static_cast<uint8_t>(dlen));
        out.insert(out.end(), host.begin(), host.begin() + static_cast<ptrdiff_t>(dlen));
    }
    out.push_back(static_cast<uint8_t>((port >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(port & 0xFFu));
    return out;
}

bool ParseSsCipher(std::string_view method, SsCipher& out_cipher, size_t& out_key_len, bool& out_is_2022) noexcept {
    const std::string m = ToLowerAscii(method);
    if (m == "aes-128-gcm") {
        out_cipher = SsCipher::Aes128Gcm; out_key_len = 16; out_is_2022 = false; return true;
    }
    if (m == "aes-256-gcm") {
        out_cipher = SsCipher::Aes256Gcm; out_key_len = 32; out_is_2022 = false; return true;
    }
    if (m == "chacha20-ietf-poly1305" || m == "chacha20-poly1305") {
        out_cipher = SsCipher::ChaCha20Poly1305; out_key_len = 32; out_is_2022 = false; return true;
    }
    if (m == "2022-blake3-aes-128-gcm") {
        out_cipher = SsCipher::Ss2022Aes128Gcm; out_key_len = 16; out_is_2022 = true; return true;
    }
    if (m == "2022-blake3-aes-256-gcm") {
        out_cipher = SsCipher::Ss2022Aes256Gcm; out_key_len = 32; out_is_2022 = true; return true;
    }
    if (m == "2022-blake3-chacha20-poly1305") {
        out_cipher = SsCipher::Ss2022ChaCha20Poly1305; out_key_len = 32; out_is_2022 = true; return true;
    }
    return false;
}

bool DeriveSsSubkey(SsCipher cipher, std::string_view password, const uint8_t* salt, size_t salt_len, uint8_t out_subkey[32]) noexcept {
    if (!salt || salt_len == 0 || !out_subkey) return false;
    std::memset(out_subkey, 0, 32);
    size_t key_len = 16;
    bool is_2022 = false;
    SsCipher dummy{};
    if (cipher == SsCipher::Aes128Gcm) { key_len = 16; is_2022 = false; }
    else if (cipher == SsCipher::Aes256Gcm || cipher == SsCipher::ChaCha20Poly1305) { key_len = 32; is_2022 = false; }
    else if (cipher == SsCipher::Ss2022Aes128Gcm) { key_len = 16; is_2022 = true; }
    else { key_len = 32; is_2022 = true; }
    (void)dummy;

    if (!is_2022) {
        uint8_t master[32]{};
        crypto::EvpBytesToKeyMd5(reinterpret_cast<const uint8_t*>(password.data()), password.size(), master, key_len);
        uint8_t prk[20]{};
        crypto::HkdfExtractSha1(salt, salt_len, master, key_len, prk);
        static constexpr uint8_t kInfo[9] = {'s', 's', '-', 's', 'u', 'b', 'k', 'e', 'y'};
        return crypto::HkdfExpandSha1(prk, kInfo, sizeof(kInfo), out_subkey, key_len);
    }

    // SIP022: password is base64 (take final key segment if colon-delimited iPSK:uPSK)
    const size_t colon = password.rfind(':');
    const std::string_view psk_b64 = (colon != std::string_view::npos) ? password.substr(colon + 1) : password;
    auto psk = crypto::Base64Decode(psk_b64);
    if (!psk || psk->size() < key_len) return false;

    std::vector<uint8_t> mat;
    mat.reserve(key_len + salt_len);
    mat.insert(mat.end(), psk->begin(), psk->begin() + static_cast<ptrdiff_t>(key_len));
    mat.insert(mat.end(), salt, salt + salt_len);
    crypto::Blake3::DeriveKey("shadowsocks 2022 session subkey", mat.data(), mat.size(), out_subkey, key_len);
    return true;
}

bool ShadowsocksStream::AeadSeal(const uint8_t key[32], uint64_t ctr,
                                 const uint8_t* pt, size_t pt_len, std::vector<uint8_t>& out_ct_tag) noexcept {
    uint8_t nonce[12];
    StoreNonceLe64(ctr, nonce);
    out_ct_tag.resize(pt_len + 16u);
    if (IsChaCha(cipher_)) {
        return crypto::ChaCha20Poly1305Encrypt(key, nonce, nullptr, 0, pt, pt_len, out_ct_tag.data(), out_ct_tag.data() + pt_len);
    }
    return crypto::AesGcmEncrypt(key, key_len_, nonce, nullptr, 0, pt, pt_len, out_ct_tag.data(), out_ct_tag.data() + pt_len);
}

bool ShadowsocksStream::AeadOpen(const uint8_t key[32], uint64_t ctr,
                                 const uint8_t* ct, size_t ct_len, const uint8_t tag[16], uint8_t* out_pt) noexcept {
    uint8_t nonce[12];
    StoreNonceLe64(ctr, nonce);
    if (IsChaCha(cipher_)) {
        return crypto::ChaCha20Poly1305Decrypt(key, nonce, nullptr, 0, ct, ct_len, tag, out_pt);
    }
    return crypto::AesGcmDecrypt(key, key_len_, nonce, nullptr, 0, ct, ct_len, tag, out_pt);
}

bool ShadowsocksStream::Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms) noexcept {
    Close();
    target_ = target;
    if (!ParseSsCipher(node_.method, cipher_, key_len_, is_2022_)) return false;
    if (!crypto::RandomBytes(tx_salt_, key_len_)) return false;
    if (!DeriveSsSubkey(cipher_, node_.password_or_key, tx_salt_, key_len_, tx_subkey_)) return false;

    uint32_t srv_be = 0;
    if (!resolver.ResolveIPv4(node_.server, srv_be)) return false;
    if (!sock_.ConnectExactBlocking(Swap32(srv_be), node_.port, timeout_ms)) return false;

    const auto addr = EncodeSocksTargetAddress(target_.host, target_.port);
    tx_buf_.insert(tx_buf_.end(), tx_salt_, tx_salt_ + key_len_);

    if (!is_2022_) {
        if (!AppendEncryptedChunk(addr.data(), addr.size())) {
            Close();
            return false;
        }
    } else {
        // SS-2022 TCP fixed request header: [type=0(1)] [timestamp(8 BE)] [var_hdr_len(2 BE)]
        std::vector<uint8_t> var_hdr = addr;
        var_hdr.push_back(0x00);
        var_hdr.push_back(0x00);  // pad_len = 0

        uint8_t fixed[11]{};
        fixed[0] = 0x00;  // client stream
        const uint64_t ts = 1700000000ULL + (MonotonicMs() / 1000ULL);
        for (int i = 0; i < 8; ++i) fixed[1 + i] = static_cast<uint8_t>((ts >> ((7 - i) * 8)) & 0xFFu);
        const uint16_t vlen = static_cast<uint16_t>(var_hdr.size());
        fixed[9] = static_cast<uint8_t>((vlen >> 8) & 0xFFu);
        fixed[10] = static_cast<uint8_t>(vlen & 0xFFu);

        std::vector<uint8_t> enc_fixed, enc_var;
        if (!AeadSeal(tx_subkey_, tx_nonce_ctr_++, fixed, sizeof(fixed), enc_fixed) ||
            !AeadSeal(tx_subkey_, tx_nonce_ctr_++, var_hdr.data(), var_hdr.size(), enc_var)) {
            Close();
            return false;
        }
        tx_buf_.insert(tx_buf_.end(), enc_fixed.begin(), enc_fixed.end());
        tx_buf_.insert(tx_buf_.end(), enc_var.begin(), enc_var.end());
    }

    if (!sock_.SendAllBlocking(tx_buf_.data(), tx_buf_.size(), timeout_ms)) {
        Close();
        return false;
    }
    tx_buf_.clear();
    tx_off_ = 0;
    header_sent_ = true;
    return true;
}

bool ShadowsocksStream::AppendEncryptedChunk(const uint8_t* pt, size_t pt_len) noexcept {
    if (pt_len == 0 || pt_len > 0x3FFFu) return false;
    const uint8_t len_be[2] = {
        static_cast<uint8_t>((pt_len >> 8) & 0xFFu),
        static_cast<uint8_t>(pt_len & 0xFFu),
    };
    std::vector<uint8_t> c1, c2;
    if (!AeadSeal(tx_subkey_, tx_nonce_ctr_++, len_be, 2, c1) ||
        !AeadSeal(tx_subkey_, tx_nonce_ctr_++, pt, pt_len, c2)) {
        return false;
    }
    tx_buf_.insert(tx_buf_.end(), c1.begin(), c1.end());
    tx_buf_.insert(tx_buf_.end(), c2.begin(), c2.end());
    return true;
}

bool ShadowsocksStream::FlushPending() noexcept {
    while (tx_off_ < tx_buf_.size()) {
        const auto io = sock_.SendSome(tx_buf_.data() + tx_off_, tx_buf_.size() - tx_off_);
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

IoResult ShadowsocksStream::WriteNonBlocking(const uint8_t* data, size_t len) noexcept {
    if (!sock_.IsValid() || !header_sent_) return {IoStatus::Error, 0};
    if (!FlushPending()) return {IoStatus::Error, 0};
    if (HasPendingWrite()) return {IoStatus::WouldBlock, 0};
    if (len == 0) return {IoStatus::Ok, 0};

    const size_t chunk = std::min<size_t>(len, 16000u);
    if (!AppendEncryptedChunk(data, chunk)) return {IoStatus::Error, 0};
    if (!FlushPending()) return {IoStatus::Error, 0};
    return {IoStatus::Ok, chunk};
}

bool ShadowsocksStream::ProcessIncoming() noexcept {
    if (!rx_salt_seen_) {
        if (rx_raw_.size() < key_len_) return true;
        if (!DeriveSsSubkey(cipher_, node_.password_or_key, rx_raw_.data(), key_len_, rx_subkey_)) return false;
        rx_raw_.erase(rx_raw_.begin(), rx_raw_.begin() + static_cast<ptrdiff_t>(key_len_));
        rx_nonce_ctr_ = 0;
        rx_salt_seen_ = true;
    }

    if (is_2022_ && !rx_2022_hdr_seen_) {
        // Response fixed header: [type=1(1)] [ts(8)] [req_salt(key_len)] [init_chunk_len(2)] + 16 tag
        const size_t pt_len = 1u + 8u + key_len_ + 2u;
        if (rx_raw_.size() < pt_len + 16u) return true;
        std::vector<uint8_t> pt(pt_len);
        if (!AeadOpen(rx_subkey_, rx_nonce_ctr_++, rx_raw_.data(), pt_len, rx_raw_.data() + pt_len, pt.data())) {
            return false;
        }
        if (pt[0] != 0x01 || !crypto::ConstantTimeEqual(pt.data() + 9, tx_salt_, key_len_)) return false;
        const uint16_t init_len = static_cast<uint16_t>((uint16_t(pt[9 + key_len_]) << 8) | pt[10 + key_len_]);
        rx_raw_.erase(rx_raw_.begin(), rx_raw_.begin() + static_cast<ptrdiff_t>(pt_len + 16u));
        rx_2022_hdr_seen_ = true;
        if (init_len > 0) {
            pending_chunk_len_ = init_len;
            rx_len_parsed_ = true;
        }
    }

    while (true) {
        if (!rx_len_parsed_) {
            if (rx_raw_.size() < 18u) break;
            uint8_t len_pt[2]{};
            if (!AeadOpen(rx_subkey_, rx_nonce_ctr_++, rx_raw_.data(), 2, rx_raw_.data() + 2, len_pt)) {
                return false;
            }
            const uint16_t clen = static_cast<uint16_t>((uint16_t(len_pt[0]) << 8) | len_pt[1]) & 0x3FFFu;
            rx_raw_.erase(rx_raw_.begin(), rx_raw_.begin() + 18);
            pending_chunk_len_ = clen;
            rx_len_parsed_ = true;
        }
        if (rx_raw_.size() < static_cast<size_t>(pending_chunk_len_) + 16u) break;
        const size_t base = pt_rx_.size();
        pt_rx_.resize(base + pending_chunk_len_);
        if (!AeadOpen(rx_subkey_, rx_nonce_ctr_++, rx_raw_.data(), pending_chunk_len_,
                      rx_raw_.data() + pending_chunk_len_, pt_rx_.data() + base)) {
            return false;
        }
        rx_raw_.erase(rx_raw_.begin(), rx_raw_.begin() + static_cast<ptrdiff_t>(pending_chunk_len_ + 16u));
        rx_len_parsed_ = false;
        pending_chunk_len_ = 0;
    }
    return true;
}

IoResult ShadowsocksStream::ReadNonBlocking(uint8_t* out, size_t cap) noexcept {
    if (!sock_.IsValid()) return {IoStatus::Error, 0};
    if (pt_off_ < pt_rx_.size()) {
        const size_t n = std::min(cap, pt_rx_.size() - pt_off_);
        std::memcpy(out, pt_rx_.data() + pt_off_, n);
        pt_off_ += n;
        if (pt_off_ >= pt_rx_.size()) { pt_rx_.clear(); pt_off_ = 0; }
        return {IoStatus::Ok, n};
    }
    if (remote_eof_) return {IoStatus::Eof, 0};

    uint8_t tmp[8192];
    const auto io = sock_.RecvSome(tmp, sizeof(tmp));
    if (io.status == IoStatus::Ok && io.bytes > 0) {
        rx_raw_.insert(rx_raw_.end(), tmp, tmp + io.bytes);
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

void ShadowsocksStream::Close() noexcept {
    sock_.Close();
    header_sent_ = false;
    rx_salt_seen_ = false;
    rx_2022_hdr_seen_ = false;
    rx_len_parsed_ = false;
    pending_chunk_len_ = 0;
    remote_eof_ = false;
    tx_nonce_ctr_ = 0;
    rx_nonce_ctr_ = 0;
    tx_buf_.clear();
    tx_off_ = 0;
    rx_raw_.clear();
    pt_rx_.clear();
    pt_off_ = 0;
}

}  // namespace yumi_nx::net
