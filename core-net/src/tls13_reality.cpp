#include "yumi_nx/tls13_reality.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

#include "yumi_nx/crypto.hpp"

#ifdef __SWITCH__
#include <switch.h>
#elif defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace yumi_nx::net {

namespace {

inline uint16_t ReadBe16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>((uint16_t(p[0]) << 8) | p[1]);
}
inline uint32_t ReadBe24(const uint8_t* p) noexcept {
    return (uint32_t(p[0]) << 16) | (uint32_t(p[1]) << 8) | p[2];
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

void BuildRecordNonce(const uint8_t iv[12], uint64_t seq, uint8_t out_nonce[12]) noexcept {
    std::memcpy(out_nonce, iv, 12);
    for (int i = 0; i < 8; ++i) {
        out_nonce[4 + i] ^= static_cast<uint8_t>((seq >> ((7 - i) * 8)) & 0xFFu);
    }
}

void HashTranscript(bool use_sha384, const std::vector<uint8_t>& tr, uint8_t* out, size_t& out_len) noexcept {
    if (use_sha384) {
        crypto::Sha512::Digest384(tr.data(), tr.size(), out);
        out_len = 48;
    } else {
        crypto::Sha256::Digest(tr.data(), tr.size(), out);
        out_len = 32;
    }
}

void HkdfExtractChoice(bool use_sha384, const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t* out) noexcept {
    if (use_sha384) crypto::HkdfExtractSha384(salt, salt_len, ikm, ikm_len, out);
    else crypto::HkdfExtractSha256(salt, salt_len, ikm, ikm_len, out);
}

void HmacChoice(bool use_sha384, const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t* out) noexcept {
    if (use_sha384) crypto::HmacSha384(key, key_len, data, data_len, out);
    else crypto::HmacSha256(key, key_len, data, data_len, out);
}

bool VerifyRealityTempCert(const uint8_t* cert_msg, size_t cert_len, const uint8_t auth_key[32]) noexcept {
    // Certificate handshake payload: context_len(1B), context, cert_list_len(3B), [cert_len(3B), cert_der, ext_len(2B)]
    if (!cert_msg || cert_len < 12) return false;
    size_t off = cert_msg[0] + 1u;
    if (off + 3u > cert_len) return false;
    const size_t list_len = ReadBe24(cert_msg + off);
    off += 3u;
    if (off + list_len > cert_len || list_len < 5u) return false;
    const size_t der_len = ReadBe24(cert_msg + off);
    off += 3u;
    if (off + der_len > cert_len || der_len < 96u) return false;
    const uint8_t* der = cert_msg + off;

    // REALITY temporary Ed25519 cert embeds Ed25519 OID 1.3.101.112 (06 03 2B 65 70) + 32-byte public key,
    // and trailing BIT STRING signatureValue contains HMAC-SHA512(auth_key, ed25519_pub).
    static constexpr uint8_t kEd25519Oid[5] = {0x06, 0x03, 0x2B, 0x65, 0x70};
    const uint8_t* pub32 = nullptr;
    for (size_t i = 0; i + 40 <= der_len; ++i) {
        if (std::memcmp(der + i, kEd25519Oid, 5) == 0) {
            // Expect BIT STRING tag 0x03, len 0x21 (33), unused bits 0x00, then 32-byte pubkey.
            for (size_t k = i + 5; k + 35 <= der_len && k < i + 12; ++k) {
                if (der[k] == 0x03 && der[k + 1] == 0x21 && der[k + 2] == 0x00) {
                    pub32 = der + k + 3;
                    break;
                }
            }
            if (pub32) break;
        }
    }
    if (!pub32 || der_len < 64u) return false;
    const uint8_t* sig64 = der + (der_len - 64u);
    uint8_t expected[64]{};
    crypto::HmacSha512(auth_key, 32, pub32, 32, expected);
    return crypto::ConstantTimeEqual(expected, sig64, 64);
}

void AppendGreaseExtension(std::vector<uint8_t>& exts, uint16_t grease_val) {
    AppendBe16(exts, grease_val);
    AppendBe16(exts, 0x0000);
}

uint16_t PickGrease(const uint8_t client_random[32], size_t offset) noexcept {
    static constexpr uint16_t kGrease[8] = {
        0x0A0Au, 0x1A1Au, 0x2A2Au, 0x3A3Au, 0x4A4Au, 0x5A5Au, 0x6A6Au, 0x7A7Au
    };
    return kGrease[client_random[offset % 32] & 7u];
}

void SleepMilliseconds(uint32_t ms) noexcept {
    if (ms == 0) return;
#ifdef __SWITCH__
    svcSleepThread(static_cast<u64>(ms) * 1'000'000ULL);
#elif defined(_WIN32)
    Sleep(ms);
#else
    usleep(ms * 1000u);
#endif
}

}  // namespace

bool ParseRangeMinMax(std::string_view range_str,
                      uint16_t def_min,
                      uint16_t def_max,
                      uint16_t& out_min,
                      uint16_t& out_max) noexcept {
    out_min = def_min;
    out_max = def_max;
    if (range_str.empty()) return false;
    const size_t dash = range_str.find('-');
    auto parse_u16 = [](std::string_view sv, uint16_t& val) -> bool {
        if (sv.empty() || sv.size() > 5) return false;
        uint32_t acc = 0;
        for (char c : sv) {
            if (c < '0' || c > '9') return false;
            acc = acc * 10u + static_cast<uint32_t>(c - '0');
        }
        if (acc > 65535u) return false;
        val = static_cast<uint16_t>(acc);
        return true;
    };
    if (dash == std::string_view::npos) {
        uint16_t v = 0;
        if (!parse_u16(range_str, v)) return false;
        out_min = v;
        out_max = v;
        return true;
    }
    uint16_t a = 0, b = 0;
    if (!parse_u16(range_str.substr(0, dash), a) || !parse_u16(range_str.substr(dash + 1), b)) return false;
    out_min = std::min(a, b);
    out_max = std::max(a, b);
    return true;
}

FragmentConfig MakeFragmentConfig(const AppSettings& settings) noexcept {
    FragmentConfig cfg;
    cfg.mode = settings.fragment_mode;
    cfg.scope = settings.fragment_scope;
    (void)ParseRangeMinMax(settings.fragment_length, 20, 50, cfg.min_len, cfg.max_len);
    (void)ParseRangeMinMax(settings.fragment_interval, 2, 5, cfg.min_interval_ms, cfg.max_interval_ms);
    if (cfg.min_len < 1) cfg.min_len = 1;
    if (cfg.max_len < cfg.min_len) cfg.max_len = cfg.min_len;
    if (!settings.fragment_max_chunks.empty()) {
        uint16_t dummy_min = 0, mx = 0;
        if (ParseRangeMinMax(settings.fragment_max_chunks, 0, 0, dummy_min, mx)) {
            cfg.max_chunks = mx;
        }
    }
    return cfg;
}

TlsFingerprint ResolveEffectiveFingerprint(TlsFingerprint global_override, std::string_view node_fp) noexcept {
    if (global_override != TlsFingerprint::Auto) return global_override;
    if (node_fp.empty()) return TlsFingerprint::Chrome;
    std::string lower;
    lower.reserve(node_fp.size());
    for (char c : node_fp) lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lower == "firefox") return TlsFingerprint::Firefox;
    if (lower == "safari") return TlsFingerprint::Safari;
    if (lower == "ios") return TlsFingerprint::Ios;
    if (lower == "android") return TlsFingerprint::Android;
    if (lower == "edge") return TlsFingerprint::Edge;
    if (lower == "qq") return TlsFingerprint::Qq;
    if (lower == "360" || lower == "browser360") return TlsFingerprint::Browser360;
    if (lower == "random") return TlsFingerprint::Random;
    if (lower == "randomized") return TlsFingerprint::Randomized;
    return TlsFingerprint::Chrome;
}

bool SendFragmentedBlocking(NetSocket& sock,
                            const uint8_t* data,
                            size_t len,
                            const FragmentConfig& cfg,
                            int timeout_ms) noexcept {
    if (!data || len == 0) return true;
    if (cfg.mode == FragmentMode::Off || cfg.min_len >= len) {
        return sock.SendAllBlocking(data, len, timeout_ms);
    }

    uint16_t min_len = std::max<uint16_t>(1, cfg.min_len);
    uint16_t max_len = std::max(min_len, cfg.max_len);
    size_t off = 0;
    uint16_t chunks = 0;
    uint8_t rbuf[4]{};

    while (off < len) {
        size_t chunk_sz = len - off;
        if (cfg.max_chunks == 0 || (chunks + 1u) < cfg.max_chunks) {
            uint16_t rnd = 0;
            if (crypto::RandomBytes(rbuf, 4)) {
                rnd = static_cast<uint16_t>((uint16_t(rbuf[0]) << 8) | rbuf[1]);
            }
            const uint32_t span = static_cast<uint32_t>(max_len - min_len) + 1u;
            chunk_sz = std::min<size_t>(chunk_sz, min_len + (rnd % span));
        }
        if (!sock.SendAllBlocking(data + off, chunk_sz, timeout_ms)) return false;
        off += chunk_sz;
        ++chunks;

        if (off < len && cfg.max_interval_ms > 0) {
            const uint16_t i_span = static_cast<uint16_t>(cfg.max_interval_ms - cfg.min_interval_ms) + 1u;
            const uint16_t irnd = static_cast<uint16_t>((uint16_t(rbuf[2]) << 8) | rbuf[3]);
            SleepMilliseconds(cfg.min_interval_ms + (irnd % i_span));
        }
    }
    return true;
}

bool ParseRealityShortId(std::string_view hex, uint8_t out_short_id[8]) noexcept {
    std::memset(out_short_id, 0, 8);
    if (hex.empty()) return true;
    auto dec = crypto::HexDecode(hex);
    if (!dec || dec->size() > 8) return false;
    std::memcpy(out_short_id, dec->data(), dec->size());
    return true;
}

bool BuildRealitySessionId(const uint8_t eph_priv[32],
                           const uint8_t server_pub[32],
                           const uint8_t client_random[32],
                           const uint8_t short_id[8],
                           uint32_t timestamp_sec,
                           const uint8_t* raw_client_hello_zero_sid,
                           size_t raw_ch_len,
                           uint8_t out_session_id[32],
                           uint8_t out_auth_key[32]) noexcept {
    uint8_t shared[32]{};
    if (!crypto::X25519(shared, eph_priv, server_pub)) return false;

    uint8_t prk[32]{};
    crypto::HkdfExtractSha256(client_random, 20, shared, 32, prk);
    static constexpr uint8_t kInfo[7] = {'R', 'E', 'A', 'L', 'I', 'T', 'Y'};
    if (!crypto::HkdfExpandSha256(prk, kInfo, sizeof(kInfo), out_auth_key, 32)) return false;

    uint8_t pt[16]{};
    pt[0] = 1;   // Version major 1
    pt[1] = 8;   // Version minor 8
    pt[2] = 24;  // Patch 24
    pt[3] = 0;
    pt[4] = static_cast<uint8_t>((timestamp_sec >> 24) & 0xFFu);
    pt[5] = static_cast<uint8_t>((timestamp_sec >> 16) & 0xFFu);
    pt[6] = static_cast<uint8_t>((timestamp_sec >> 8) & 0xFFu);
    pt[7] = static_cast<uint8_t>(timestamp_sec & 0xFFu);
    std::memcpy(pt + 8, short_id, 8);

    uint8_t ct[16]{};
    uint8_t tag[16]{};
    if (!crypto::AesGcmEncrypt(out_auth_key, 32, client_random + 20, raw_client_hello_zero_sid, raw_ch_len, pt, 16, ct, tag)) {
        return false;
    }
    std::memcpy(out_session_id, ct, 16);
    std::memcpy(out_session_id + 16, tag, 16);
    return true;
}

std::vector<uint8_t> BuildTls13ClientHello(std::string_view sni,
                                           const std::vector<std::string>& alpn,
                                           const uint8_t eph_priv[32],
                                           const uint8_t client_random[32],
                                           const RealityOptions* reality,
                                           uint32_t now_epoch_sec,
                                           uint8_t* out_auth_key_32,
                                           TlsFingerprint fingerprint,
                                           const std::vector<uint8_t>* extra_extensions) noexcept {
    uint8_t eph_pub[32]{};
    crypto::X25519Base(eph_pub, eph_priv);

    TlsFingerprint fp = fingerprint;
    if (fp == TlsFingerprint::Auto) fp = TlsFingerprint::Chrome;
    if (fp == TlsFingerprint::Random || fp == TlsFingerprint::Randomized) {
        static constexpr TlsFingerprint kPool[5] = {
            TlsFingerprint::Chrome, TlsFingerprint::Firefox, TlsFingerprint::Safari,
            TlsFingerprint::Edge, TlsFingerprint::Ios,
        };
        fp = kPool[client_random[0] % 5u];
    }

    const bool use_grease = (fp == TlsFingerprint::Chrome || fp == TlsFingerprint::Edge ||
                             fp == TlsFingerprint::Ios || fp == TlsFingerprint::Android);
    const uint16_t grease_cs = PickGrease(client_random, 1);
    const uint16_t grease_ext1 = PickGrease(client_random, 2);
    uint16_t grease_ext2 = PickGrease(client_random, 3);
    if (grease_ext2 == grease_ext1) grease_ext2 ^= 0x1010u;

    std::vector<uint8_t> exts;
    if (use_grease) AppendGreaseExtension(exts, grease_ext1);

    auto append_sni = [&]() {
        if (!sni.empty()) {
            std::vector<uint8_t> ext;
            const uint16_t name_len = static_cast<uint16_t>(sni.size());
            AppendBe16(ext, 0x0000);
            AppendBe16(ext, static_cast<uint16_t>(name_len + 5));
            AppendBe16(ext, static_cast<uint16_t>(name_len + 3));
            ext.push_back(0x00);
            AppendBe16(ext, name_len);
            ext.insert(ext.end(), sni.begin(), sni.end());
            exts.insert(exts.end(), ext.begin(), ext.end());
        }
    };
    auto append_alpn = [&]() {
        if (!alpn.empty()) {
            std::vector<uint8_t> alpn_list;
            for (const auto& proto : alpn) {
                if (!proto.empty() && proto.size() <= 255) {
                    alpn_list.push_back(static_cast<uint8_t>(proto.size()));
                    alpn_list.insert(alpn_list.end(), proto.begin(), proto.end());
                }
            }
            if (!alpn_list.empty()) {
                AppendBe16(exts, 0x0010);
                AppendBe16(exts, static_cast<uint16_t>(2 + alpn_list.size()));
                AppendBe16(exts, static_cast<uint16_t>(alpn_list.size()));
                exts.insert(exts.end(), alpn_list.begin(), alpn_list.end());
            }
        }
    };

    append_sni();
    AppendBe16(exts, 0x0017); AppendBe16(exts, 0x0000);  // extended_master_secret
    AppendBe16(exts, 0xFF01); AppendBe16(exts, 0x0001); exts.push_back(0x00);  // renegotiation_info

    if (fp == TlsFingerprint::Firefox) {
        // Firefox extension order puts supported_groups + alpn + key_share + supported_versions + sig_algs + record_size_limit
        AppendBe16(exts, 0x000A); AppendBe16(exts, 0x0008); AppendBe16(exts, 0x0006);
        AppendBe16(exts, 0x001D); AppendBe16(exts, 0x0017); AppendBe16(exts, 0x0018);
        append_alpn();
        AppendBe16(exts, 0x0033); AppendBe16(exts, 0x0026); AppendBe16(exts, 0x0024);
        AppendBe16(exts, 0x001D); AppendBe16(exts, 0x0020);
        exts.insert(exts.end(), eph_pub, eph_pub + 32);
        AppendBe16(exts, 0x002B); AppendBe16(exts, 0x0005); exts.push_back(0x04);
        AppendBe16(exts, 0x0304); AppendBe16(exts, 0x0303);
        static constexpr uint16_t kFfSig[] = {0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601};
        AppendBe16(exts, 0x000D);
        AppendBe16(exts, static_cast<uint16_t>(2 + sizeof(kFfSig)));
        AppendBe16(exts, static_cast<uint16_t>(sizeof(kFfSig)));
        for (uint16_t sa : kFfSig) AppendBe16(exts, sa);
        AppendBe16(exts, 0x002D); AppendBe16(exts, 0x0002); exts.push_back(0x01); exts.push_back(0x01);
        AppendBe16(exts, 0x001C); AppendBe16(exts, 0x0002); AppendBe16(exts, 0x4001);  // record_size_limit
    } else if (fp == TlsFingerprint::Safari || fp == TlsFingerprint::Ios) {
        AppendBe16(exts, 0x000A); AppendBe16(exts, 0x0008); AppendBe16(exts, 0x0006);
        AppendBe16(exts, 0x001D); AppendBe16(exts, 0x0017); AppendBe16(exts, 0x0018);
        append_alpn();
        static constexpr uint16_t kSafSig[] = {0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0806, 0x0601};
        AppendBe16(exts, 0x000D);
        AppendBe16(exts, static_cast<uint16_t>(2 + sizeof(kSafSig)));
        AppendBe16(exts, static_cast<uint16_t>(sizeof(kSafSig)));
        for (uint16_t sa : kSafSig) AppendBe16(exts, sa);
        AppendBe16(exts, 0x002D); AppendBe16(exts, 0x0002); exts.push_back(0x01); exts.push_back(0x01);
        AppendBe16(exts, 0x002B); AppendBe16(exts, 0x0005); exts.push_back(0x04);
        AppendBe16(exts, 0x0304); AppendBe16(exts, 0x0303);
        AppendBe16(exts, 0x0033); AppendBe16(exts, 0x0026); AppendBe16(exts, 0x0024);
        AppendBe16(exts, 0x001D); AppendBe16(exts, 0x0020);
        exts.insert(exts.end(), eph_pub, eph_pub + 32);
    } else {
        // Chrome / Edge / Android / QQ / 360 profile
        AppendBe16(exts, 0x000A); AppendBe16(exts, 0x0006); AppendBe16(exts, 0x0004);
        AppendBe16(exts, 0x001D); AppendBe16(exts, 0x0017);
        static constexpr uint16_t kSigAlgs[] = {0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0807, 0x0601};
        AppendBe16(exts, 0x000D);
        AppendBe16(exts, static_cast<uint16_t>(2 + sizeof(kSigAlgs)));
        AppendBe16(exts, static_cast<uint16_t>(sizeof(kSigAlgs)));
        for (uint16_t sa : kSigAlgs) AppendBe16(exts, sa);
        append_alpn();
        AppendBe16(exts, 0x002B); AppendBe16(exts, 0x0005); exts.push_back(0x04);
        AppendBe16(exts, 0x0304); AppendBe16(exts, 0x0303);
        AppendBe16(exts, 0x002D); AppendBe16(exts, 0x0002); exts.push_back(0x01); exts.push_back(0x01);
        AppendBe16(exts, 0x0033); AppendBe16(exts, 0x0026); AppendBe16(exts, 0x0024);
        AppendBe16(exts, 0x001D); AppendBe16(exts, 0x0020);
        exts.insert(exts.end(), eph_pub, eph_pub + 32);
        if (fp == TlsFingerprint::Edge || fp == TlsFingerprint::Qq) {
            AppendBe16(exts, 0x0012); AppendBe16(exts, 0x0000);  // signed_certificate_timestamp
        }
    }

    if (extra_extensions && !extra_extensions->empty()) {
        exts.insert(exts.end(), extra_extensions->begin(), extra_extensions->end());
    }
    if (use_grease) AppendGreaseExtension(exts, grease_ext2);

    std::vector<uint8_t> body;
    AppendBe16(body, 0x0303);  // legacy_version
    body.insert(body.end(), client_random, client_random + 32);
    body.push_back(32);        // session_id length
    const size_t sid_off = 4 + body.size();
    body.resize(body.size() + 32, 0);

    std::vector<uint16_t> suites;
    if (use_grease) suites.push_back(grease_cs);
    if (fp == TlsFingerprint::Firefox) {
        suites.insert(suites.end(), {0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8});
    } else if (fp == TlsFingerprint::Qq || fp == TlsFingerprint::Browser360) {
        suites.insert(suites.end(), {0x1302, 0x1301, 0x1303, 0xC02B, 0xC02F});
    } else {
        suites.insert(suites.end(), {0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8});
    }
    AppendBe16(body, static_cast<uint16_t>(suites.size() * 2u));
    for (uint16_t cs : suites) AppendBe16(body, cs);
    body.push_back(1);
    body.push_back(0);  // compression null
    AppendBe16(body, static_cast<uint16_t>(exts.size()));
    body.insert(body.end(), exts.begin(), exts.end());

    std::vector<uint8_t> hs;
    hs.push_back(0x01);  // HandshakeType: client_hello
    AppendBe24(hs, static_cast<uint32_t>(body.size()));
    hs.insert(hs.end(), body.begin(), body.end());

    if (reality && reality->enabled) {
        auto pub_opt = crypto::Base64Decode(reality->public_key);
        uint8_t short_id[8]{};
        if (pub_opt && pub_opt->size() == 32 && ParseRealityShortId(reality->short_id, short_id)) {
            uint8_t sid[32]{};
            uint8_t ak[32]{};
            if (BuildRealitySessionId(eph_priv, pub_opt->data(), client_random, short_id,
                                      now_epoch_sec, hs.data(), hs.size(), sid, ak)) {
                std::memcpy(hs.data() + sid_off, sid, 32);
                if (out_auth_key_32) std::memcpy(out_auth_key_32, ak, 32);
            }
        }
    } else {
        crypto::RandomBytes(hs.data() + sid_off, 32);
    }

    return hs;
}

void Tls13Client::DeriveTrafficKeys(bool use_sha384, size_t key_len, const uint8_t* secret, uint8_t key[32], uint8_t iv[12]) noexcept {
    std::memset(key, 0, 32);
    std::memset(iv, 0, 12);
    crypto::Tls13HkdfExpandLabel(use_sha384, secret, "key", nullptr, 0, key, key_len);
    crypto::Tls13HkdfExpandLabel(use_sha384, secret, "iv", nullptr, 0, iv, 12);
}

bool Tls13Client::EncryptRecord(uint8_t content_type, const uint8_t* payload, size_t len, std::vector<uint8_t>& out_record) noexcept {
    if (len > 16384u) return false;
    std::vector<uint8_t> inner(len + 1u);
    if (len > 0) std::memcpy(inner.data(), payload, len);
    inner[len] = content_type;

    const size_t ct_len = inner.size() + 16u;
    uint8_t hdr[5] = {0x17, 0x03, 0x03, static_cast<uint8_t>((ct_len >> 8) & 0xFFu), static_cast<uint8_t>(ct_len & 0xFFu)};
    uint8_t nonce[12];
    BuildRecordNonce(ks_.client_iv, ks_.client_seq++, nonce);

    out_record.resize(5u + ct_len);
    std::memcpy(out_record.data(), hdr, 5);
    uint8_t* ct_ptr = out_record.data() + 5u;
    uint8_t* tag_ptr = ct_ptr + inner.size();
    if (ks_.cipher_suite == 0x1303) {
        return crypto::ChaCha20Poly1305Encrypt(ks_.client_key, nonce, hdr, 5, inner.data(), inner.size(), ct_ptr, tag_ptr);
    }
    return crypto::AesGcmEncrypt(ks_.client_key, ks_.key_len, nonce, hdr, 5, inner.data(), inner.size(), ct_ptr, tag_ptr);
}

bool Tls13Client::DecryptRecord(const uint8_t* rec, size_t rec_len, uint8_t& out_content_type, std::vector<uint8_t>& out_pt) noexcept {
    if (!rec || rec_len < 5u + 17u) return false;
    const uint16_t body_len = ReadBe16(rec + 3);
    if (rec[0] != 0x17 || body_len + 5u != rec_len || body_len < 17u) return false;

    const uint8_t* ct_ptr = rec + 5u;
    const size_t pt_len = body_len - 16u;
    const uint8_t* tag_ptr = ct_ptr + pt_len;

    uint8_t nonce[12];
    BuildRecordNonce(ks_.server_iv, ks_.server_seq++, nonce);

    out_pt.resize(pt_len);
    bool ok = false;
    if (ks_.cipher_suite == 0x1303) {
        ok = crypto::ChaCha20Poly1305Decrypt(ks_.server_key, nonce, rec, 5, ct_ptr, pt_len, tag_ptr, out_pt.data());
    } else {
        ok = crypto::AesGcmDecrypt(ks_.server_key, ks_.key_len, nonce, rec, 5, ct_ptr, pt_len, tag_ptr, out_pt.data());
    }
    if (!ok) return false;

    while (!out_pt.empty() && out_pt.back() == 0) out_pt.pop_back();
    if (out_pt.empty()) return false;
    out_content_type = out_pt.back();
    out_pt.pop_back();
    return true;
}

bool Tls13Client::ReadRawRecordBlocking(NetSocket& sock, uint8_t& out_type, std::vector<uint8_t>& out_rec, int timeout_ms) noexcept {
    const uint64_t deadline = MonotonicMs() + static_cast<uint64_t>(timeout_ms);
    uint8_t hdr[5];
    size_t got = 0;
    while (got < 5) {
        const uint64_t now = MonotonicMs();
        if (now >= deadline) return false;
        const auto r = sock.RecvSomeBlocking(hdr + got, 5 - got, static_cast<int>(deadline - now));
        if (r.status != IoStatus::Ok || r.bytes == 0) return false;
        got += r.bytes;
    }
    const uint16_t body_len = ReadBe16(hdr + 3);
    if (body_len > 18432u) return false;
    out_type = hdr[0];
    out_rec.resize(5u + body_len);
    std::memcpy(out_rec.data(), hdr, 5);
    got = 0;
    while (got < body_len) {
        const uint64_t now = MonotonicMs();
        if (now >= deadline) return false;
        const auto r = sock.RecvSomeBlocking(out_rec.data() + 5 + got, body_len - got, static_cast<int>(deadline - now));
        if (r.status != IoStatus::Ok || r.bytes == 0) return false;
        got += r.bytes;
    }
    return true;
}

bool Tls13Client::Handshake(NetSocket& sock,
                            std::string_view sni,
                            const std::vector<std::string>& alpn,
                            const RealityOptions* reality,
                            uint32_t now_epoch_sec,
                            int timeout_ms,
                            TlsFingerprint fingerprint,
                            const FragmentConfig* fragment) noexcept {
    established_ = false;
    direct_copy_ = false;
    peer_closed_ = false;
    ks_ = {};
    ct_read_buf_.clear();
    pt_buf_.clear();
    pt_off_ = 0;
    ct_write_buf_.clear();
    ct_write_off_ = 0;

    uint8_t eph_priv[32]{};
    uint8_t client_random[32]{};
    if (!crypto::RandomBytes(eph_priv, 32) || !crypto::RandomBytes(client_random, 32)) return false;

    uint8_t auth_key[32]{};
    if (now_epoch_sec == 0) now_epoch_sec = static_cast<uint32_t>(MonotonicMs() / 1000ULL);
    const auto ch = BuildTls13ClientHello(sni, alpn, eph_priv, client_random, reality, now_epoch_sec, auth_key, fingerprint);

    std::vector<uint8_t> ch_rec;
    ch_rec.reserve(5 + ch.size());
    ch_rec.push_back(0x16);
    ch_rec.push_back(0x03);
    ch_rec.push_back(0x01);
    AppendBe16(ch_rec, static_cast<uint16_t>(ch.size()));
    ch_rec.insert(ch_rec.end(), ch.begin(), ch.end());
    const bool use_frag = fragment && fragment->mode != FragmentMode::Off &&
        (!(reality && reality->enabled) || fragment->scope != FragmentScope::TlsOnly);
    const bool sent_ok = use_frag
        ? SendFragmentedBlocking(sock, ch_rec.data(), ch_rec.size(), *fragment, timeout_ms)
        : sock.SendAllBlocking(ch_rec.data(), ch_rec.size(), timeout_ms);
    if (!sent_ok) return false;

    std::vector<uint8_t> transcript = ch;

    // Wait for ServerHello
    uint8_t rec_type = 0;
    std::vector<uint8_t> rec;
    uint16_t suite = 0;
    uint8_t server_pub[32]{};
    bool got_server_pub = false;
    bool got_tls13 = false;

    for (int tries = 0; tries < 6; ++tries) {
        if (!ReadRawRecordBlocking(sock, rec_type, rec, timeout_ms)) return false;
        if (rec_type == 0x14) continue;  // ChangeCipherSpec
        if (rec_type != 0x16 || rec.size() < 9 || rec[5] != 0x02) return false;  // Expect ServerHello (0x02)
        const uint32_t msg_len = ReadBe24(rec.data() + 6);
        if (9u + msg_len > rec.size() || msg_len < 38u) return false;
        const uint8_t* sh = rec.data() + 9u;
        transcript.insert(transcript.end(), rec.data() + 5u, rec.data() + 9u + msg_len);

        const uint8_t sid_len = sh[34];
        size_t pos = 35u + sid_len;
        if (pos + 5u > msg_len) return false;
        suite = ReadBe16(sh + pos);
        pos += 3u;  // skip suite + compression
        const uint16_t ext_total = ReadBe16(sh + pos);
        pos += 2u;
        if (pos + ext_total > msg_len) return false;

        const size_t ext_end = pos + ext_total;
        while (pos + 4u <= ext_end) {
            const uint16_t eid = ReadBe16(sh + pos);
            const uint16_t elen = ReadBe16(sh + pos + 2);
            pos += 4u;
            if (pos + elen > ext_end) return false;
            if (eid == 0x002B && elen >= 2) {
                if (ReadBe16(sh + pos) == 0x0304) got_tls13 = true;
            } else if (eid == 0x0033 && elen >= 36) {
                const uint16_t grp = ReadBe16(sh + pos);
                const uint16_t klen = ReadBe16(sh + pos + 2);
                if (grp == 0x001D && klen == 32 && pos + 4 + 32 <= ext_end) {
                    std::memcpy(server_pub, sh + pos + 4, 32);
                    got_server_pub = true;
                }
            }
            pos += elen;
        }
        break;
    }

    if (!got_tls13 || !got_server_pub) return false;
    if (suite != 0x1301 && suite != 0x1302 && suite != 0x1303) return false;

    ks_.cipher_suite = suite;
    ks_.use_sha384 = (suite == 0x1302);
    ks_.hash_len = ks_.use_sha384 ? 48u : 32u;
    ks_.key_len = (suite == 0x1301) ? 16u : 32u;

    uint8_t shared[32]{};
    if (!crypto::X25519(shared, eph_priv, server_pub)) return false;

    uint8_t zeros[48]{};
    uint8_t early_secret[48]{};
    HkdfExtractChoice(ks_.use_sha384, zeros, ks_.hash_len, zeros, ks_.hash_len, early_secret);

    uint8_t empty_hash[48]{};
    size_t eh_len = 0;
    HashTranscript(ks_.use_sha384, {}, empty_hash, eh_len);

    uint8_t derived[48]{};
    crypto::Tls13HkdfExpandLabel(ks_.use_sha384, early_secret, "derived", empty_hash, ks_.hash_len, derived, ks_.hash_len);

    uint8_t hs_secret[48]{};
    HkdfExtractChoice(ks_.use_sha384, derived, ks_.hash_len, shared, 32, hs_secret);

    uint8_t ch_sh_hash[48]{};
    size_t hlen = 0;
    HashTranscript(ks_.use_sha384, transcript, ch_sh_hash, hlen);

    uint8_t c_hs_traffic[48]{}, s_hs_traffic[48]{};
    crypto::Tls13HkdfExpandLabel(ks_.use_sha384, hs_secret, "c hs traffic", ch_sh_hash, ks_.hash_len, c_hs_traffic, ks_.hash_len);
    crypto::Tls13HkdfExpandLabel(ks_.use_sha384, hs_secret, "s hs traffic", ch_sh_hash, ks_.hash_len, s_hs_traffic, ks_.hash_len);

    DeriveTrafficKeys(ks_.use_sha384, ks_.key_len, c_hs_traffic, ks_.client_key, ks_.client_iv);
    DeriveTrafficKeys(ks_.use_sha384, ks_.key_len, s_hs_traffic, ks_.server_key, ks_.server_iv);

    // Receive EncryptedExtensions, Certificate, CertificateVerify, Finished
    std::vector<uint8_t> hs_stream;
    bool got_cert = false;
    bool reality_verified = !(reality && reality->enabled);
    bool got_server_finished = false;

    while (!got_server_finished) {
        if (!ReadRawRecordBlocking(sock, rec_type, rec, timeout_ms)) return false;
        if (rec_type == 0x14) continue;
        if (rec_type != 0x17) return false;

        uint8_t inner_type = 0;
        std::vector<uint8_t> inner_pt;
        if (!DecryptRecord(rec.data(), rec.size(), inner_type, inner_pt)) return false;
        if (inner_type == 0x15) return false;  // Alert
        if (inner_type != 0x16) continue;
        hs_stream.insert(hs_stream.end(), inner_pt.begin(), inner_pt.end());

        while (hs_stream.size() >= 4u) {
            const uint8_t ht = hs_stream[0];
            const uint32_t mlen = ReadBe24(hs_stream.data() + 1);
            if (hs_stream.size() < 4u + mlen) break;

            if (ht == 0x0B) {  // Certificate
                got_cert = true;
                if (reality && reality->enabled) {
                    reality_verified = VerifyRealityTempCert(hs_stream.data() + 4, mlen, auth_key);
                }
            } else if (ht == 0x14) {  // Server Finished
                uint8_t pre_fin_hash[48]{};
                size_t phlen = 0;
                HashTranscript(ks_.use_sha384, transcript, pre_fin_hash, phlen);

                uint8_t s_fin_key[48]{};
                crypto::Tls13HkdfExpandLabel(ks_.use_sha384, s_hs_traffic, "finished", nullptr, 0, s_fin_key, ks_.hash_len);
                uint8_t expected_fin[48]{};
                HmacChoice(ks_.use_sha384, s_fin_key, ks_.hash_len, pre_fin_hash, ks_.hash_len, expected_fin);
                if (mlen != ks_.hash_len || !crypto::ConstantTimeEqual(expected_fin, hs_stream.data() + 4, ks_.hash_len)) {
                    return false;
                }
                got_server_finished = true;
            }

            transcript.insert(transcript.end(), hs_stream.begin(), hs_stream.begin() + static_cast<ptrdiff_t>(4u + mlen));
            hs_stream.erase(hs_stream.begin(), hs_stream.begin() + static_cast<ptrdiff_t>(4u + mlen));
            if (got_server_finished) break;
        }
    }

    if (!got_cert || !reality_verified) return false;

    // Master Secret & Application Keys before Client Finished
    uint8_t tr_sf_hash[48]{};
    HashTranscript(ks_.use_sha384, transcript, tr_sf_hash, hlen);

    uint8_t c_fin_key[48]{};
    crypto::Tls13HkdfExpandLabel(ks_.use_sha384, c_hs_traffic, "finished", nullptr, 0, c_fin_key, ks_.hash_len);
    uint8_t c_verify[48]{};
    HmacChoice(ks_.use_sha384, c_fin_key, ks_.hash_len, tr_sf_hash, ks_.hash_len, c_verify);

    std::vector<uint8_t> c_fin;
    c_fin.push_back(0x14);
    AppendBe24(c_fin, static_cast<uint32_t>(ks_.hash_len));
    c_fin.insert(c_fin.end(), c_verify, c_verify + ks_.hash_len);

    std::vector<uint8_t> fin_rec;
    if (!EncryptRecord(0x16, c_fin.data(), c_fin.size(), fin_rec)) return false;

    // Send ChangeCipherSpec + Encrypted Client Finished
    static constexpr uint8_t kCcs[6] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
    std::vector<uint8_t> wire;
    wire.reserve(6 + fin_rec.size());
    wire.insert(wire.end(), kCcs, kCcs + 6);
    wire.insert(wire.end(), fin_rec.begin(), fin_rec.end());
    if (!sock.SendAllBlocking(wire.data(), wire.size(), timeout_ms)) return false;

    uint8_t derived2[48]{};
    crypto::Tls13HkdfExpandLabel(ks_.use_sha384, hs_secret, "derived", empty_hash, ks_.hash_len, derived2, ks_.hash_len);
    uint8_t master_secret[48]{};
    HkdfExtractChoice(ks_.use_sha384, derived2, ks_.hash_len, zeros, ks_.hash_len, master_secret);

    uint8_t c_ap_traffic[48]{}, s_ap_traffic[48]{};
    crypto::Tls13HkdfExpandLabel(ks_.use_sha384, master_secret, "c ap traffic", tr_sf_hash, ks_.hash_len, c_ap_traffic, ks_.hash_len);
    crypto::Tls13HkdfExpandLabel(ks_.use_sha384, master_secret, "s ap traffic", tr_sf_hash, ks_.hash_len, s_ap_traffic, ks_.hash_len);

    DeriveTrafficKeys(ks_.use_sha384, ks_.key_len, c_ap_traffic, ks_.client_key, ks_.client_iv);
    DeriveTrafficKeys(ks_.use_sha384, ks_.key_len, s_ap_traffic, ks_.server_key, ks_.server_iv);
    ks_.client_seq = 0;
    ks_.server_seq = 0;
    established_ = true;
    return true;
}

bool Tls13Client::FlushPendingWrite(NetSocket& sock) noexcept {
    while (ct_write_off_ < ct_write_buf_.size()) {
        const auto io = sock.SendSome(ct_write_buf_.data() + ct_write_off_, ct_write_buf_.size() - ct_write_off_);
        if (io.status == IoStatus::Ok && io.bytes > 0) {
            ct_write_off_ += io.bytes;
        } else if (io.status == IoStatus::WouldBlock) {
            return true;
        } else {
            return false;
        }
    }
    ct_write_buf_.clear();
    ct_write_off_ = 0;
    return true;
}

IoResult Tls13Client::WriteNonBlocking(NetSocket& sock, const uint8_t* data, size_t len) noexcept {
    if (!established_) return {IoStatus::Error, 0};
    if (!FlushPendingWrite(sock)) return {IoStatus::Error, 0};
    if (HasPendingCipherWrite()) return {IoStatus::WouldBlock, 0};
    if (len == 0) return {IoStatus::Ok, 0};

    if (direct_copy_) {
        return sock.SendSome(data, len);
    }

    const size_t chunk = std::min<size_t>(len, 16384u);
    std::vector<uint8_t> rec;
    if (!EncryptRecord(0x17, data, chunk, rec)) return {IoStatus::Error, 0};
    ct_write_buf_ = std::move(rec);
    ct_write_off_ = 0;
    if (!FlushPendingWrite(sock)) return {IoStatus::Error, 0};
    return {IoStatus::Ok, chunk};
}

bool Tls13Client::PullAndDecryptNonBlocking(NetSocket& sock, bool& out_eof, bool& out_would_block) noexcept {
    out_eof = false;
    out_would_block = false;
    uint8_t tmp[8192];
    const auto io = sock.RecvSome(tmp, sizeof(tmp));
    if (io.status == IoStatus::Ok && io.bytes > 0) {
        if (direct_copy_) {
            pt_buf_.insert(pt_buf_.end(), tmp, tmp + io.bytes);
            return true;
        }
        ct_read_buf_.insert(ct_read_buf_.end(), tmp, tmp + io.bytes);
    } else if (io.status == IoStatus::Eof) {
        out_eof = true;
        peer_closed_ = true;
    } else if (io.status == IoStatus::WouldBlock) {
        out_would_block = true;
    } else {
        return false;
    }

    if (direct_copy_) return true;

    while (ct_read_buf_.size() >= 5u) {
        const uint16_t body_len = ReadBe16(ct_read_buf_.data() + 3);
        if (body_len > 18432u) return false;
        const size_t rec_len = 5u + body_len;
        if (ct_read_buf_.size() < rec_len) break;

        if (ct_read_buf_[0] == 0x14) {
            ct_read_buf_.erase(ct_read_buf_.begin(), ct_read_buf_.begin() + static_cast<ptrdiff_t>(rec_len));
            continue;
        }
        uint8_t inner_type = 0;
        std::vector<uint8_t> pt;
        if (!DecryptRecord(ct_read_buf_.data(), rec_len, inner_type, pt)) return false;
        ct_read_buf_.erase(ct_read_buf_.begin(), ct_read_buf_.begin() + static_cast<ptrdiff_t>(rec_len));

        if (inner_type == 0x17) {
            pt_buf_.insert(pt_buf_.end(), pt.begin(), pt.end());
        } else if (inner_type == 0x15) {
            // close_notify or alert
            peer_closed_ = true;
            out_eof = true;
        }
        // NewSessionTicket (0x16) ignored gracefully.
    }
    return true;
}

IoResult Tls13Client::ReadNonBlocking(NetSocket& sock, uint8_t* out, size_t cap) noexcept {
    if (!established_) return {IoStatus::Error, 0};
    if (pt_off_ < pt_buf_.size()) {
        const size_t avail = pt_buf_.size() - pt_off_;
        const size_t n = std::min(cap, avail);
        std::memcpy(out, pt_buf_.data() + pt_off_, n);
        pt_off_ += n;
        if (pt_off_ >= pt_buf_.size()) {
            pt_buf_.clear();
            pt_off_ = 0;
        }
        return {IoStatus::Ok, n};
    }
    if (peer_closed_) return {IoStatus::Eof, 0};

    bool eof = false, wb = false;
    if (!PullAndDecryptNonBlocking(sock, eof, wb)) return {IoStatus::Error, 0};
    if (pt_off_ < pt_buf_.size()) {
        const size_t avail = pt_buf_.size() - pt_off_;
        const size_t n = std::min(cap, avail);
        std::memcpy(out, pt_buf_.data() + pt_off_, n);
        pt_off_ += n;
        if (pt_off_ >= pt_buf_.size()) {
            pt_buf_.clear();
            pt_off_ = 0;
        }
        return {IoStatus::Ok, n};
    }
    if (eof) return {IoStatus::Eof, 0};
    return {IoStatus::WouldBlock, 0};
}

bool Tls13Client::WriteBlocking(NetSocket& sock, const uint8_t* data, size_t len, int timeout_ms) noexcept {
    const uint64_t deadline = MonotonicMs() + static_cast<uint64_t>(std::max(1, timeout_ms));
    size_t off = 0;
    while (off < len || HasPendingCipherWrite()) {
        const auto res = WriteNonBlocking(sock, data + off, len - off);
        if (res.status == IoStatus::Ok) {
            off += res.bytes;
            if (!HasPendingCipherWrite() && off >= len) return true;
        } else if (res.status != IoStatus::WouldBlock) {
            return false;
        }
        const uint64_t now = MonotonicMs();
        if (now >= deadline) return false;
        WaitSingleSocket(sock.Fd(), false, true, static_cast<int>(std::min<uint64_t>(deadline - now, 250ULL)));
    }
    return true;
}

IoResult Tls13Client::ReadBlocking(NetSocket& sock, uint8_t* out, size_t cap, int timeout_ms) noexcept {
    const uint64_t deadline = MonotonicMs() + static_cast<uint64_t>(std::max(1, timeout_ms));
    while (true) {
        const auto res = ReadNonBlocking(sock, out, cap);
        if (res.status != IoStatus::WouldBlock) return res;
        const uint64_t now = MonotonicMs();
        if (now >= deadline) return {IoStatus::WouldBlock, 0};
        WaitSingleSocket(sock.Fd(), true, false, static_cast<int>(std::min<uint64_t>(deadline - now, 250ULL)));
    }
}

void Tls13Client::SendCloseNotify(NetSocket& sock) noexcept {
    if (!established_ || direct_copy_ || !sock.IsValid()) return;
    static constexpr uint8_t kCloseNotify[2] = {0x01, 0x00};
    std::vector<uint8_t> rec;
    if (EncryptRecord(0x15, kCloseNotify, 2, rec)) {
        sock.SendSome(rec.data(), rec.size());
    }
}

// ---------------- QUIC TLS 1.3 Driver (Hysteria2) ----------------

bool Tls13QuicDriver::Start(std::string_view sni,
                            const std::vector<std::string>& alpn,
                            const std::vector<uint8_t>& quic_transport_params_ext,
                            TlsFingerprint fp,
                            std::vector<uint8_t>& out_client_hello) noexcept {
    init_buf_.clear();
    hs_buf_.clear();
    transcript_.clear();
    peer_tp_.clear();
    secrets_ = {};
    has_hs_ = false;
    complete_ = false;
    std::memset(hs_secret_, 0, sizeof(hs_secret_));
    std::memset(empty_hash_, 0, sizeof(empty_hash_));

    if (!crypto::RandomBytes(eph_priv_, 32) || !crypto::RandomBytes(client_random_, 32)) return false;
    out_client_hello = BuildTls13ClientHello(
        sni, alpn, eph_priv_, client_random_, nullptr, 0, nullptr, fp, &quic_transport_params_ext);
    if (out_client_hello.size() < 75u) return false;
    out_client_hello[38] = 0;
    out_client_hello.erase(out_client_hello.begin() + 39, out_client_hello.begin() + 71);
    const uint32_t new_hs_len = static_cast<uint32_t>(out_client_hello.size() - 4u);
    out_client_hello[1] = static_cast<uint8_t>((new_hs_len >> 16) & 0xFFu);
    out_client_hello[2] = static_cast<uint8_t>((new_hs_len >> 8) & 0xFFu);
    out_client_hello[3] = static_cast<uint8_t>(new_hs_len & 0xFFu);

    transcript_ = out_client_hello;
    return true;
}

bool Tls13QuicDriver::OnInitialServerBytes(const uint8_t* data, size_t len) noexcept {
    if (!data || len == 0 || has_hs_) return has_hs_;
    init_buf_.insert(init_buf_.end(), data, data + len);
    if (init_buf_.size() < 4u) return false;
    if (init_buf_[0] != 0x02) return false;
    const uint32_t msg_len = ReadBe24(init_buf_.data() + 1);
    if (init_buf_.size() < 4u + msg_len || msg_len < 38u) return false;

    const uint8_t* sh = init_buf_.data() + 4u;
    const uint8_t sid_len = sh[34];
    size_t pos = 35u + sid_len;
    if (pos + 5u > msg_len) return false;
    const uint16_t suite = ReadBe16(sh + pos);
    pos += 3u;
    const uint16_t ext_total = ReadBe16(sh + pos);
    pos += 2u;
    if (pos + ext_total > msg_len) return false;

    uint8_t server_pub[32]{};
    bool got_pub = false, got_13 = false;
    const size_t ext_end = pos + ext_total;
    while (pos + 4u <= ext_end) {
        const uint16_t eid = ReadBe16(sh + pos);
        const uint16_t elen = ReadBe16(sh + pos + 2);
        pos += 4u;
        if (pos + elen > ext_end) return false;
        if (eid == 0x002B && elen >= 2 && ReadBe16(sh + pos) == 0x0304) got_13 = true;
        else if (eid == 0x0033 && elen >= 36) {
            if (ReadBe16(sh + pos) == 0x001D && ReadBe16(sh + pos + 2) == 32 && pos + 36 <= ext_end) {
                std::memcpy(server_pub, sh + pos + 4, 32);
                got_pub = true;
            }
        }
        pos += elen;
    }
    if (!got_13 || !got_pub || (suite != 0x1301 && suite != 0x1302 && suite != 0x1303)) return false;

    transcript_.insert(transcript_.end(), init_buf_.begin(), init_buf_.begin() + static_cast<ptrdiff_t>(4u + msg_len));
    init_buf_.erase(init_buf_.begin(), init_buf_.begin() + static_cast<ptrdiff_t>(4u + msg_len));

    secrets_.cipher_suite = suite;
    secrets_.use_sha384 = (suite == 0x1302);
    secrets_.hash_len = secrets_.use_sha384 ? 48u : 32u;

    uint8_t shared[32]{};
    if (!crypto::X25519(shared, eph_priv_, server_pub)) return false;
    uint8_t zeros[48]{}, early[48]{}, derived[48]{};
    HkdfExtractChoice(secrets_.use_sha384, zeros, secrets_.hash_len, zeros, secrets_.hash_len, early);
    size_t eh_len = 0;
    HashTranscript(secrets_.use_sha384, {}, empty_hash_, eh_len);
    crypto::Tls13HkdfExpandLabel(secrets_.use_sha384, early, "derived", empty_hash_, secrets_.hash_len, derived, secrets_.hash_len);
    HkdfExtractChoice(secrets_.use_sha384, derived, secrets_.hash_len, shared, 32, hs_secret_);

    uint8_t tr_hash[48]{};
    size_t hlen = 0;
    HashTranscript(secrets_.use_sha384, transcript_, tr_hash, hlen);
    crypto::Tls13HkdfExpandLabel(secrets_.use_sha384, hs_secret_, "c hs traffic", tr_hash, secrets_.hash_len, secrets_.client_hs_traffic, secrets_.hash_len);
    crypto::Tls13HkdfExpandLabel(secrets_.use_sha384, hs_secret_, "s hs traffic", tr_hash, secrets_.hash_len, secrets_.server_hs_traffic, secrets_.hash_len);
    has_hs_ = true;
    return true;
}

bool Tls13QuicDriver::OnHandshakeServerBytes(const uint8_t* data, size_t len,
                                             std::vector<uint8_t>& out_client_finished,
                                             bool& out_complete) noexcept {
    out_complete = false;
    if (!has_hs_ || !data || len == 0) return false;
    hs_buf_.insert(hs_buf_.end(), data, data + len);

    while (hs_buf_.size() >= 4u) {
        const uint8_t ht = hs_buf_[0];
        const uint32_t mlen = ReadBe24(hs_buf_.data() + 1);
        if (hs_buf_.size() < 4u + mlen) break;

        if (ht == 0x08 && mlen >= 2u) {
            const uint8_t* ee = hs_buf_.data() + 4;
            const uint16_t ext_tot = ReadBe16(ee);
            size_t pos = 2u;
            const size_t end = std::min<size_t>(mlen, 2u + ext_tot);
            while (pos + 4u <= end) {
                const uint16_t eid = ReadBe16(ee + pos);
                const uint16_t elen = ReadBe16(ee + pos + 2);
                pos += 4u;
                if (pos + elen > end) break;
                if (eid == 0x0039) peer_tp_.assign(ee + pos, ee + pos + elen);
                pos += elen;
            }
        } else if (ht == 0x14) {
            uint8_t pre_hash[48]{};
            size_t hlen = 0;
            HashTranscript(secrets_.use_sha384, transcript_, pre_hash, hlen);
            uint8_t s_fin_key[48]{}, exp_fin[48]{};
            crypto::Tls13HkdfExpandLabel(secrets_.use_sha384, secrets_.server_hs_traffic, "finished", nullptr, 0, s_fin_key, secrets_.hash_len);
            HmacChoice(secrets_.use_sha384, s_fin_key, secrets_.hash_len, pre_hash, secrets_.hash_len, exp_fin);
            if (mlen != secrets_.hash_len || !crypto::ConstantTimeEqual(exp_fin, hs_buf_.data() + 4, secrets_.hash_len)) {
                return false;
            }
            transcript_.insert(transcript_.end(), hs_buf_.begin(), hs_buf_.begin() + static_cast<ptrdiff_t>(4u + mlen));
            hs_buf_.erase(hs_buf_.begin(), hs_buf_.begin() + static_cast<ptrdiff_t>(4u + mlen));

            uint8_t tr_sf_hash[48]{};
            HashTranscript(secrets_.use_sha384, transcript_, tr_sf_hash, hlen);
            uint8_t c_fin_key[48]{}, c_ver[48]{};
            crypto::Tls13HkdfExpandLabel(secrets_.use_sha384, secrets_.client_hs_traffic, "finished", nullptr, 0, c_fin_key, secrets_.hash_len);
            HmacChoice(secrets_.use_sha384, c_fin_key, secrets_.hash_len, tr_sf_hash, secrets_.hash_len, c_ver);

            out_client_finished.clear();
            out_client_finished.push_back(0x14);
            AppendBe24(out_client_finished, static_cast<uint32_t>(secrets_.hash_len));
            out_client_finished.insert(out_client_finished.end(), c_ver, c_ver + secrets_.hash_len);

            uint8_t zeros[48]{}, d2[48]{}, ms[48]{};
            crypto::Tls13HkdfExpandLabel(secrets_.use_sha384, hs_secret_, "derived", empty_hash_, secrets_.hash_len, d2, secrets_.hash_len);
            HkdfExtractChoice(secrets_.use_sha384, d2, secrets_.hash_len, zeros, secrets_.hash_len, ms);
            crypto::Tls13HkdfExpandLabel(secrets_.use_sha384, ms, "c ap traffic", tr_sf_hash, secrets_.hash_len, secrets_.client_ap_traffic, secrets_.hash_len);
            crypto::Tls13HkdfExpandLabel(secrets_.use_sha384, ms, "s ap traffic", tr_sf_hash, secrets_.hash_len, secrets_.server_ap_traffic, secrets_.hash_len);
            complete_ = true;
            out_complete = true;
            return true;
        }

        transcript_.insert(transcript_.end(), hs_buf_.begin(), hs_buf_.begin() + static_cast<ptrdiff_t>(4u + mlen));
        hs_buf_.erase(hs_buf_.begin(), hs_buf_.begin() + static_cast<ptrdiff_t>(4u + mlen));
    }
    return true;
}

}  // namespace yumi_nx::net
