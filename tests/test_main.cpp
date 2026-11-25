#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "yumi_nx/config_store.hpp"
#include "yumi_nx/ipc_protocol.hpp"
#include "yumi_nx/models.hpp"
#include "yumi_nx/qr_matrix.hpp"
#include "yumi_nx/mitm_policy.hpp"
#include "yumi_nx/subscription_parser.hpp"
#include "yumi_nx/rules_bin.hpp"
#include "ui/yumi_theme.hpp"
#include "yumi_nx/net_interfaces.hpp"
#include "yumi_nx/crypto.hpp"
#include "yumi_nx/socket_io.hpp"
#include "yumi_nx/dns_engine.hpp"
#include "yumi_nx/tls13_reality.hpp"
#include "yumi_nx/transports.hpp"
#include "yumi_nx/vless_dialer.hpp"
#include "yumi_nx/wireguard_dialer.hpp"
#include "yumi_nx/shadowsocks_dialer.hpp"
#include "yumi_nx/trojan_dialer.hpp"
#include "yumi_nx/vmess_dialer.hpp"
#include "yumi_nx/hysteria2_dialer.hpp"
#include "yumi_nx/tunnel_engine.hpp"
#include "http_client.hpp"
#include "pairing_service.hpp"
#include "latency_tester.hpp"
#include "remote_service.hpp"
#include "hos_apps.hpp"
#include "speed_tester.hpp"
#include "update_checker.hpp"
#include <filesystem>
#include <nlohmann/json.hpp>

namespace {

int g_tests_run = 0;

#define YUMI_TEST(name)                                                       \
    do {                                                                      \
        ++g_tests_run;                                                        \
        std::printf("[RUN ] %s\n", name);                                     \
    } while (0)

#define YUMI_CHECK(expr)                                                      \
    do {                                                                      \
        if (!(expr)) {                                                        \
            std::fprintf(stderr, "[FAIL] %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return 1;                                                         \
        }                                                                     \
    } while (0)

}  // namespace

int main() {
    using namespace yumi_nx;

    // 1. IPC protocol layout & HOS generation checks
    YUMI_TEST("ipc_hos_version_classification");
    {
        YUMI_CHECK(ipc::ClassifyHosVersion(0x00120100u) == ipc::HosGeneration::Pre19);    // 18.1.0
        YUMI_CHECK(ipc::ClassifyHosVersion(0x00130001u) == ipc::HosGeneration::Hos19);    // 19.0.1
        YUMI_CHECK(ipc::ClassifyHosVersion(0x00140000u) == ipc::HosGeneration::Hos20Plus);// 20.0.0
        YUMI_CHECK(ipc::ClassifyHosVersion(0x00150100u) == ipc::HosGeneration::Hos20Plus);// 21.1.0
        YUMI_CHECK(ipc::ClassifyHosVersion(0u) == ipc::HosGeneration::Unknown);
    }

    // 2. Active node binary codec round-trip across protocols
    YUMI_TEST("active_node_binary_vless_reality_roundtrip");
    {
        ProxyNode node;
        node.id = "node-01";
        node.name = "Finland REALITY";
        node.server = "fi.example.com";
        node.port = 443;
        node.protocol = Protocol::Vless;
        node.uuid_or_user = "11111111-2222-3333-4444-555555555555";
        node.flow = "xtls-rprx-vision";
        node.packet_encoding = "xudp";
        node.tls.enabled = true;
        node.tls.server_name = "www.apple.com";
        node.tls.alpn = {"h2", "http/1.1"};
        node.tls.fingerprint = "chrome";
        node.tls.reality.enabled = true;
        node.tls.reality.public_key = "pub-key-base64";
        node.tls.reality.short_id = "abcd1234";
        node.tls.reality.spider_x = "/store";
        node.transport.kind = TransportKind::Xhttp;
        node.transport.path = "/api";
        node.transport.host = "cdn.example.com";
        node.transport.xhttp_mode = "packet-up";

        const auto encoded = store::EncodeActiveNodeBinary(node);
        YUMI_CHECK(!encoded.empty());
        const auto decoded = store::DecodeActiveNodeBinary(encoded);
        YUMI_CHECK(decoded.has_value());
        YUMI_CHECK(decoded->id == node.id);
        YUMI_CHECK(decoded->name == node.name);
        YUMI_CHECK(decoded->server == node.server);
        YUMI_CHECK(decoded->port == 443);
        YUMI_CHECK(decoded->protocol == Protocol::Vless);
        YUMI_CHECK(decoded->flow == "xtls-rprx-vision");
        YUMI_CHECK(decoded->tls.reality.enabled);
        YUMI_CHECK(decoded->tls.reality.public_key == "pub-key-base64");
        YUMI_CHECK(decoded->tls.reality.short_id == "abcd1234");
        YUMI_CHECK(decoded->tls.alpn.size() == 2);
        YUMI_CHECK(decoded->transport.kind == TransportKind::Xhttp);
        YUMI_CHECK(decoded->transport.xhttp_mode == "packet-up");

        // Corruption rejection
        auto corrupted = encoded;
        corrupted.back() ^= 0x5Au;
        YUMI_CHECK(!store::DecodeActiveNodeBinary(corrupted).has_value());
    }

    YUMI_TEST("active_node_binary_wireguard_and_hy2_roundtrip");
    {
        ProxyNode wg;
        wg.id = "wg-1";
        wg.name = "Home WG";
        wg.server = "203.0.113.10";
        wg.port = 51820;
        wg.protocol = Protocol::WireGuard;
        wg.wireguard.private_key = "priv";
        wg.wireguard.peer_public_key = "peer";
        wg.wireguard.local_addresses = {"10.0.0.2/32", "fd00::2/128"};
        wg.wireguard.mtu = 1420;
        wg.wireguard.has_reserved = true;
        wg.wireguard.reserved[0] = 1;
        wg.wireguard.reserved[1] = 2;
        wg.wireguard.reserved[2] = 3;

        const auto dec_wg = store::DecodeActiveNodeBinary(store::EncodeActiveNodeBinary(wg));
        YUMI_CHECK(dec_wg.has_value());
        YUMI_CHECK(dec_wg->wireguard.mtu == 1420);
        YUMI_CHECK(dec_wg->wireguard.has_reserved);
        YUMI_CHECK(dec_wg->wireguard.reserved[2] == 3);
        YUMI_CHECK(dec_wg->wireguard.local_addresses.size() == 2);

        ProxyNode hy2;
        hy2.id = "hy2-1";
        hy2.name = "Fast Hy2";
        hy2.server = "hy.example.com";
        hy2.port = 8443;
        hy2.protocol = Protocol::Hysteria2;
        hy2.password_or_key = "secret";
        hy2.hysteria2.obfs_type = "salamander";
        hy2.hysteria2.obfs_password = "obfs";
        hy2.hysteria2.up_mbps = 50;
        hy2.hysteria2.down_mbps = 200;

        const auto dec_hy2 = store::DecodeActiveNodeBinary(store::EncodeActiveNodeBinary(hy2));
        YUMI_CHECK(dec_hy2.has_value());
        YUMI_CHECK(dec_hy2->hysteria2.obfs_type == "salamander");
        YUMI_CHECK(dec_hy2->hysteria2.down_mbps == 200);
    }

    // 3. Settings JSON round-trip (including TitleID split tunneling & CustomRules)
    YUMI_TEST("settings_json_roundtrip");
    {
        AppSettings s;
        s.routing_mode = RoutingMode::Rules;
        s.block_quic = true;
        s.auto_connect_on_boot = true;
        s.split_tunnel_mode = SplitTunnelMode::AllowList;
        s.split_tunnel_title_ids = {0x01003A400C3DA000ULL, 0x010000000000100FULL};
        s.tls_fingerprint = TlsFingerprint::Chrome;
        s.fragment_mode = FragmentMode::TlsHello;
        s.custom_rules.proxy = {"domain:youtube.com", "domain:googlevideo.com"};
        s.custom_rules.direct = {"geosite:ru", "192.168.1.0/24"};
        s.custom_rules.block = {"geosite:category-ads-all"};

        const std::string json_str = store::SerializeSettingsJson(s);
        const auto parsed = store::DeserializeSettingsJson(json_str);
        YUMI_CHECK(parsed.has_value());
        YUMI_CHECK(parsed->routing_mode == RoutingMode::Rules);
        YUMI_CHECK(parsed->block_quic);
        YUMI_CHECK(parsed->auto_connect_on_boot);
        YUMI_CHECK(parsed->split_tunnel_mode == SplitTunnelMode::AllowList);
        YUMI_CHECK(parsed->split_tunnel_title_ids.size() == 2);
        YUMI_CHECK(parsed->split_tunnel_title_ids[0] == 0x01003A400C3DA000ULL);
        YUMI_CHECK(parsed->tls_fingerprint == TlsFingerprint::Chrome);
        YUMI_CHECK(parsed->fragment_mode == FragmentMode::TlsHello);
        YUMI_CHECK(parsed->custom_rules.proxy.size() == 2);
        YUMI_CHECK(parsed->custom_rules.direct[1] == "192.168.1.0/24");
    }

    // 4. CustomRules normalization tests
    YUMI_TEST("custom_rules_normalize");
    {
        YUMI_CHECK(CustomRules::Normalize("https://www.YouTube.com/watch?v=123") == "domain:www.youtube.com");
        YUMI_CHECK(CustomRules::Normalize("192.168.0.0/16") == "192.168.0.0/16");
        YUMI_CHECK(CustomRules::Normalize("1.1.1.1:443") == "1.1.1.1");
        YUMI_CHECK(CustomRules::Normalize("geosite:ru") == "geosite:ru");
        YUMI_CHECK(!CustomRules::Normalize("bad host name").has_value());
        YUMI_CHECK(!CustomRules::Normalize("999.0.0.1/33").has_value());
    }

    // 5. Router Stub (QUIC block, Bypass LAN, TitleID Split Tunneling)
    YUMI_TEST("basic_router_decisions");
    {
        net::BasicRouter router;
        AppSettings s;
        s.routing_mode = RoutingMode::Global;
        s.block_quic = true;
        s.bypass_lan = true;

        YUMI_CHECK(router.Decide({"www.youtube.com", 443, true, 0x01003A400C3DA000ULL}, s) ==
                   net::RouteAction::Block);
        YUMI_CHECK(router.Decide({"www.youtube.com", 443, false, 0x01003A400C3DA000ULL}, s) ==
                   net::RouteAction::Proxy);
        YUMI_CHECK(router.Decide({"192.168.1.50", 8080, false, 0}, s) == net::RouteAction::Direct);
        YUMI_CHECK(router.Decide({"10.0.0.1", 53, true, 0}, s) == net::RouteAction::Direct);
        YUMI_CHECK(router.Decide({"switch.local", 5000, false, 0}, s) == net::RouteAction::Direct);

        // AllowList TitleID split tunneling: YouTube goes Proxy, other title goes Direct
        s.split_tunnel_mode = SplitTunnelMode::AllowList;
        s.split_tunnel_title_ids = {0x01003A400C3DA000ULL};
        YUMI_CHECK(router.Decide({"example.com", 443, false, 0x01003A400C3DA000ULL}, s) ==
                   net::RouteAction::Proxy);
        YUMI_CHECK(router.Decide({"example.com", 443, false, 0x01006A800016E000ULL}, s) ==
                   net::RouteAction::Direct);
    }

    // 7. QR Version 4-M matrix encoding
    YUMI_TEST("qr_matrix_v4m_encoding");
    {
        const auto qr = BuildQrMatrixV4M("vless://11111111-2222-3333-4444@1.2.3.4:443");
        YUMI_CHECK(yumi_nx::QrMatrix::kSize == 33);
        YUMI_CHECK(qr.modules.size() == 33u * 33u);
        // Top-left 7x7 finder pattern corners & center must be dark
        YUMI_CHECK(qr.IsFinder(0, 0) && !qr.IsFinder(10, 10));
        YUMI_CHECK(qr.At(0, 0) && qr.At(6, 0) && qr.At(0, 6) && qr.At(3, 3));
        // Timing pattern alternating bits on row 6 (col 8 is dark, col 9 is light)
        YUMI_CHECK(qr.At(8, 6) && !qr.At(9, 6));
    }

    // 8. MITM self/system PID exclusion policy
    YUMI_TEST("mitm_policy_self_and_system_protection");
    {
        YUMI_CHECK(!mitm::ShouldMitmProgramId(ipc::kYumiProgramId));
        YUMI_CHECK(!mitm::ShouldMitmProgramId(0x0100000000000000ULL));
        YUMI_CHECK(!mitm::ShouldMitmProgramId(0x0100000000000FFFULL));
        YUMI_CHECK(mitm::ShouldMitmProgramId(0x0100000000001000ULL));
        YUMI_CHECK(mitm::ShouldMitmProgramId(0x01006A800016E000ULL));
        YUMI_CHECK(mitm::ShouldMitmProgramId(mitm::kYumiAppProgramId));
    }

    // 9. IPC connection record binary contract & MITM bitmask
    YUMI_TEST("ipc_connection_record_layout");
    {
        ipc::IpcConnectionRecord rec{};
        rec.program_id = 0x01006A800016E000ULL;
        rec.sequence_id = 42;
        rec.port = 443;
        rec.is_udp = 1;
        rec.route_action = 2;
        rec.accepted = 0;
        YUMI_CHECK(sizeof(ipc::IpcConnectionRecord) == 128);
        YUMI_CHECK(rec.sequence_id == 42 && rec.port == 443 && rec.accepted == 0);
        YUMI_CHECK((ipc::mitm_flag::kBsdMitmActive | ipc::mitm_flag::kSfdnsresMitmActive |
                    ipc::mitm_flag::kPscMonitorActive | ipc::mitm_flag::kNetworkOnline) == 0x0F);
    }

    // 10. Yumi M3 Expressive palettes and AMOLED semantics
    YUMI_TEST("yumi_theme_palettes_and_amoled");
    {
        std::array<ui::ColorRgba, 7> primaries{};
        for (uint8_t i = 0; i < 7; ++i) {
            const auto pal = static_cast<ui::PaletteId>(i);
            const auto t = ui::BuildYumiTheme(pal, false);
            const auto t_amoled = ui::BuildYumiTheme(pal, true);
            primaries[i] = t.primary;

            YUMI_CHECK(t.background.r > 0 || t.background.g > 0 || t.background.b > 0);
            YUMI_CHECK(t_amoled.background == (ui::ColorRgba{0, 0, 0, 255}));
            YUMI_CHECK(t_amoled.surface_lowest == (ui::ColorRgba{0, 0, 0, 255}));
            YUMI_CHECK(t.marker_accent.r >= 200 || t.marker_accent.g >= 200 || t.marker_accent.b >= 200);
            YUMI_CHECK(ui::LatencyColorFor(t, -1) == t.latency_dead);
            YUMI_CHECK(ui::LatencyColorFor(t, 40) == t.latency_fast);
            YUMI_CHECK(ui::LatencyColorFor(t, 100) == t.latency_medium);
            YUMI_CHECK(ui::LatencyColorFor(t, 250) == t.latency_slow);
        }
        for (size_t i = 0; i < primaries.size(); ++i) {
            for (size_t j = i + 1; j < primaries.size(); ++j) {
                YUMI_CHECK(!(primaries[i] == primaries[j]));
            }
        }
    }

    // 11. Phase 2 Crypto RFC test vectors (SHA-256/512, BLAKE2s, HMAC, X25519 RFC 7748, AES-GCM NIST, ChaCha20-Poly1305)
    YUMI_TEST("crypto_rfc_vectors");
    {
        auto to_hex = [](const uint8_t* d, size_t n) {
            std::string s;
            static const char kHex[] = "0123456789abcdef";
            for (size_t i = 0; i < n; ++i) {
                s.push_back(kHex[d[i] >> 4]);
                s.push_back(kHex[d[i] & 0xF]);
            }
            return s;
        };

        uint8_t s256[32]{};
        net::crypto::Sha256::Digest("abc", 3, s256);
        YUMI_CHECK(to_hex(s256, 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

        uint8_t s512[64]{};
        net::crypto::Sha512::Digest512("abc", 3, s512);
        YUMI_CHECK(to_hex(s512, 64) ==
                   "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                   "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");

        uint8_t b2s[32]{};
        net::crypto::Blake2s::Digest(nullptr, 0, "abc", 3, b2s, 32);
        YUMI_CHECK(to_hex(b2s, 32) == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");

        uint8_t hmac_out[32]{};
        const uint8_t key_jefe[4] = {'J', 'e', 'f', 'e'};
        const char msg_rfc4231[] = "what do ya want for nothing?";
        net::crypto::HmacSha256(key_jefe, 4, reinterpret_cast<const uint8_t*>(msg_rfc4231), 28, hmac_out);
        YUMI_CHECK(to_hex(hmac_out, 32) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

        // X25519 RFC 7748 §6.1
        auto alice_priv = net::crypto::HexDecode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        auto bob_priv = net::crypto::HexDecode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        YUMI_CHECK(alice_priv && bob_priv);
        uint8_t alice_pub[32]{}, bob_pub[32]{}, shared_ab[32]{}, shared_ba[32]{};
        net::crypto::X25519Base(alice_pub, alice_priv->data());
        net::crypto::X25519Base(bob_pub, bob_priv->data());
        YUMI_CHECK(to_hex(alice_pub, 32) == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        YUMI_CHECK(to_hex(bob_pub, 32) == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        YUMI_CHECK(net::crypto::X25519(shared_ab, alice_priv->data(), bob_pub));
        YUMI_CHECK(net::crypto::X25519(shared_ba, bob_priv->data(), alice_pub));
        YUMI_CHECK(std::memcmp(shared_ab, shared_ba, 32) == 0);
        YUMI_CHECK(to_hex(shared_ab, 32) == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        // AES-128-GCM NIST SP 800-38D Test Case 2 (zero key, zero iv, 16 zero bytes)
        uint8_t key0[16]{}, iv0[12]{}, pt0[16]{}, ct0[16]{}, tag0[16]{}, dec0[16]{};
        YUMI_CHECK(net::crypto::AesGcmEncrypt(key0, 16, iv0, nullptr, 0, pt0, 16, ct0, tag0));
        YUMI_CHECK(to_hex(ct0, 16) == "0388dace60b6a392f328c2b971b2fe78");
        YUMI_CHECK(to_hex(tag0, 16) == "ab6e47d42cec13bdf53a67b21257bddf");
        YUMI_CHECK(net::crypto::AesGcmDecrypt(key0, 16, iv0, nullptr, 0, ct0, 16, tag0, dec0));
        YUMI_CHECK(std::memcmp(dec0, pt0, 16) == 0);
        tag0[0] ^= 0x01;
        YUMI_CHECK(!net::crypto::AesGcmDecrypt(key0, 16, iv0, nullptr, 0, ct0, 16, tag0, dec0));

        // ChaCha20-Poly1305 RFC 8439 round-trip + tamper detection
        uint8_t ckey[32]{}, cnonce[12]{}, cpt[21] = "YumiSwitch ChaCha20!";
        uint8_t cct[21]{}, ctag[16]{}, cdec[21]{};
        net::crypto::RandomBytes(ckey, 32);
        net::crypto::RandomBytes(cnonce, 12);
        const uint8_t aad[5] = {0x17, 0x03, 0x03, 0x00, 0x25};
        YUMI_CHECK(net::crypto::ChaCha20Poly1305Encrypt(ckey, cnonce, aad, 5, cpt, 21, cct, ctag));
        YUMI_CHECK(net::crypto::ChaCha20Poly1305Decrypt(ckey, cnonce, aad, 5, cct, 21, ctag, cdec));
        YUMI_CHECK(std::memcmp(cdec, cpt, 21) == 0);
        ctag[15] ^= 0x80;
        YUMI_CHECK(!net::crypto::ChaCha20Poly1305Decrypt(ckey, cnonce, aad, 5, cct, 21, ctag, cdec));
    }

    // 12. DNS packet + FakeIP pool + Horizon OS sfdnsres wire serializer
    YUMI_TEST("dns_packet_and_sfdnsres_codec");
    {
        auto q = net::BuildDnsQueryA("youtube.com", 0x1234);
        YUMI_CHECK(q.size() > 12 && q[0] == 0x12 && q[1] == 0x34);

        // Synthetic response echoing query + compressed answer 0xC0 0x0C -> 142.250.74.78 (TTL 120)
        std::vector<uint8_t> resp = q;
        resp[2] = 0x81; resp[3] = 0x80;  // Response, NoError
        resp[6] = 0x00; resp[7] = 0x01;  // ANCOUNT = 1
        const uint8_t ans[16] = {
            0xC0, 0x0C,              // Pointer to QNAME
            0x00, 0x01, 0x00, 0x01,  // TYPE A, CLASS IN
            0x00, 0x00, 0x00, 0x78,  // TTL 120
            0x00, 0x04,              // RDLENGTH 4
            142, 250, 74, 78
        };
        resp.insert(resp.end(), ans, ans + 16);
        uint32_t ip_h = 0, ttl = 0;
        YUMI_CHECK(net::ParseDnsResponseA(resp.data(), resp.size(), ip_h, ttl));
        YUMI_CHECK(ip_h == 0x8EFA4A4Eu && ttl == 120u);

        net::FakeIpPool fake;
        const uint32_t fip = fake.Allocate("www.youtube.com");
        YUMI_CHECK(net::FakeIpPool::IsFakeIp(fip));
        std::string resolved_host;
        YUMI_CHECK(fake.Lookup(fip, resolved_host) && resolved_host == "www.youtube.com");

        uint8_t buf[256]{};
        const size_t n1 = net::SerializeSfdnsresAddrInfoIPv4(fip, 443, 1, 6, "www.youtube.com", buf, sizeof(buf));
        YUMI_CHECK(n1 > 40);
        YUMI_CHECK(buf[0] == 0xBE && buf[1] == 0xEF && buf[2] == 0xCA && buf[3] == 0xFE);
        YUMI_CHECK(buf[11] == 2 && buf[23] == 16 && buf[24] == 16 && buf[25] == 2);
        // Little-endian port 443 (0x01BB -> {0xBB, 0x01}) for libnx rev16
        YUMI_CHECK(buf[26] == 0xBB && buf[27] == 0x01);

        const size_t n2 = net::SerializeSfdnsresHostentIPv4("www.youtube.com", fip, buf, sizeof(buf));
        YUMI_CHECK(n2 == 16 + 16);
    }

    // 13. TLS 1.3 ClientHello + XTLS-REALITY SessionId auth token round-trip
    YUMI_TEST("tls13_reality_client_hello_and_schedule");
    {
        uint8_t srv_priv[32]{}, srv_pub[32]{}, eph_priv[32]{}, crand[32]{};
        net::crypto::RandomBytes(srv_priv, 32);
        net::crypto::RandomBytes(eph_priv, 32);
        net::crypto::RandomBytes(crand, 32);
        net::crypto::X25519Base(srv_pub, srv_priv);

        RealityOptions ropt{};
        ropt.enabled = true;
        ropt.public_key = net::crypto::Base64Encode(srv_pub, 32, true, false);
        ropt.short_id = "a1b2c3d4";

        uint8_t client_ak[32]{};
        const auto ch = net::BuildTls13ClientHello("www.microsoft.com", {"h2", "http/1.1"},
                                                   eph_priv, crand, &ropt, 1764000000u, client_ak);
        YUMI_CHECK(ch.size() > 80 && ch[0] == 0x01);

        // Server side verification of REALITY SessionId ciphertext using srv_priv + client key_share
        const uint8_t* sid = ch.data() + 39;
        uint8_t eph_pub[32]{};
        net::crypto::X25519Base(eph_pub, eph_priv);
        uint8_t srv_shared[32]{}, srv_prk[32]{}, srv_ak[32]{};
        YUMI_CHECK(net::crypto::X25519(srv_shared, srv_priv, eph_pub));
        net::crypto::HkdfExtractSha256(crand, 20, srv_shared, 32, srv_prk);
        static constexpr uint8_t kR[7] = {'R', 'E', 'A', 'L', 'I', 'T', 'Y'};
        YUMI_CHECK(net::crypto::HkdfExpandSha256(srv_prk, kR, 7, srv_ak, 32));
        YUMI_CHECK(std::memcmp(client_ak, srv_ak, 32) == 0);

        std::vector<uint8_t> aad = ch;
        std::memset(aad.data() + 39, 0, 32);  // REALITY decrypts with zeroed SessionId AAD
        uint8_t pt[16]{};
        YUMI_CHECK(net::crypto::AesGcmDecrypt(srv_ak, 32, crand + 20, aad.data(), aad.size(), sid, 16, sid + 16, pt));
        YUMI_CHECK(pt[0] == 1 && pt[1] == 8 && pt[2] == 24 && pt[8] == 0xA1 && pt[9] == 0xB2);
    }

    // 14. VLESS + XTLS-Vision + XUDP wire codec
    YUMI_TEST("vless_vision_xudp_wire_format");
    {
        uint8_t uuid[16]{};
        YUMI_CHECK(net::crypto::ParseUuidBytes("11111111-2222-3333-4444-555555555555", uuid));
        const auto vhdr = net::EncodeVlessRequestHeader(uuid, "xtls-rprx-vision", net::VlessCmd::Tcp, "www.youtube.com", 443);
        YUMI_CHECK(vhdr[0] == 0x00 && std::memcmp(vhdr.data() + 1, uuid, 16) == 0 && vhdr[17] == 18);

        const uint8_t vresp[2] = {0x00, 0x00};
        bool vvalid = false;
        YUMI_CHECK(net::DecodeVlessResponseHeader(vresp, 2, vvalid) == 2 && vvalid);

        const uint8_t hello[5] = {0x16, 0x03, 0x01, 0x00, 0xAA};
        const auto vis = net::EncodeVisionPacket(uuid, net::VisionCmd::Continue, hello, 5, 3);
        net::VisionCmd out_cmd = net::VisionCmd::End;
        std::vector<uint8_t> out_c;
        YUMI_CHECK(net::DecodeVisionPacket(vis.data(), vis.size(), true, out_cmd, out_c) == vis.size());
        YUMI_CHECK(out_cmd == net::VisionCmd::Continue && out_c.size() == 5 && out_c[4] == 0xAA);

        const uint8_t dpkt[4] = {0xDE, 0xAD, 0xBE, 0xEF};
        const auto xudp = net::EncodeXudpFrame(7, 1, "1.1.1.1", 53, dpkt, 4);
        size_t xused = 0;
        uint16_t fid = 0;
        uint8_t fst = 0;
        std::vector<uint8_t> xpay;
        YUMI_CHECK(net::DecodeXudpFrame(xudp.data(), xudp.size(), xused, fid, fst, xpay));
        YUMI_CHECK(xused == xudp.size() && fid == 7 && fst == 1 && xpay.size() == 4 && xpay[0] == 0xDE);
    }

    // 15. WireGuard Noise_IKpsk2 handshake & transport encryption
    YUMI_TEST("wireguard_noise_ikpsk2_handshake_and_transport");
    {
        uint8_t c_priv[32]{}, c_pub[32]{}, s_priv[32]{}, s_pub[32]{}, psk[32]{}, tai[12]{};
        net::crypto::RandomBytes(c_priv, 32);
        net::crypto::RandomBytes(s_priv, 32);
        net::crypto::RandomBytes(psk, 32);
        net::crypto::X25519Base(c_pub, c_priv);
        net::crypto::X25519Base(s_pub, s_priv);
        tai[0] = 0x40;
        tai[7] = 0x01;

        net::WgHandshakeScratch scratch{};
        uint8_t init_msg[148]{};
        YUMI_CHECK(net::WgBuildHandshakeInitiation(c_priv, s_pub, psk, true, 0x10203040u, nullptr, tai, scratch, init_msg));

        uint8_t resp_msg[92]{};
        net::WgSessionState srv_sess{}, cli_sess{};
        YUMI_CHECK(net::WgRespondHandshakeInitiation(s_priv, c_pub, psk, true, 0x55667788u, init_msg, resp_msg, srv_sess));
        YUMI_CHECK(net::WgProcessHandshakeResponse(scratch, c_priv, resp_msg, cli_sess));
        YUMI_CHECK(std::memcmp(cli_sess.send_key, srv_sess.recv_key, 32) == 0);
        YUMI_CHECK(std::memcmp(cli_sess.recv_key, srv_sess.send_key, 32) == 0);

        const uint8_t ip_pkt[20] = {0x45, 0x00, 0x00, 0x28, 0, 1, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1};
        const auto wire = net::WgEncryptTransportPacket(cli_sess, nullptr, ip_pkt, sizeof(ip_pkt));
        std::vector<uint8_t> dec_ip;
        YUMI_CHECK(net::WgDecryptTransportPacket(srv_sess, wire.data(), wire.size(), dec_ip));
        YUMI_CHECK(dec_ip.size() >= sizeof(ip_pkt) && std::memcmp(dec_ip.data(), ip_pkt, sizeof(ip_pkt)) == 0);
    }

    // 16. Live E2E loopback TunnelEngine proxy test via SOCKS5 + Echo server
    YUMI_TEST("e2e_loopback_tunnel_socks5_and_http");
    {
        YUMI_CHECK(net::SocketLayerInit());

        uint16_t echo_port = 0;
        auto echo_listen = net::NetSocket::TcpListenLoopback(echo_port);
        YUMI_CHECK(echo_listen.IsValid() && echo_port != 0);

        uint16_t socks_port = 0;
        auto socks_listen = net::NetSocket::TcpListenLoopback(socks_port);
        YUMI_CHECK(socks_listen.IsValid() && socks_port != 0);

        std::atomic<bool> stop_servers{false};
        std::thread echo_thr([&]() {
            while (!stop_servers.load()) {
                uint32_t pip = 0;
                uint16_t pport = 0;
                auto cli = echo_listen.Accept(pip, pport);
                if (cli.IsValid()) {
                    uint8_t buf[256];
                    const auto r = cli.RecvSomeBlocking(buf, sizeof(buf), 1500);
                    if (r.status == net::IoStatus::Ok && r.bytes > 0) {
                        cli.SendAllBlocking(buf, r.bytes, 1500);
                    }
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        });

        std::thread socks_thr([&]() {
            net::NetSocket cli, upstream;
            while (!stop_servers.load()) {
                uint32_t pip = 0;
                uint16_t pport = 0;
                cli = socks_listen.Accept(pip, pport);
                if (cli.IsValid()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            if (!cli.IsValid()) return;
            uint8_t greet[3]{};
            if (cli.RecvSomeBlocking(greet, 3, 1500).bytes < 3) return;
            const uint8_t method_ok[2] = {0x05, 0x00};
            cli.SendAllBlocking(method_ok, 2, 1000);
            uint8_t creq[10]{};
            if (cli.RecvSomeBlocking(creq, 10, 1500).bytes < 10) return;
            const uint16_t dport = static_cast<uint16_t>((uint16_t(creq[8]) << 8) | creq[9]);
            if (!upstream.ConnectExactBlocking(0x7F000001u, dport, 1500)) return;
            const uint8_t crep[10] = {0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0};
            cli.SendAllBlocking(crep, 10, 1000);

            uint8_t io_buf[256];
            for (int t = 0; t < 200 && !stop_servers.load(); ++t) {
                auto r1 = cli.RecvSome(io_buf, sizeof(io_buf));
                if (r1.status == net::IoStatus::Ok && r1.bytes > 0) {
                    upstream.SendAllBlocking(io_buf, r1.bytes, 1000);
                }
                auto r2 = upstream.RecvSome(io_buf, sizeof(io_buf));
                if (r2.status == net::IoStatus::Ok && r2.bytes > 0) {
                    cli.SendAllBlocking(io_buf, r2.bytes, 1000);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(3));
            }
        });

        ProxyNode s5_node{};
        s5_node.id = "test-s5";
        s5_node.protocol = Protocol::Socks5;
        s5_node.server = "127.0.0.1";
        s5_node.port = socks_port;

        AppSettings cfg{};
        cfg.routing_mode = RoutingMode::Global;

        net::TunnelEngine engine;
        YUMI_CHECK(engine.Start(s5_node, cfg, false, 0));
        YUMI_CHECK(engine.RelayPort() != 0);

        // Bind a temporary loopback port matching Switch MITM bind -> GetLocalPort -> RegisterPendingTarget
        uint16_t cli_port = 0;
        net::NetSocket client = net::NetSocket::CreateTcp(true);
        // Connect via ephemeral source bound listener-less socket helper:
        net::NetSocket tmp_bind = net::NetSocket::TcpListenLoopback(cli_port);
        YUMI_CHECK(tmp_bind.IsValid());
        tmp_bind.Close();
        // Even simpler: connect client first via TcpConnectAsync isn't pre-bound unless we connect cleanly after getting port?
        // Instead register a bound socket directly OR test via ConnectExactBlocking after binding 127.0.0.1:0!
        // Look: NetSocket doesn't expose raw bind(), so let's connect via a local TCP client bound with a helper test or register port:
        // Actually on Windows we can test engine.Start(spawn_thread=true) OR add direct ConnectFromEphemeral? No! Wait: let's connect and read port:
        client.Close();

        // Bind client socket before connect using TcpConnectAsync wouldn't bind 0; instead let's test direct + TunnelEngine via bind?
        // Wait: on TunnelEngine without spawn_thread, if ConnectBlocking happens before StepOnce(), TCP 3-way handshake completes on loopback kernel queue AND client.GetLocalPort(cli_port) succeeds immediately!
        bool async_ok = false;
        client = net::NetSocket::TcpConnectAsync(0x7F000001u, engine.RelayPort(), async_ok);
        YUMI_CHECK(client.IsValid());
        uint16_t assigned_cli_port = 0;
        YUMI_CHECK(client.GetLocalPort(assigned_cli_port) && assigned_cli_port != 0);
        engine.RegisterPendingTarget(assigned_cli_port, {"127.0.0.1", echo_port, false, 0});

        const char payload[] = "Hello Yumi Phase 2!";
        YUMI_CHECK(client.SendAllBlocking(payload, sizeof(payload) - 1, 1500));

        std::string echoed;
        for (int iter = 0; iter < 150 && echoed.size() < sizeof(payload) - 1; ++iter) {
            engine.StepOnce(10);
            uint8_t rx[64];
            const auto r = client.RecvSome(rx, sizeof(rx));
            if (r.status == net::IoStatus::Ok && r.bytes > 0) {
                echoed.append(reinterpret_cast<const char*>(rx), r.bytes);
            }
        }
        YUMI_CHECK(echoed == payload);
        YUMI_CHECK(engine.TotalUplinkBytes() >= sizeof(payload) - 1);
        YUMI_CHECK(engine.TotalDownlinkBytes() >= sizeof(payload) - 1);

        stop_servers.store(true);
        client.Close();
        engine.Stop();
        echo_thr.join();
        socks_thr.join();
    }

    // 17. Dynamic ISO/IEC 18004 QR capacity V1..V15 (incl. yumi://pair & yumi://remote URLs >= 220B)
    YUMI_TEST("qr_matrix_auto_v1_to_v15_capacity");
    {
        auto qr1 = BuildQrMatrixAuto("hi");
        YUMI_CHECK(qr1.size == 21 && qr1.modules.size() == 21u * 21u);
        YUMI_CHECK(qr1.IsFinder(0, 0) && qr1.IsFinder(20, 0) && qr1.IsFinder(0, 20));
        YUMI_CHECK(qr1.At(0, 0) && qr1.At(3, 3) && !qr1.At(1, 1));

        std::string long_pair =
            "yumi://pair?v=1&host=192.168.100.42&port=47654&sid=AbCdEfGhIjKlMnOpQrStUvWxYz"
            "&key=MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            "&name=Nintendo%20Switch";
        auto qr_pair = BuildQrMatrixAuto(long_pair);
        YUMI_CHECK(qr_pair.size >= 57 && qr_pair.size <= 77);
        YUMI_CHECK(qr_pair.modules.size() == static_cast<size_t>(qr_pair.size * qr_pair.size));
        YUMI_CHECK(qr_pair.At(0, 0) && qr_pair.At(qr_pair.size - 1, 0) && qr_pair.At(0, qr_pair.size - 1));

        std::string max_l(510, 'Y');
        auto qr_max = BuildQrMatrixAuto(max_l);
        YUMI_CHECK(qr_max.size == 77 && qr_max.modules.size() == 77u * 77u);
    }

    // 18. Extended crypto test vectors: MD5, SHA-1, SHA-224, BLAKE2b, BLAKE3, SHAKE128, NIST P-256 ECDH & SPKI
    YUMI_TEST("crypto_p256_blake3_blake2b_sha1_sha224_md5_shake128");
    {
        uint8_t d16[16]{}, d20[20]{}, d28[28]{}, d32[32]{}, d64[64]{};
        net::crypto::Md5::Digest("abc", 3, d16);
        YUMI_CHECK(net::crypto::HexEncode(d16, 16) == "900150983cd24fb0d6963f7d28e17f72");

        net::crypto::Sha1::Digest("abc", 3, d20);
        YUMI_CHECK(net::crypto::HexEncode(d20, 20) == "a9993e364706816aba3e25717850c26c9cd0d89d");

        net::crypto::Sha224::Digest("abc", 3, d28);
        YUMI_CHECK(net::crypto::HexEncode(d28, 28) == "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");

        net::crypto::Blake2b::Digest(nullptr, 0, nullptr, 0, d64, 64);
        YUMI_CHECK(net::crypto::HexEncode(d64, 16) == "786a02f742015903c6c6fd852552d272");

        net::crypto::Blake3::Digest("", 0, d32, 32);
        YUMI_CHECK(net::crypto::HexEncode(d32, 16) == "af1349b9f5f9a1a6a0404dea36dcc949");

        net::crypto::Shake128 shake;
        shake.Init();
        shake.Update("abc", 3);
        shake.Final();
        shake.Squeeze(d16, 16);
        YUMI_CHECK(net::crypto::HexEncode(d16, 8) == "5881092dd818bf5c");

        net::crypto::P256KeyPair alice, bob;
        YUMI_CHECK(net::crypto::P256GenerateKeyPair(alice));
        YUMI_CHECK(net::crypto::P256GenerateKeyPair(bob));
        const auto a_spki = net::crypto::P256EncodeSpkiDer(alice.pub65);
        YUMI_CHECK(a_spki.size() == 91);
        uint8_t dec_pub[65]{};
        YUMI_CHECK(net::crypto::P256DecodeSpkiDer(a_spki.data(), a_spki.size(), dec_pub));
        YUMI_CHECK(std::memcmp(dec_pub, alice.pub65, 65) == 0);

        uint8_t sh_a[32]{}, sh_b[32]{};
        YUMI_CHECK(net::crypto::P256Ecdh(sh_a, alice.priv, bob.pub65));
        YUMI_CHECK(net::crypto::P256Ecdh(sh_b, bob.priv, dec_pub));
        YUMI_CHECK(std::memcmp(sh_a, sh_b, 32) == 0);

        dec_pub[5] ^= 0xFFu;
        YUMI_CHECK(!net::crypto::P256Ecdh(sh_a, bob.priv, dec_pub));
    }

    // 19. URI & Subscription Parsers (VLESS, VMess, Trojan, SS/SS2022, Hy2, WG, SOCKS5, HTTP, JSON, SIP008, Clash YAML)
    YUMI_TEST("uri_and_subscription_parsers_all_formats");
    {
        auto n_vless = parse::ParseProxyUri(
            "vless://11111111-2222-3333-4444-555555555555@fi.example.com:443"
            "?security=reality&sni=www.microsoft.com&pbk=pubK&sid=ab12&fp=chrome&flow=xtls-rprx-vision#FI%20Hero",
            "s1");
        YUMI_CHECK(n_vless.has_value() && n_vless->protocol == Protocol::Vless &&
                   n_vless->tls.reality.enabled && n_vless->flow == "xtls-rprx-vision" &&
                   n_vless->name == "FI Hero");

        nlohmann::json vj = {
            {"v", "2"}, {"ps", "VMess AEAD"}, {"add", "vm.example.com"}, {"port", "443"},
            {"id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}, {"aid", "0"},
            {"net", "ws"}, {"path", "/vm"}, {"host", "cdn.example.com"}, {"tls", "tls"}
        };
        const std::string vj_s = vj.dump();
        auto n_vmess = parse::ParseProxyUri(
            "vmess://" + net::crypto::Base64Encode(reinterpret_cast<const uint8_t*>(vj_s.data()), vj_s.size()), "s1");
        YUMI_CHECK(n_vmess.has_value() && n_vmess->protocol == Protocol::Vmess &&
                   n_vmess->transport.kind == TransportKind::WebSocket && n_vmess->tls.enabled);

        auto n_tr = parse::ParseProxyUri("trojan://secretpass@tr.example.com:443?type=grpc&serviceName=TrSvc#Troj", "s1");
        YUMI_CHECK(n_tr.has_value() && n_tr->protocol == Protocol::Trojan &&
                   n_tr->transport.kind == TransportKind::Grpc && n_tr->transport.service_name == "TrSvc");

        const std::string ss_uinfo = net::crypto::Base64Encode(
            reinterpret_cast<const uint8_t*>("aes-128-gcm:pass123"), 19, true, false);
        auto n_ss = parse::ParseProxyUri("ss://" + ss_uinfo + "@ss.example.com:8388#SS1", "s1");
        YUMI_CHECK(n_ss.has_value() && n_ss->protocol == Protocol::Shadowsocks && n_ss->method == "aes-128-gcm");

        auto n_hy2 = parse::ParseProxyUri(
            "hy2://authpw@hy.example.com:8443?obfs=salamander&obfs-password=obfpw&sni=cdn.test#Hy2", "s1");
        YUMI_CHECK(n_hy2.has_value() && n_hy2->protocol == Protocol::Hysteria2 &&
                   n_hy2->hysteria2.obfs_type == "salamander" && n_hy2->password_or_key == "authpw");

        auto n_wg = parse::ParseProxyUri(
            "wg://privK@198.51.100.2:51820?publickey=peerPub&address=10.0.0.2/32&mtu=1420&reserved=1,2,3#WG", "s1");
        YUMI_CHECK(n_wg.has_value() && n_wg->protocol == Protocol::WireGuard &&
                   n_wg->wireguard.mtu == 1420 && n_wg->wireguard.has_reserved && n_wg->wireguard.reserved[1] == 2);

        const std::string sip008 = R"({"version":1,"servers":[{"remarks":"SIP Node","server":"1.2.3.4","server_port":8388,"password":"pw","method":"aes-256-gcm"}]})";
        auto sip_res = parse::ParseSubscriptionBody(sip008, "s-sip");
        YUMI_CHECK(sip_res.status == parse::SubscriptionParseResult::Status::Ok &&
                   sip_res.nodes.size() == 1 && sip_res.nodes[0].name == "SIP Node");

        const std::string clash_yaml =
            "proxies:\n"
            "  - name: Clash Trojan\n"
            "    type: trojan\n"
            "    server: cl.example.net\n"
            "    port: 443\n"
            "    password: clpw\n"
            "    sni: sni.example.net\n";
        auto clash_res = parse::ParseSubscriptionBody(clash_yaml, "s-cl");
        YUMI_CHECK(clash_res.status == parse::SubscriptionParseResult::Status::Ok &&
                   clash_res.nodes.size() == 1 && clash_res.nodes[0].protocol == Protocol::Trojan);

        auto ui = parse::ParseSubscriptionUserInfo("upload=1073741824; download=2147483648; total=10737418240; expire=1798761600");
        YUMI_CHECK(ui.has_value() && ui->has_total && ui->total_bytes == 10737418240ULL);

        std::string b64_title = net::crypto::Base64Encode(reinterpret_cast<const uint8_t*>("Yumi Profile"), 12);
        YUMI_CHECK(parse::DecodeProfileTitle("base64:" + b64_title) == "Yumi Profile");

        ProxyNode ph; ph.server = "0.0.0.0"; ph.port = 1;
        YUMI_CHECK(parse::IsPlaceholderNode(ph));

        std::vector<parse::SubscriptionRecord> sr = {{"s1", "Sub One", "Remote One", "https://sub.test", "", {}, true, 1, 1000, "", ui}};
        auto sr_rt = store::DeserializeSubscriptionsJson(store::SerializeSubscriptionsJson(sr));
        YUMI_CHECK(sr_rt.has_value() && sr_rt->size() == 1 && (*sr_rt)[0].name == "Sub One");

        std::vector<ProxyNode> nv = {*n_vless, *n_hy2};
        auto nv_rt = store::DeserializeNodesJson(store::SerializeNodesJson(nv));
        YUMI_CHECK(nv_rt.has_value() && nv_rt->size() == 2 && (*nv_rt)[1].hysteria2.obfs_type == "salamander");
    }

    // 20. GeoSite/GeoIP Protobuf Extractor + rules.bin Compiler + Live BasicRouter
    YUMI_TEST("rules_bin_geosite_geoip_compiler_and_router");
    {
        auto pb_str = [](uint32_t fnum, std::string_view val) {
            std::vector<uint8_t> out;
            out.push_back(static_cast<uint8_t>((fnum << 3) | 2));
            size_t len = val.size();
            while (len >= 0x80) { out.push_back(static_cast<uint8_t>((len & 0x7Fu) | 0x80u)); len >>= 7; }
            out.push_back(static_cast<uint8_t>(len));
            out.insert(out.end(), val.begin(), val.end());
            return out;
        };
        auto pb_bytes = [](uint32_t fnum, const std::vector<uint8_t>& val) {
            std::vector<uint8_t> out;
            out.push_back(static_cast<uint8_t>((fnum << 3) | 2));
            size_t len = val.size();
            while (len >= 0x80) { out.push_back(static_cast<uint8_t>((len & 0x7Fu) | 0x80u)); len >>= 7; }
            out.push_back(static_cast<uint8_t>(len));
            out.insert(out.end(), val.begin(), val.end());
            return out;
        };

        // GeoSite Domain(type=RootDomain(2), value="gosuslugi.ru") inside GeoSite(country="CATEGORY-RU")
        std::vector<uint8_t> dom_msg = {0x08, 0x02};
        auto v_dom = pb_str(2, "gosuslugi.ru");
        dom_msg.insert(dom_msg.end(), v_dom.begin(), v_dom.end());
        auto site_entry = pb_str(1, "CATEGORY-RU");
        auto dom_wrap = pb_bytes(2, dom_msg);
        site_entry.insert(site_entry.end(), dom_wrap.begin(), dom_wrap.end());
        auto geosite_blob = pb_bytes(1, site_entry);

        // GeoIP CIDR(ip=77.88.55.0, prefix=24) inside GeoIP(country="RU")
        std::vector<uint8_t> cidr_msg = {0x0A, 0x04, 77, 88, 55, 0, 0x10, 24};
        auto geoip_entry = pb_str(1, "RU");
        auto cidr_wrap = pb_bytes(2, cidr_msg);
        geoip_entry.insert(geoip_entry.end(), cidr_wrap.begin(), cidr_wrap.end());
        auto geoip_blob = pb_bytes(1, geoip_entry);

        AppSettings rcfg;
        rcfg.routing_mode = RoutingMode::Rules;
        rcfg.block_quic = true;
        rcfg.bypass_lan = true;
        rcfg.custom_rules.proxy = {"domain:youtube.com"};
        rcfg.custom_rules.direct = {"geosite:category-ru", "geoip:ru"};
        rcfg.custom_rules.block = {"ads.bad.example"};

        const auto idx = rules::CompileRulesIndex(rcfg, &geosite_blob, &geoip_blob);
        const auto bin = rules::SerializeRulesBin(idx);
        const auto dec_idx = rules::DeserializeRulesBin(bin);
        YUMI_CHECK(dec_idx.has_value());

        net::BasicRouter router;
        router.SetRulesIndex(*dec_idx);
        YUMI_CHECK(router.Decide({"www.youtube.com", 443, true, 0}, rcfg) == net::RouteAction::Block);
        YUMI_CHECK(router.Decide({"www.youtube.com", 443, false, 0}, rcfg) == net::RouteAction::Proxy);
        YUMI_CHECK(router.Decide({"portal.gosuslugi.ru", 443, false, 0}, rcfg) == net::RouteAction::Direct);
        YUMI_CHECK(router.Decide({"77.88.55.80", 443, false, 0}, rcfg) == net::RouteAction::Direct);
        YUMI_CHECK(router.Decide({"tracker.ads.bad.example", 443, false, 0}, rcfg) == net::RouteAction::Block);
    }

    // 21. Pairing Protocol E2E Loopback (yumi://pair ECDH P-256 + AES-256-GCM)
    YUMI_TEST("pairing_protocol_e2e_loopback_ecdh_p256");
    {
        logic::PairingServer ps;
        bool callback_seen = false;
        std::string got_url;
        YUMI_CHECK(ps.Start("127.0.0.1", "Switch Test", true, 0, [&](const logic::SubscriptionTransfer& tr) {
            callback_seen = true;
            got_url = tr.url;
            return logic::PairingResult{true, "accepted", tr.name};
        }));
        const std::string uri = ps.ShareUrl();
        const auto parsed_uri = logic::ParsePairUri(uri);
        YUMI_CHECK(parsed_uri.valid);

        logic::SubscriptionTransfer tr;
        tr.version = 1;
        tr.name = "My Yumi Sub";
        tr.url = "https://sub.example.net/v1/abc";
        tr.user_agent_override = "YumiAndroid/2.1";
        tr.headers = {{"X-Test", "1"}};

        const auto reply = logic::SendPairingSubscription(uri, tr, 4000);
        YUMI_CHECK(reply.accepted && reply.status == "accepted" && callback_seen && got_url == tr.url);

        // Wrong host/sid rejection
        auto bad = logic::SendPairingSubscription(uri + "corrupt", tr, 1500);
        YUMI_CHECK(!bad.accepted);
        ps.Stop();
    }

    // 22. Latency Tester (TcpConnect, 3-sample Median, UrlTest, AsyncLatencyBatch)
    YUMI_TEST("latency_tester_tcp_tls_median_urltest_loopback");
    {
        net::SocketLayerInit();
        uint16_t tcp_port = 0;
        auto tcp_lst = net::NetSocket::TcpListenLoopback(tcp_port);
        YUMI_CHECK(tcp_lst.IsValid());

        uint16_t http_port = 0;
        auto http_lst = net::NetSocket::TcpListenLoopback(http_port);
        YUMI_CHECK(http_lst.IsValid());

        std::atomic<bool> stop_lat{false};
        std::thread acc_thr([&]() {
            while (!stop_lat.load()) {
                uint32_t pip = 0; uint16_t pp = 0;
                auto c1 = tcp_lst.Accept(pip, pp);
                if (c1.IsValid()) c1.Close();
                auto c2 = http_lst.Accept(pip, pp);
                if (c2.IsValid()) {
                    uint8_t buf[512];
                    (void)c2.RecvSomeBlocking(buf, sizeof(buf), 800);
                    const char resp[] = "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n";
                    c2.SendAllBlocking(resp, sizeof(resp) - 1, 800);
                    c2.Close();
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        });

        ProxyNode n1; n1.id = "lat-1"; n1.server = "127.0.0.1"; n1.port = tcp_port; n1.protocol = Protocol::Vless;
        ProxyNode n2; n2.id = "lat-2"; n2.server = "127.0.0.1"; n2.port = http_port; n2.protocol = Protocol::Direct;
        AppSettings cfg;
        const int med = logic::ProbeNodeMedianLatency(n1, cfg, logic::LatencyTestMethod::TcpConnect, 3, nullptr, 1500);
        YUMI_CHECK(med >= 1);

        // HTTP URL test direct loopback
        logic::HttpRequest hr;
        hr.url = "http://127.0.0.1:" + std::to_string(http_port) + "/generate_204";
        hr.timeout_ms = 2000;
        const auto hresp = logic::ExecuteHttpRequest(hr);
        YUMI_CHECK(hresp.ok && hresp.status_code == 204);

        logic::AsyncLatencyBatch batch;
        YUMI_CHECK(batch.Start({n1, n2}, cfg, logic::LatencyTestMethod::TcpConnect, 1, 1500, 2));
        for (int w = 0; w < 100 && batch.IsRunning(); ++w) {
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }
        batch.Stop();
        std::vector<logic::LatencyResult> lres;
        batch.DrainCompleted(lres);
        YUMI_CHECK(lres.size() == 2 && lres[0].ping_ms >= 1 && lres[1].ping_ms >= 1);

        stop_lat.store(true);
        acc_thr.join();
    }

    // 23. Global uTLS Fingerprints + FragmentMode chunked ClientHello delivery
    YUMI_TEST("utls_fingerprints_and_fragment_mode");
    {
        AppSettings cfg;
        cfg.tls_fingerprint = TlsFingerprint::Firefox;
        cfg.fragment_mode = FragmentMode::TlsHello;
        cfg.fragment_length = "20-40";
        cfg.fragment_interval = "1-2";
        cfg.fragment_max_chunks = "12";

        YUMI_CHECK(net::ResolveEffectiveFingerprint(cfg.tls_fingerprint, "chrome") == TlsFingerprint::Firefox);
        YUMI_CHECK(net::ResolveEffectiveFingerprint(TlsFingerprint::Auto, "safari") == TlsFingerprint::Safari);
        const auto frag = net::MakeFragmentConfig(cfg);
        YUMI_CHECK(frag.mode == FragmentMode::TlsHello && frag.min_len == 20 && frag.max_len == 40 && frag.max_chunks == 12);

        uint8_t priv[32]{}, rnd[32]{};
        net::crypto::RandomBytes(priv, 32);
        net::crypto::RandomBytes(rnd, 32);
        const auto ch_chrome = net::BuildTls13ClientHello("example.com", {"h2"}, priv, rnd, nullptr, 1700000000, nullptr, TlsFingerprint::Chrome);
        const auto ch_ff = net::BuildTls13ClientHello("example.com", {"h2"}, priv, rnd, nullptr, 1700000000, nullptr, TlsFingerprint::Firefox);
        YUMI_CHECK(ch_chrome.size() > 60 && ch_ff.size() > 60 && ch_chrome != ch_ff);

        uint16_t fport = 0;
        auto flist = net::NetSocket::TcpListenLoopback(fport);
        YUMI_CHECK(flist.IsValid());
        std::vector<uint8_t> reassembled;
        std::thread srv([&]() {
            net::NetSocket c;
            for (int i = 0; i < 100 && !c.IsValid(); ++i) {
                uint32_t ip = 0; uint16_t p = 0;
                c = flist.Accept(ip, p);
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            uint8_t b[512];
            while (reassembled.size() < ch_ff.size()) {
                auto r = c.RecvSomeBlocking(b, sizeof(b), 1000);
                if (r.status != net::IoStatus::Ok || r.bytes == 0) break;
                reassembled.insert(reassembled.end(), b, b + r.bytes);
            }
        });
        net::NetSocket cli;
        YUMI_CHECK(cli.ConnectExactBlocking(0x7F000001u, fport, 1500));
        YUMI_CHECK(net::SendFragmentedBlocking(cli, ch_ff.data(), ch_ff.size(), frag, 3000));
        cli.Close();
        srv.join();
        YUMI_CHECK(reassembled == ch_ff);
    }

    // 24. Transports Loopback (WebSocket, HttpUpgrade, gRPC, XHTTP)
    YUMI_TEST("transports_ws_httpupgrade_grpc_xhttp_loopback");
    {
        net::DohResolver dummy_dns;
        auto run_transport_echo = [&](TransportKind kind) -> bool {
            uint16_t tp = 0;
            auto lst = net::NetSocket::TcpListenLoopback(tp);
            if (!lst.IsValid()) return false;
            std::atomic<bool> done{false};
            std::thread srv([&]() {
                net::NetSocket c;
                for (int i = 0; i < 100 && !c.IsValid(); ++i) {
                    uint32_t ip = 0; uint16_t p = 0;
                    c = lst.Accept(ip, p);
                    std::this_thread::sleep_for(std::chrono::milliseconds(4));
                }
                if (!c.IsValid()) return;
                uint8_t buf[2048];
                std::vector<uint8_t> acc;
                if (kind == TransportKind::WebSocket || kind == TransportKind::HttpUpgrade) {
                    while (!done.load()) {
                        auto r = c.RecvSomeBlocking(buf, sizeof(buf), 800);
                        if (r.status != net::IoStatus::Ok || r.bytes == 0) break;
                        acc.insert(acc.end(), buf, buf + r.bytes);
                        std::string s(acc.begin(), acc.end());
                        size_t eoh = s.find("\r\n\r\n");
                        if (eoh != std::string::npos) {
                            const char ok101[] = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
                            c.SendAllBlocking(ok101, sizeof(ok101) - 1, 800);
                            acc.erase(acc.begin(), acc.begin() + static_cast<ptrdiff_t>(eoh + 4));
                            break;
                        }
                    }
                    if (kind == TransportKind::HttpUpgrade) {
                        while (!done.load()) {
                            if (!acc.empty()) { c.SendAllBlocking(acc.data(), acc.size(), 800); acc.clear(); }
                            auto r = c.RecvSomeBlocking(buf, sizeof(buf), 200);
                            if (r.status == net::IoStatus::Ok && r.bytes > 0) acc.insert(acc.end(), buf, buf + r.bytes);
                            else if (r.status == net::IoStatus::Eof || r.status == net::IoStatus::Error) break;
                        }
                    } else {
                        while (!done.load()) {
                            if (acc.size() >= 6) {
                                size_t plen = acc[1] & 0x7Fu;
                                if (acc.size() >= 6 + plen) {
                                    std::vector<uint8_t> rep = {0x82, static_cast<uint8_t>(plen)};
                                    for (size_t k = 0; k < plen; ++k) rep.push_back(acc[6 + k] ^ acc[2 + (k & 3)]);
                                    c.SendAllBlocking(rep.data(), rep.size(), 800);
                                    acc.erase(acc.begin(), acc.begin() + static_cast<ptrdiff_t>(6 + plen));
                                    continue;
                                }
                            }
                            auto r = c.RecvSomeBlocking(buf, sizeof(buf), 200);
                            if (r.status == net::IoStatus::Ok && r.bytes > 0) acc.insert(acc.end(), buf, buf + r.bytes);
                            else if (r.status == net::IoStatus::Eof || r.status == net::IoStatus::Error) break;
                        }
                    }
                } else if (kind == TransportKind::Grpc) {
                    // Read client H2 preface + SETTINGS + HEADERS, send empty server SETTINGS, then echo DATA frames 1:1
                    std::vector<uint8_t> h2_pre = {0,0,0, 0x04, 0x00, 0,0,0,0};
                    c.SendAllBlocking(h2_pre.data(), h2_pre.size(), 800);
                    while (!done.load()) {
                        auto r = c.RecvSomeBlocking(buf, sizeof(buf), 200);
                        if (r.status == net::IoStatus::Ok && r.bytes > 0) {
                            acc.insert(acc.end(), buf, buf + r.bytes);
                            if (acc.size() >= 24 && std::memcmp(acc.data(), "PRI * HTTP/2.0", 14) == 0) {
                                acc.erase(acc.begin(), acc.begin() + 24);
                            }
                            while (acc.size() >= 9 && (acc.size() - 9) >= ((uint32_t(acc[0])<<16)|(uint32_t(acc[1])<<8)|acc[2])) {
                                size_t fl = (size_t(acc[0])<<16)|(size_t(acc[1])<<8)|acc[2];
                                if (acc[3] == 0x00) {
                                    c.SendAllBlocking(acc.data(), 9 + fl, 800);
                                }
                                acc.erase(acc.begin(), acc.begin() + static_cast<ptrdiff_t>(9 + fl));
                            }
                        } else if (r.status == net::IoStatus::Eof || r.status == net::IoStatus::Error) break;
                    }
                } else {  // XHTTP
                    const char ok200[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
                    c.SendAllBlocking(ok200, sizeof(ok200) - 1, 800);
                    bool eoh_done = false;
                    while (!done.load()) {
                        auto r = c.RecvSomeBlocking(buf, sizeof(buf), 200);
                        if (r.status == net::IoStatus::Ok && r.bytes > 0) {
                            acc.insert(acc.end(), buf, buf + r.bytes);
                            if (!eoh_done) {
                                std::string s(acc.begin(), acc.end());
                                size_t p = s.find("\r\n\r\n");
                                if (p != std::string::npos) {
                                    acc.erase(acc.begin(), acc.begin() + static_cast<ptrdiff_t>(p + 4));
                                    eoh_done = true;
                                }
                            }
                            if (eoh_done && !acc.empty()) {
                                c.SendAllBlocking(acc.data(), acc.size(), 800);
                                acc.clear();
                            }
                        } else if (r.status == net::IoStatus::Eof || r.status == net::IoStatus::Error) break;
                    }
                }
            });

            ProxyNode tn;
            tn.server = "127.0.0.1";
            tn.port = tp;
            tn.tls.enabled = false;
            tn.transport.kind = kind;
            tn.transport.path = "/tunnel";
            tn.transport.service_name = "Tun";

            net::TransportPipeline pipe;
            bool ok = pipe.Connect(tn, {}, dummy_dns, 2500, false);
            if (ok) {
                const uint8_t msg[] = "YumiTransport!";
                ok = pipe.WriteBlocking(msg, sizeof(msg) - 1, 2000);
                std::string got;
                uint8_t rx[64];
                for (int w = 0; w < 60 && got.size() < sizeof(msg) - 1; ++w) {
                    auto rr = pipe.ReadNonBlocking(rx, sizeof(rx));
                    if (rr.status == net::IoStatus::Ok && rr.bytes > 0) {
                        got.append(reinterpret_cast<const char*>(rx), rr.bytes);
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
                ok = ok && (got == "YumiTransport!");
            }
            done.store(true);
            pipe.Close();
            srv.join();
            return ok;
        };

        YUMI_CHECK(run_transport_echo(TransportKind::WebSocket));
        YUMI_CHECK(run_transport_echo(TransportKind::HttpUpgrade));
        YUMI_CHECK(run_transport_echo(TransportKind::Grpc));
        YUMI_CHECK(run_transport_echo(TransportKind::Xhttp));
    }

    // 25. Shadowsocks (AEAD + 2022 BLAKE3) & Trojan E2E Dialers
    YUMI_TEST("dialers_shadowsocks_aead_2022_and_trojan_e2e");
    {
        net::DohResolver dummy_dns;
        // 25a. Trojan request wire + loopback echo
        const auto tr_hdr = net::EncodeTrojanRequestHeader("my-trojan-pw", "127.0.0.1", 443);
        uint8_t tr_digest[28]{};
        net::crypto::Sha224::Digest("my-trojan-pw", 12, tr_digest);
        const std::string tr_hex = net::crypto::HexEncode(tr_digest, 28);
        YUMI_CHECK(tr_hdr.size() > 64 && std::memcmp(tr_hdr.data(), tr_hex.data(), 56) == 0);

        uint16_t tr_port = 0;
        auto tr_lst = net::NetSocket::TcpListenLoopback(tr_port);
        YUMI_CHECK(tr_lst.IsValid());
        std::thread tr_srv([&]() {
            net::NetSocket c;
            for (int i = 0; i < 100 && !c.IsValid(); ++i) {
                uint32_t ip = 0; uint16_t p = 0;
                c = tr_lst.Accept(ip, p);
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            std::vector<uint8_t> rx;
            uint8_t buf[256];
            while (rx.size() < tr_hdr.size() + 4) {
                auto r = c.RecvSomeBlocking(buf, sizeof(buf), 1200);
                if (r.status != net::IoStatus::Ok || r.bytes == 0) break;
                rx.insert(rx.end(), buf, buf + r.bytes);
            }
            if (rx.size() >= tr_hdr.size() + 4) {
                c.SendAllBlocking(rx.data() + tr_hdr.size(), 4, 1000);
            }
        });
        ProxyNode tr_node;
        tr_node.protocol = Protocol::Trojan;
        tr_node.server = "127.0.0.1";
        tr_node.port = tr_port;
        tr_node.password_or_key = "my-trojan-pw";
        tr_node.tls.enabled = false;
        auto tr_stream = net::CreateOutboundStream(tr_node, {});
        YUMI_CHECK(tr_stream && tr_stream->Kind() == Protocol::Trojan);
        YUMI_CHECK(tr_stream->Connect({"127.0.0.1", 443, false, 0}, dummy_dns, 2000));
        YUMI_CHECK(tr_stream->WriteNonBlocking(reinterpret_cast<const uint8_t*>("PING"), 4).status == net::IoStatus::Ok);
        std::string tr_got;
        for (int w = 0; w < 50 && tr_got.size() < 4; ++w) {
            uint8_t b[16];
            auto rr = tr_stream->ReadNonBlocking(b, sizeof(b));
            if (rr.status == net::IoStatus::Ok) tr_got.append(reinterpret_cast<const char*>(b), rr.bytes);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        YUMI_CHECK(tr_got == "PING");
        tr_stream->Close();
        tr_srv.join();

        // 25b. Shadowsocks 2022-blake3-aes-128-gcm E2E loopback
        uint8_t psk[16]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        const std::string psk_b64 = net::crypto::Base64Encode(psk, 16);
        uint16_t ss_port = 0;
        auto ss_lst = net::NetSocket::TcpListenLoopback(ss_port);
        YUMI_CHECK(ss_lst.IsValid());
        std::thread ss_srv([&]() {
            net::NetSocket c;
            for (int i = 0; i < 100 && !c.IsValid(); ++i) {
                uint32_t ip = 0; uint16_t p = 0;
                c = ss_lst.Accept(ip, p);
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
            uint8_t buf[512];
            std::vector<uint8_t> rx;
            while (rx.size() < 16 + 11 + 16 + 9 + 16) {
                auto r = c.RecvSomeBlocking(buf, sizeof(buf), 1200);
                if (r.status != net::IoStatus::Ok || r.bytes == 0) return;
                rx.insert(rx.end(), buf, buf + r.bytes);
            }
            uint8_t cli_salt[16]; std::memcpy(cli_salt, rx.data(), 16);
            uint8_t cli_sub[32]{};
            net::DeriveSsSubkey(net::SsCipher::Ss2022Aes128Gcm, psk_b64, cli_salt, 16, cli_sub);

            uint8_t srv_salt[16]{}; net::crypto::RandomBytes(srv_salt, 16);
            uint8_t srv_sub[32]{};
            net::DeriveSsSubkey(net::SsCipher::Ss2022Aes128Gcm, psk_b64, srv_salt, 16, srv_sub);

            std::vector<uint8_t> reply;
            reply.insert(reply.end(), srv_salt, srv_salt + 16);
            // Response fixed header: [1(1)] [ts(8)] [req_salt(16)] [init_len=0(2)] -> 27 bytes
            uint8_t rfh[27]{}; rfh[0] = 0x01; std::memcpy(rfh + 9, cli_salt, 16);
            uint8_t n0[12]{}, ct[32], tag[16];
            net::crypto::AesGcmEncrypt(srv_sub, 16, n0, nullptr, 0, rfh, 27, ct, tag);
            reply.insert(reply.end(), ct, ct + 27);
            reply.insert(reply.end(), tag, tag + 16);

            // AEAD chunk ("SS22")
            uint8_t len2[2] = {0, 4}, lct[2], ltag[16], pct[4], ptag[16];
            uint8_t n1[12]{1}, n2[12]{2};
            net::crypto::AesGcmEncrypt(srv_sub, 16, n1, nullptr, 0, len2, 2, lct, ltag);
            net::crypto::AesGcmEncrypt(srv_sub, 16, n2, nullptr, 0, reinterpret_cast<const uint8_t*>("SS22"), 4, pct, ptag);
            reply.insert(reply.end(), lct, lct + 2); reply.insert(reply.end(), ltag, ltag + 16);
            reply.insert(reply.end(), pct, pct + 4); reply.insert(reply.end(), ptag, ptag + 16);
            c.SendAllBlocking(reply.data(), reply.size(), 1000);
        });

        ProxyNode ss_node;
        ss_node.protocol = Protocol::Shadowsocks;
        ss_node.server = "127.0.0.1";
        ss_node.port = ss_port;
        ss_node.method = "2022-blake3-aes-128-gcm";
        ss_node.password_or_key = psk_b64;
        auto ss_stream = net::CreateOutboundStream(ss_node, {});
        YUMI_CHECK(ss_stream && ss_stream->Kind() == Protocol::Shadowsocks);
        YUMI_CHECK(ss_stream->Connect({"127.0.0.1", 80, false, 0}, dummy_dns, 2000));
        std::string ss_got;
        for (int w = 0; w < 60 && ss_got.size() < 4; ++w) {
            uint8_t b[16];
            auto rr = ss_stream->ReadNonBlocking(b, sizeof(b));
            if (rr.status == net::IoStatus::Ok) ss_got.append(reinterpret_cast<const char*>(b), rr.bytes);
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        YUMI_CHECK(ss_got == "SS22");
        ss_stream->Close();
        ss_srv.join();
    }

    // 26. VMess AEAD + Hysteria2 QUIC v1 Initial & Salamander Wire Codecs
    YUMI_TEST("dialer_vmess_aead_and_hysteria2_quic_salamander");
    {
        uint8_t uuid[16]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        uint8_t cmd_key[16]{};
        net::DeriveVmessCmdKey(uuid, cmd_key);
        const uint8_t nonce8[8]{1,2,3,4,5,6,7,8};
        const uint8_t req_iv[16]{9,8,7,6,5,4,3,2,1,0,1,2,3,4,5,6};
        const uint8_t req_key[16]{6,5,4,3,2,1,0,1,2,3,4,5,6,7,8,9};
        const auto vhdr = net::EncodeVmessAeadRequestHeader(cmd_key, 1700000000ULL, nonce8, req_iv, req_key, 0x42, 3, "example.com", 443);
        YUMI_CHECK(vhdr.size() > 16 + 18 + 8 + 16);

        // QUIC varint & Initial key derivation + Hysteria2 Salamander BLAKE2b roundtrip + TCP 0x401 framing
        std::vector<uint8_t> vi;
        net::QuicEncodeVarint(vi, 0x401);
        size_t cons = 0; uint64_t val = 0;
        YUMI_CHECK(net::QuicDecodeVarint(vi.data(), vi.size(), cons, val) && cons == vi.size() && val == 0x401);

        const uint8_t dcid[8]{0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
        net::QuicLevelKeys cli_init, srv_init;
        YUMI_CHECK(net::QuicDeriveInitialKeys(dcid, 8, true, cli_init));
        YUMI_CHECK(net::QuicDeriveInitialKeys(dcid, 8, false, srv_init));
        YUMI_CHECK(cli_init.key_len == 16 && std::memcmp(cli_init.key, srv_init.key, 16) != 0);

        const uint8_t salt8[8]{11, 22, 33, 44, 55, 66, 77, 88};
        const uint8_t quic_pl[10]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
        const auto wrapped = net::Hysteria2SalamanderWrap("salamander-pw", salt8, quic_pl, sizeof(quic_pl));
        std::vector<uint8_t> unwrapped;
        YUMI_CHECK(net::Hysteria2SalamanderUnwrap("salamander-pw", wrapped.data(), wrapped.size(), unwrapped));
        YUMI_CHECK(unwrapped.size() == sizeof(quic_pl) && std::memcmp(unwrapped.data(), quic_pl, sizeof(quic_pl)) == 0);

        const auto h2_req = net::Hysteria2EncodeTcpRequest("127.0.0.1:443", 4);
        YUMI_CHECK(h2_req.size() > 16 && h2_req[0] == 0x44 && h2_req[1] == 0x01);

        ProxyNode vm_n; vm_n.protocol = Protocol::Vmess; vm_n.uuid_or_user = "11111111-2222-3333-4444-555555555555";
        ProxyNode hy_n; hy_n.protocol = Protocol::Hysteria2; hy_n.password_or_key = "pw";
        YUMI_CHECK(net::CreateOutboundStream(vm_n, {})->Kind() == Protocol::Vmess);
        YUMI_CHECK(net::CreateOutboundStream(hy_n, {})->Kind() == Protocol::Hysteria2);
    }

    // 27. Yumi Remote Protocol E2E: UDP Beacon + QR Pair + Trusted Resume + Commands
    YUMI_TEST("remote_protocol_e2e_beacon_pair_resume_and_commands");
    {
        logic::RemoteServer rs;
        YUMI_CHECK(rs.Start("127.0.0.1", "", "Switch Lab", true, 0));
        logic::RemoteBeacon rb;
        YUMI_CHECK(rb.Start(rs.HostId(), rs.HostName(), rs.Port(), true, 0));

        const auto sighting = logic::ProbeRemoteBeacon(0x7F000001u, rb.BoundPort(), 1200);
        YUMI_CHECK(sighting.valid && sighting.host_id == rs.HostId() && sighting.port == rs.Port());

        logic::RemoteHostSnapshot snap;
        snap.host_name = "Switch Lab";
        snap.state = "On";
        snap.selected_node_id = "fi1";
        snap.nodes.push_back({"fi1", "Finland #1", "Sub", 31, false, Protocol::Vless, {"REALITY"}, "s1"});
        rs.SetSnapshot(snap);

        const std::string invite = rs.ShareUrl();
        const auto inv_parsed = logic::ParseRemoteInviteUri(invite);
        YUMI_CHECK(inv_parsed.valid);

        const auto bond = logic::RemoteClientPair(invite, "Pixel 9 Pro XL", 3000);
        YUMI_CHECK(bond.valid && !bond.peer_id.empty() && !bond.secret.empty());
        YUMI_CHECK(rs.TrustedPeerCount() == 1);

        // Resumed session without QR code + command roundtrip
        std::vector<std::string> rx_snaps;
        YUMI_CHECK(logic::RemoteClientSessionExchange(
            bond, 0x7F000001u, rs.Port(), "Pixel 9 Pro XL",
            {R"({"type":"look"})", R"({"type":"update_settings","patch":{"routingMode":"Global","blockQuic":true}})"},
            rx_snaps, 2000));
        YUMI_CHECK(!rx_snaps.empty() && rx_snaps[0].find("Switch Lab") != std::string::npos);

        std::vector<logic::RemoteCommand> cmds;
        rs.DrainCommands(cmds);
        YUMI_CHECK(cmds.size() >= 2 && cmds.back().type == logic::RemoteCommand::Type::UpdateSettings);
        AppSettings patched;
        patched.routing_mode = RoutingMode::Direct;
        YUMI_CHECK(logic::ApplyRemoteSettingsPatch(cmds.back().settings_patch_json, patched));
        YUMI_CHECK(patched.routing_mode == RoutingMode::Global && patched.block_quic);

        rb.Stop();
        rs.Stop();
    }

    // 28. SpeedTest & GitHub UpdateChecker Codecs + Loopback E2E
    YUMI_TEST("speed_test_and_update_checker_codecs");
    {
        YUMI_CHECK(logic::CompareSemVer("v0.4.0", "0.3.1") > 0);
        YUMI_CHECK(logic::CompareSemVer("0.3.1", "v0.3.1") == 0);
        YUMI_CHECK(logic::CompareSemVer("0.3.0", "0.3.1") < 0);

        const std::string gh_json =
            R"({"tag_name":"v0.4.2","body":"New release","assets":[{"name":"yumi.nro","size":1234,"browser_download_url":"https://example.com/yumi.nro"}]})";
        const auto parsed_rel = logic::ParseGitHubReleaseJson(gh_json, "0.3.1", ".nro");
        YUMI_CHECK(parsed_rel.check_ok && parsed_rel.update_available &&
                   parsed_rel.latest_version == "0.4.2" && parsed_rel.asset_name == "yumi.nro");

        // Loopback HTTP server for SpeedTest & atomic Download
        uint16_t sp_port = 0;
        auto sp_lst = net::NetSocket::TcpListenLoopback(sp_port);
        YUMI_CHECK(sp_lst.IsValid());
        std::atomic<bool> sp_stop{false};
        std::thread sp_srv([&]() {
            while (!sp_stop.load()) {
                uint32_t ip = 0; uint16_t p = 0;
                auto c = sp_lst.Accept(ip, p);
                if (!c.IsValid()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    continue;
                }
                std::string hdr;
                uint8_t b[4096];
                while (true) {
                    auto r = c.RecvSomeBlocking(b, sizeof(b), 500);
                    if (r.status != net::IoStatus::Ok || r.bytes == 0) break;
                    hdr.append(reinterpret_cast<const char*>(b), r.bytes);
                    if (hdr.find("\r\n\r\n") != std::string::npos) {
                        if (hdr.rfind("GET /dl", 0) == 0) {
                            std::string body(131072, 'Z');
                            std::string rep = "HTTP/1.1 200 OK\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
                            c.SendAllBlocking(rep.data(), rep.size(), 1500);
                        } else if (hdr.rfind("GET /rel", 0) == 0) {
                            const char rep[] = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nNRO!";
                            c.SendAllBlocking(rep, sizeof(rep) - 1, 1000);
                        } else {
                            const char rep[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                            c.SendAllBlocking(rep, sizeof(rep) - 1, 1000);
                        }
                        break;
                    }
                }
                c.Close();
            }
        });

        logic::SpeedTestConfig scfg;
        scfg.download_url = "http://127.0.0.1:" + std::to_string(sp_port) + "/dl";
        scfg.upload_url = "http://127.0.0.1:" + std::to_string(sp_port) + "/up";
        scfg.upload_bytes = 32768;
        scfg.timeout_ms = 3000;
        const auto sres = logic::RunSpeedTestSync(scfg);
        YUMI_CHECK(sres.ok && sres.download_mbps > 0.0 && sres.upload_mbps > 0.0);

        const std::string tmp_dl = "yumi_test_dl_artifact.tmp";
        logic::HttpRequest dl_req;
        dl_req.url = "http://127.0.0.1:" + std::to_string(sp_port) + "/rel";
        dl_req.timeout_ms = 2000;
        const auto dl_resp = logic::DownloadHttpFileAtomic(dl_req, tmp_dl);
        YUMI_CHECK(dl_resp.ok && dl_resp.status_code == 200);
        const auto dl_txt = store::ReadTextFile(tmp_dl);
        YUMI_CHECK(dl_txt.has_value() && *dl_txt == "NRO!");
        std::error_code ec;
        std::filesystem::remove(tmp_dl, ec);

        sp_stop.store(true);
        sp_srv.join();
    }

    std::printf("ALL %d UNIT TESTS PASSED\n", g_tests_run);
    return 0;
}
