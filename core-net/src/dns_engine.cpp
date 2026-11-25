#include "yumi_nx/dns_engine.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

#include "yumi_nx/crypto.hpp"
#include "yumi_nx/socket_io.hpp"
#include "yumi_nx/tls13_reality.hpp"

namespace yumi_nx::net {

namespace {

inline uint16_t ReadBe16(const uint8_t* p) noexcept {
    return static_cast<uint16_t>((uint16_t(p[0]) << 8) | p[1]);
}
inline uint32_t ReadBe32(const uint8_t* p) noexcept {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}
inline void WriteBe16(uint8_t* p, uint16_t v) noexcept {
    p[0] = uint8_t(v >> 8);
    p[1] = uint8_t(v);
}
inline void WriteBe32(uint8_t* p, uint32_t v) noexcept {
    p[0] = uint8_t(v >> 24);
    p[1] = uint8_t(v >> 16);
    p[2] = uint8_t(v >> 8);
    p[3] = uint8_t(v);
}
inline void WriteLe16(uint8_t* p, uint16_t v) noexcept {
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
}
inline void WriteLe32(uint8_t* p, uint32_t v) noexcept {
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
    p[2] = uint8_t(v >> 16);
    p[3] = uint8_t(v >> 24);
}

std::string LowerAscii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

bool SkipDnsName(const uint8_t* pkt, size_t len, size_t& io_off) noexcept {
    int jumps = 0;
    size_t pos = io_off;
    bool jumped = false;
    while (pos < len) {
        const uint8_t c = pkt[pos];
        if (c == 0) {
            if (!jumped) io_off = pos + 1;
            return true;
        }
        if ((c & 0xC0u) == 0xC0u) {
            if (pos + 1 >= len) return false;
            if (!jumped) io_off = pos + 2;
            const size_t ptr = (static_cast<size_t>(c & 0x3Fu) << 8) | pkt[pos + 1];
            if (ptr >= len || ++jumps > 16) return false;
            pos = ptr;
            jumped = true;
        } else {
            const size_t adv = 1u + static_cast<size_t>(c);
            if (pos + adv > len) return false;
            pos += adv;
        }
    }
    return false;
}

bool ParseHttpsUrl(std::string_view url, std::string& out_host, uint16_t& out_port, std::string& out_path) {
    out_host.clear();
    out_port = 443;
    out_path = "/dns-query";
    if (url.starts_with("https://")) url.remove_prefix(8);
    else if (url.starts_with("http://")) url.remove_prefix(7);
    if (url.empty()) return false;
    const size_t slash = url.find('/');
    std::string_view hp = (slash == std::string_view::npos) ? url : url.substr(0, slash);
    if (slash != std::string_view::npos) {
        out_path = std::string(url.substr(slash));
        if (out_path.empty()) out_path = "/";
    }
    const size_t colon = hp.rfind(':');
    if (colon != std::string_view::npos) {
        out_host = std::string(hp.substr(0, colon));
        uint32_t p = 0;
        for (char c : hp.substr(colon + 1)) {
            if (c < '0' || c > '9') {
                p = 0;
                break;
            }
            p = p * 10u + static_cast<uint32_t>(c - '0');
        }
        if (p >= 1 && p <= 65535) out_port = static_cast<uint16_t>(p);
    } else {
        out_host = std::string(hp);
    }
    return !out_host.empty();
}

bool ExtractHttpBody(const std::vector<uint8_t>& raw, std::vector<uint8_t>& out_body) {
    out_body.clear();
    const char* data = reinterpret_cast<const char*>(raw.data());
    const std::string_view sv(data, raw.size());
    const size_t hdr_end = sv.find("\r\n\r\n");
    if (hdr_end == std::string_view::npos) return false;
    const std::string hdr_lower = LowerAscii(sv.substr(0, hdr_end));
    const size_t body_start = hdr_end + 4;
    if (hdr_lower.find("transfer-encoding: chunked") != std::string::npos) {
        size_t pos = body_start;
        while (pos < raw.size()) {
            const size_t line_end = sv.find("\r\n", pos);
            if (line_end == std::string_view::npos) break;
            size_t chunk_sz = 0;
            for (size_t i = pos; i < line_end; ++i) {
                char c = sv[i];
                if (c == ';') break;
                int v = -1;
                if (c >= '0' && c <= '9') v = c - '0';
                else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
                if (v < 0) break;
                chunk_sz = (chunk_sz << 4) | static_cast<size_t>(v);
            }
            pos = line_end + 2;
            if (chunk_sz == 0) return !out_body.empty();
            if (pos + chunk_sz > raw.size()) break;
            out_body.insert(out_body.end(), raw.begin() + static_cast<ptrdiff_t>(pos),
                            raw.begin() + static_cast<ptrdiff_t>(pos + chunk_sz));
            pos += chunk_sz + 2;
        }
        return !out_body.empty();
    }

    out_body.assign(raw.begin() + static_cast<ptrdiff_t>(body_start), raw.end());
    return !out_body.empty();
}

}  // namespace

std::vector<uint8_t> BuildDnsQueryA(std::string_view host, uint16_t txid) noexcept {
    std::vector<uint8_t> pkt;
    pkt.reserve(32 + host.size());
    pkt.resize(12, 0);
    WriteBe16(pkt.data(), txid);
    WriteBe16(pkt.data() + 2, 0x0100u);  // Standard query, RD=1
    WriteBe16(pkt.data() + 4, 1);        // QDCOUNT = 1

    size_t start = 0;
    while (start < host.size()) {
        size_t dot = host.find('.', start);
        if (dot == std::string_view::npos) dot = host.size();
        const size_t lbl_len = dot - start;
        if (lbl_len == 0 || lbl_len > 63) break;
        pkt.push_back(static_cast<uint8_t>(lbl_len));
        pkt.insert(pkt.end(), host.begin() + static_cast<ptrdiff_t>(start),
                   host.begin() + static_cast<ptrdiff_t>(dot));
        start = dot + 1;
    }
    pkt.push_back(0);     // Root label
    pkt.push_back(0); pkt.push_back(1);  // QTYPE = A (1)
    pkt.push_back(0); pkt.push_back(1);  // QCLASS = IN (1)
    return pkt;
}

bool ParseDnsResponseA(const uint8_t* pkt, size_t len, uint32_t& out_ipv4_host, uint32_t& out_ttl_sec) noexcept {
    out_ipv4_host = 0;
    out_ttl_sec = 60;
    if (!pkt || len < 12) return false;
    const uint16_t flags = ReadBe16(pkt + 2);
    if ((flags & 0x8000u) == 0 || (flags & 0x000Fu) != 0) return false;  // Not response or RCODE != 0
    const uint16_t qdcount = ReadBe16(pkt + 4);
    const uint16_t ancount = ReadBe16(pkt + 6);
    if (ancount == 0) return false;

    size_t off = 12;
    for (uint16_t q = 0; q < qdcount; ++q) {
        if (!SkipDnsName(pkt, len, off)) return false;
        if (off + 4 > len) return false;
        off += 4;
    }

    for (uint16_t a = 0; a < ancount; ++a) {
        if (!SkipDnsName(pkt, len, off)) return false;
        if (off + 10 > len) return false;
        const uint16_t type = ReadBe16(pkt + off);
        const uint16_t cls = ReadBe16(pkt + off + 2);
        const uint32_t ttl = ReadBe32(pkt + off + 4);
        const uint16_t rdlen = ReadBe16(pkt + off + 8);
        off += 10;
        if (off + rdlen > len) return false;
        if (type == 1 && cls == 1 && rdlen == 4) {
            out_ipv4_host = ReadBe32(pkt + off);
            out_ttl_sec = std::clamp<uint32_t>(ttl, 15u, 3600u);
            return out_ipv4_host != 0;
        }
        off += rdlen;
    }
    return false;
}

void DnsCache::Put(std::string_view host, uint32_t ipv4_host, uint32_t ttl_sec, uint64_t now_ms) noexcept {
    if (host.empty() || ipv4_host == 0) return;
    std::string key = LowerAscii(host);
    const uint64_t exp = now_ms + static_cast<uint64_t>(std::clamp<uint32_t>(ttl_sec, 10u, 3600u)) * 1000ULL;
    for (auto& e : entries_) {
        if (e.valid && e.host == key) {
            e.ipv4_host = ipv4_host;
            e.expires_ms = exp;
            return;
        }
    }
    entries_[cursor_] = {true, std::move(key), ipv4_host, exp};
    cursor_ = (cursor_ + 1) % kCapacity;
}

bool DnsCache::Get(std::string_view host, uint64_t now_ms, uint32_t& out_ipv4_host) const noexcept {
    const std::string key = LowerAscii(host);
    for (const auto& e : entries_) {
        if (e.valid && e.host == key && now_ms < e.expires_ms) {
            out_ipv4_host = e.ipv4_host;
            return true;
        }
    }
    return false;
}

void DnsCache::Clear() noexcept {
    for (auto& e : entries_) e = {};
    cursor_ = 0;
}

uint32_t FakeIpPool::Allocate(std::string_view host) noexcept {
    if (host.empty()) return 0;
    const std::string key = LowerAscii(host);
    for (const auto& s : slots_) {
        if (s.used && s.host == key) return s.ipv4_host;
    }
    const uint32_t idx = (next_seq_ - 1u) % static_cast<uint32_t>(kCapacity);
    // Avoid .0 and .255 on final octet: map seq to 198.18.<hi>.<1..254>
    const uint32_t hi = ((next_seq_ - 1u) / 254u) & 0xFFu;
    const uint32_t lo = ((next_seq_ - 1u) % 254u) + 1u;
    const uint32_t ip_host = 0xC6120000u | (hi << 8) | lo;
    slots_[idx] = {true, ip_host, key};
    ++next_seq_;
    return ip_host;
}

bool FakeIpPool::Lookup(uint32_t ipv4_host, std::string& out_host) const noexcept {
    if (!IsFakeIp(ipv4_host)) return false;
    for (const auto& s : slots_) {
        if (s.used && s.ipv4_host == ipv4_host) {
            out_host = s.host;
            return true;
        }
    }
    return false;
}

void FakeIpPool::Clear() noexcept {
    for (auto& s : slots_) s = {};
    next_seq_ = 1;
}

size_t SerializeSfdnsresAddrInfoIPv4(uint32_t ipv4_host,
                                     uint16_t port_host,
                                     int32_t socktype,
                                     int32_t protocol,
                                     std::string_view canonname,
                                     uint8_t* out_buf,
                                     size_t out_cap) noexcept {
    // Wait: libnx _resolverDeserializeAddrinfo memcpy() copies 128B (sizeof(sockaddr_storage)) starting at +24,
    // advancing cursor by (24 + ntohl(ai_addrlen) + canonlen). Keep minimum padding safely within out_cap.
    const size_t name_bytes = canonname.empty() ? 1u : (canonname.size() + 1u);
    const size_t rec_len = 24u + 16u + name_bytes;
    const size_t total = rec_len + 4u;
    const size_t clear_len = std::min<size_t>(out_cap, std::max<size_t>(total, 160u));
    if (!out_buf || out_cap < total) return 0;

    std::memset(out_buf, 0, clear_len);
    // Magic 0xBEEFCAFE
    out_buf[0] = 0xBE;
    out_buf[1] = 0xEF;
    out_buf[2] = 0xCA;
    out_buf[3] = 0xFE;
    WriteBe32(out_buf + 4, 0);                                 // ai_flags
    WriteBe32(out_buf + 8, 2);                                 // ai_family = AF_INET
    WriteBe32(out_buf + 12, static_cast<uint32_t>(socktype));  // ai_socktype
    WriteBe32(out_buf + 16, static_cast<uint32_t>(protocol));  // ai_protocol
    WriteBe32(out_buf + 20, 16);                               // ai_addrlen = 16

    // Horizon OS sfdnsres sockaddr_in inside getaddrinfo: libnx calls rev16(sin_port) & rev(sin_addr),
    // expecting little-endian u16 port & little-endian u32 IPv4 in serialized bytes [24..39].
    out_buf[24] = 16;  // sin_len
    out_buf[25] = 2;   // sin_family = AF_INET
    WriteLe16(out_buf + 26, port_host);
    WriteLe32(out_buf + 28, ipv4_host);

    if (!canonname.empty()) {
        std::memcpy(out_buf + 40, canonname.data(), canonname.size());
        out_buf[40 + canonname.size()] = '\0';
    } else {
        out_buf[40] = '\0';
    }
    WriteBe32(out_buf + rec_len, 0);  // End-of-list marker (0x00000000)
    return total;
}

size_t SerializeSfdnsresHostentIPv4(std::string_view host,
                                    uint32_t ipv4_host,
                                    uint8_t* out_buf,
                                    size_t out_cap) noexcept {
    const size_t name_len = host.size() + 1u;
    const size_t total = name_len + 4u + 2u + 2u + 4u + 4u;
    if (!out_buf || out_cap < total) return 0;

    std::memset(out_buf, 0, total);
    if (!host.empty()) std::memcpy(out_buf, host.data(), host.size());
    out_buf[host.size()] = '\0';
    size_t off = name_len;
    WriteBe32(out_buf + off, 0);          // alias count = 0
    off += 4;
    WriteBe16(out_buf + off, 2);          // AF_INET
    off += 2;
    WriteBe16(out_buf + off, 4);          // addr len = 4
    off += 2;
    WriteBe32(out_buf + off, 1);          // addr count = 1
    off += 4;
    WriteLe32(out_buf + off, ipv4_host);  // libnx _resolverDeserializeHostent reverses each 4B IPv4 address
    return total;
}

bool DohResolver::QueryUdpDns(uint32_t server_ipv4_host, const uint8_t* query, size_t query_len,
                              uint32_t& out_ipv4_host, uint32_t& out_ttl) noexcept {
    NetSocket udp = NetSocket::CreateUdp(true);
    if (!udp.IsValid()) return false;
    if (!udp.UdpSendTo(server_ipv4_host, 53, query, query_len)) return false;
    if (!WaitSingleSocket(udp.Fd(), true, false, 2000)) return false;

    uint8_t resp[1500];
    uint32_t from_ip = 0;
    uint16_t from_port = 0;
    const auto io = udp.UdpRecvFrom(resp, sizeof(resp), from_ip, from_port);
    if (io.status != IoStatus::Ok || io.bytes < 12) return false;
    return ParseDnsResponseA(resp, io.bytes, out_ipv4_host, out_ttl);
}

bool DohResolver::QueryDohHttps(const uint8_t* query, size_t query_len,
                                uint32_t& out_ipv4_host, uint32_t& out_ttl) noexcept {
    std::string doh_host;
    uint16_t doh_port = 443;
    std::string doh_path;
    const std::string_view url = settings_.resolve_doh_url.empty()
        ? std::string_view("https://1.1.1.1/dns-query")
        : std::string_view(settings_.resolve_doh_url);
    if (!ParseHttpsUrl(url, doh_host, doh_port, doh_path)) return false;

    if (!query || query_len == 0 || query_len > 4096u) return false;
    uint32_t doh_ip_host = 0;
    if (!ParseIPv4Be(doh_host, doh_ip_host)) {
        // Bootstrap DoH server hostname using direct DNS (avoids infinite DoH recursion).
        uint32_t boot_dns = 0x08080808u;
        if (!ParseIPv4Be(settings_.direct_dns, boot_dns) || boot_dns == 0) {
            boot_dns = 0x08080808u;
        }
        uint32_t boot_ttl = 60;
        const auto boot_q = BuildDnsQueryA(doh_host, 0x7102u);
        if (!QueryUdpDns(boot_dns, boot_q.data(), boot_q.size(), doh_ip_host, boot_ttl)) {
            return false;
        }
    }

    NetSocket tcp;
    if (!tcp.ConnectExactBlocking(doh_ip_host, doh_port, 3500)) return false;

    Tls13Client tls;
    std::vector<std::string> alpn = {"http/1.1"};
    if (!tls.Handshake(tcp, doh_host, alpn, nullptr, static_cast<uint32_t>(MonotonicMs() / 1000ULL), 4000)) {
        return false;
    }

    char hdr[512];
    const int hdr_len = std::snprintf(
        hdr, sizeof(hdr),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Accept: application/dns-message\r\n"
        "Content-Type: application/dns-message\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n\r\n",
        doh_path.c_str(), doh_host.c_str(), query_len);
    if (hdr_len <= 0 || static_cast<size_t>(hdr_len) >= sizeof(hdr)) return false;

    const size_t hdr_sz = static_cast<size_t>(hdr_len);
    std::vector<uint8_t> req(hdr_sz + query_len);
    std::memcpy(req.data(), hdr, hdr_sz);
    std::memcpy(req.data() + hdr_sz, query, query_len);
    if (!tls.WriteBlocking(tcp, req.data(), req.size(), 3000)) return false;

    std::vector<uint8_t> http_raw;
    uint8_t buf[2048];
    const uint64_t deadline = MonotonicMs() + 4000ULL;
    while (MonotonicMs() < deadline && http_raw.size() < 32768u) {
        const auto r = tls.ReadBlocking(tcp, buf, sizeof(buf), 1500);
        if (r.status == IoStatus::Ok && r.bytes > 0) {
            http_raw.insert(http_raw.end(), buf, buf + r.bytes);
            std::vector<uint8_t> dns_body;
            if (ExtractHttpBody(http_raw, dns_body) &&
                ParseDnsResponseA(dns_body.data(), dns_body.size(), out_ipv4_host, out_ttl)) {
                return true;
            }
        } else {
            break;
        }
    }

    std::vector<uint8_t> dns_body;
    if (ExtractHttpBody(http_raw, dns_body)) {
        return ParseDnsResponseA(dns_body.data(), dns_body.size(), out_ipv4_host, out_ttl);
    }
    return false;
}

bool DohResolver::ResolveIPv4Host(std::string_view host, uint32_t& out_ipv4_host) {
    out_ipv4_host = 0;
    if (host.empty()) return false;
    if (ParseIPv4Be(host, out_ipv4_host)) return out_ipv4_host != 0;

    const uint64_t now = MonotonicMs();
    if (cache_.Get(host, now, out_ipv4_host)) return true;

    uint16_t txid = 0x5955u;
    uint8_t rb[2]{};
    if (crypto::RandomBytes(rb, 2)) txid = ReadBe16(rb);
    const auto query = BuildDnsQueryA(host, txid);

    uint32_t ip_host = 0;
    uint32_t ttl = 60;
    bool ok = false;
    if (settings_.resolve_server_address) {
        ok = QueryDohHttps(query.data(), query.size(), ip_host, ttl);
    }
    if (!ok && settings_.dns_fallback) {
        uint32_t direct_ip = 0x08080808u;
        if (!ParseIPv4Be(settings_.direct_dns, direct_ip) || direct_ip == 0) {
            direct_ip = 0x08080808u;
        }
        ok = QueryUdpDns(direct_ip, query.data(), query.size(), ip_host, ttl);
    }
    if (!ok || ip_host == 0) return false;

    cache_.Put(host, ip_host, ttl, now);
    out_ipv4_host = ip_host;
    return true;
}

bool DohResolver::ResolveIPv4(std::string_view host, uint32_t& out_ipv4_be) {
    uint32_t ip_host = 0;
    if (!ResolveIPv4Host(host, ip_host)) {
        out_ipv4_be = 0;
        return false;
    }
    // Network byte order big-endian value stored in host uint32 (consistent across BSD & Winsock s_addr).
    out_ipv4_be = ((ip_host & 0x000000FFu) << 24) |
                  ((ip_host & 0x0000FF00u) << 8) |
                  ((ip_host & 0x00FF0000u) >> 8) |
                  ((ip_host & 0xFF000000u) >> 24);
    return true;
}

}  // namespace yumi_nx::net
