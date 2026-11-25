#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "yumi_nx/models.hpp"
#include "yumi_nx/net_interfaces.hpp"

namespace yumi_nx::net {

/// Builds an RFC 1035 DNS A-record query packet (host -> IPv4).
std::vector<uint8_t> BuildDnsQueryA(std::string_view host, uint16_t txid) noexcept;

/// Parses an RFC 1035 DNS response and extracts the first Type-A IPv4 address (host byte order) + TTL.
bool ParseDnsResponseA(const uint8_t* pkt, size_t len, uint32_t& out_ipv4_host, uint32_t& out_ttl_sec) noexcept;

/// Bounded 128-entry TTL DNS cache (host -> host-order IPv4).
class DnsCache {
public:
    void Put(std::string_view host, uint32_t ipv4_host, uint32_t ttl_sec, uint64_t now_ms) noexcept;
    bool Get(std::string_view host, uint64_t now_ms, uint32_t& out_ipv4_host) const noexcept;
    void Clear() noexcept;

private:
    struct Entry {
        bool valid = false;
        std::string host;
        uint32_t ipv4_host = 0;
        uint64_t expires_ms = 0;
    };
    static constexpr size_t kCapacity = 128;
    std::array<Entry, kCapacity> entries_{};
    size_t cursor_ = 0;
};

/// Allocates synthetic `198.18.0.0/16` FakeIPs for proxied domain names resolved via MITM `sfdnsres`.
class FakeIpPool {
public:
    [[nodiscard]] static constexpr bool IsFakeIp(uint32_t ipv4_host) noexcept {
        return (ipv4_host & 0xFFFF0000u) == 0xC6120000u;  // 198.18.0.0/16
    }

    uint32_t Allocate(std::string_view host) noexcept;
    bool Lookup(uint32_t ipv4_host, std::string& out_host) const noexcept;
    void Clear() noexcept;

private:
    struct Slot {
        bool used = false;
        uint32_t ipv4_host = 0;
        std::string host;
    };
    static constexpr size_t kCapacity = 512;
    std::array<Slot, kCapacity> slots_{};
    uint32_t next_seq_ = 1;
};

/// Horizon OS `sfdnsres` GetAddrInfoRequest output wire serializer (`0xBEEFCAFE` header + FreeBSD sockaddr_in).
/// `ipv4_host` is host-order (`0xC6120001` = 198.18.0.1); `port_host` is host-order port (e.g. 443 or 0).
size_t SerializeSfdnsresAddrInfoIPv4(uint32_t ipv4_host,
                                     uint16_t port_host,
                                     int32_t socktype,
                                     int32_t protocol,
                                     std::string_view canonname,
                                     uint8_t* out_buf,
                                     size_t out_cap) noexcept;

/// Horizon OS `sfdnsres` GetHostByNameRequest output wire serializer (`host\0`, aliases=0, AF_INET, len=4, count=1, ip_be).
size_t SerializeSfdnsresHostentIPv4(std::string_view host,
                                    uint32_t ipv4_host,
                                    uint8_t* out_buf,
                                    size_t out_cap) noexcept;

/// Resolves hostnames using DNS-over-HTTPS (RFC 8484 over Tls13Client) with TTL cache and UDP:53 fallback.
/// Implements IDnsResolver (`out_ipv4_be` is network-order big-endian, wait: keep convention consistent!).
/// Specifically: ResolveIPv4 writes host-order IPv4 into `out_ipv4_host` OR check convention cleanly!
class DohResolver final : public IDnsResolver {
public:
    explicit DohResolver(AppSettings settings = {}) noexcept : settings_(std::move(settings)) {}
    void UpdateSettings(const AppSettings& settings) noexcept { settings_ = settings; }

    /// Resolves `host` and stores IPv4 in network byte order (`htonl(ip)`) in `out_ipv4_be` per IDnsResolver contract.
    [[nodiscard]] bool ResolveIPv4(std::string_view host, uint32_t& out_ipv4_be) override;

    /// Convenience helper returning host byte order IPv4 (`0x01010101` = 1.1.1.1).
    [[nodiscard]] bool ResolveIPv4Host(std::string_view host, uint32_t& out_ipv4_host);

private:
    bool QueryDohHttps(const uint8_t* query, size_t query_len, uint32_t& out_ipv4_host, uint32_t& out_ttl) noexcept;
    bool QueryUdpDns(uint32_t server_ipv4_host, const uint8_t* query, size_t query_len, uint32_t& out_ipv4_host, uint32_t& out_ttl) noexcept;

    AppSettings settings_{};
    DnsCache cache_{};
};

}  // namespace yumi_nx::net
