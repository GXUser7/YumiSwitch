#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "yumi_nx/models.hpp"

namespace yumi_nx::rules {

inline constexpr uint32_t kRulesBinMagic = 0x31524D59u;  // "YMR1" little-endian
inline constexpr uint16_t kRulesBinVersion = 1;

struct IPv4Cidr {
    uint32_t net_be = 0;   // host-order bitmask style: (a<<24)|(b<<16)|(c<<8)|d
    uint32_t mask_be = 0;
    uint8_t prefix = 32;
};

struct ActionSet {
    std::vector<std::string> full_domains;
    std::vector<std::string> domain_suffixes;
    std::vector<std::string> keywords;
    std::vector<IPv4Cidr> cidrs;

    [[nodiscard]] bool Empty() const noexcept {
        return full_domains.empty() && domain_suffixes.empty() && keywords.empty() && cidrs.empty();
    }
    [[nodiscard]] bool Matches(std::string_view host_lower, uint32_t ipv4_host_order, bool has_ipv4) const noexcept;
};

struct RulesIndex {
    bool block_udp_443 = false;
    ActionSet block;
    ActionSet direct;
    ActionSet proxy;

    [[nodiscard]] bool Empty() const noexcept {
        return !block_udp_443 && block.Empty() && direct.Empty() && proxy.Empty();
    }

    /// Evaluates priority Block -> Direct -> Proxy. Returns std::nullopt if no rule matched.
    [[nodiscard]] std::optional<CustomRules::Action> Match(std::string_view host,
                                                           uint32_t ipv4_host_order,
                                                           bool has_ipv4,
                                                           bool is_udp,
                                                           uint16_t port) const noexcept;
};

/// Parses a CIDR string like "192.168.0.0/16" or single IPv4 "8.8.8.8".
[[nodiscard]] std::optional<IPv4Cidr> ParseIPv4Cidr(std::string_view text) noexcept;

/// Streams a v2fly `geosite.dat` protobuf blob for `category_upper` (e.g. "CATEGORY-RU") and extracts exact/suffix/keyword rules.
bool ExtractGeoSiteCategoryDomains(const uint8_t* data,
                                   size_t len,
                                   std::string_view category_upper,
                                   std::vector<std::string>& out_full,
                                   std::vector<std::string>& out_suffix,
                                   std::vector<std::string>& out_keyword);

/// Streams a v2fly `geoip.dat` protobuf blob for `category_upper` (e.g. "RU") and extracts IPv4 CIDRs.
bool ExtractGeoIpCategoryCidrs(const uint8_t* data,
                               size_t len,
                               std::string_view category_upper,
                               std::vector<IPv4Cidr>& out_cidrs);

/// Compiles `settings.custom_rules` + built-in presets or optional `geosite.dat`/`geoip.dat` blobs into a compact `RulesIndex`.
[[nodiscard]] RulesIndex CompileRulesIndex(const AppSettings& settings,
                                           const std::vector<uint8_t>* geosite_dat = nullptr,
                                           const std::vector<uint8_t>* geoip_dat = nullptr);

[[nodiscard]] std::vector<uint8_t> SerializeRulesBin(const RulesIndex& index);
[[nodiscard]] std::optional<RulesIndex> DeserializeRulesBin(const std::vector<uint8_t>& bytes);

}  // namespace yumi_nx::rules
