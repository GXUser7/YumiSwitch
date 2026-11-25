#include "yumi_nx/rules_bin.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace yumi_nx::rules {

namespace {

std::string ToLowerAscii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

std::string ToUpperAscii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    return out;
}

bool ParseIpv4Raw(std::string_view text, uint32_t& out_ip) noexcept {
    if (text.empty()) return false;
    uint8_t oct[4]{};
    size_t start = 0;
    for (int i = 0; i < 4; ++i) {
        const size_t dot = text.find('.', start);
        if (i < 3 && dot == std::string_view::npos) return false;
        if (i == 3 && dot != std::string_view::npos) return false;
        const size_t end = (i < 3) ? dot : text.size();
        if (end <= start || end - start > 3) return false;
        uint32_t v = 0;
        for (size_t k = start; k < end; ++k) {
            if (text[k] < '0' || text[k] > '9') return false;
            v = v * 10u + static_cast<uint32_t>(text[k] - '0');
        }
        if (v > 255u) return false;
        oct[i] = static_cast<uint8_t>(v);
        start = end + 1;
    }
    out_ip = (uint32_t(oct[0]) << 24) | (uint32_t(oct[1]) << 16) | (uint32_t(oct[2]) << 8) | uint32_t(oct[3]);
    return true;
}

uint32_t Fnv1a32(const uint8_t* data, size_t len) noexcept {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 16777619u;
    }
    return h;
}

// Protobuf wire cursor (bounds-checked, zero exceptions)
struct PbReader {
    const uint8_t* data = nullptr;
    size_t size = 0;
    size_t pos = 0;

    bool Eof() const noexcept { return pos >= size; }

    bool ReadVarint(uint64_t& out) noexcept {
        out = 0;
        int shift = 0;
        while (pos < size && shift <= 63) {
            const uint8_t b = data[pos++];
            out |= uint64_t(b & 0x7Fu) << shift;
            if ((b & 0x80u) == 0) return true;
            shift += 7;
        }
        return false;
    }

    bool Skip(uint64_t n) noexcept {
        if (n > size - pos) {
            pos = size;
            return false;
        }
        pos += static_cast<size_t>(n);
        return true;
    }

    bool SkipValue(int wire) noexcept {
        if (wire == 0) {
            uint64_t dummy = 0;
            return ReadVarint(dummy);
        }
        if (wire == 1) return Skip(8);
        if (wire == 5) return Skip(4);
        if (wire == 2) {
            uint64_t len = 0;
            return ReadVarint(len) && Skip(len);
        }
        return false;
    }
};

void SortUniqueStrings(std::vector<std::string>& v) {
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
}

void SortUniqueCidrs(std::vector<IPv4Cidr>& v) {
    std::sort(v.begin(), v.end(), [](const IPv4Cidr& a, const IPv4Cidr& b) {
        if (a.net_be != b.net_be) return a.net_be < b.net_be;
        return a.prefix < b.prefix;
    });
    v.erase(std::unique(v.begin(), v.end(), [](const IPv4Cidr& a, const IPv4Cidr& b) {
        return a.net_be == b.net_be && a.prefix == b.prefix;
    }), v.end());
}

void AddBuiltinRuPreset(ActionSet& direct) {
    static constexpr const char* kRuSuffixes[] = {
        "ru", "su", "xn--p1ai", "vk.com", "vk.ru", "userapi.com", "vk-cdn.net",
        "yandex.ru", "ya.ru", "yandex.net", "mail.ru", "ok.ru", "gosuslugi.ru",
        "sberbank.ru", "tbank.ru", "tinkoff.ru", "ozon.ru", "wildberries.ru",
        "wb.ru", "avito.ru", "kinopoisk.ru", "rutube.ru", "dzen.ru",
    };
    for (const char* s : kRuSuffixes) direct.domain_suffixes.emplace_back(s);
}

void AddBuiltinAdsPreset(ActionSet& block) {
    static constexpr const char* kAdSuffixes[] = {
        "doubleclick.net", "googlesyndication.com", "googleadservices.com",
        "adservice.google.com", "pagead2.googlesyndication.com",
        "ads.youtube.com", "analytics.google.com", "mc.yandex.ru", "an.yandex.ru",
        "adfox.ru", "app-measurement.com", "adjust.com", "appsflyer.com",
    };
    for (const char* s : kAdSuffixes) block.domain_suffixes.emplace_back(s);
}

}  // namespace

std::optional<IPv4Cidr> ParseIPv4Cidr(std::string_view text) noexcept {
    const size_t slash = text.find('/');
    uint32_t ip = 0;
    uint8_t prefix = 32;
    if (slash == std::string_view::npos) {
        if (!ParseIpv4Raw(text, ip)) return std::nullopt;
    } else {
        if (!ParseIpv4Raw(text.substr(0, slash), ip)) return std::nullopt;
        const std::string_view pstr = text.substr(slash + 1);
        if (pstr.empty() || pstr.size() > 2) return std::nullopt;
        uint32_t p = 0;
        for (char c : pstr) {
            if (c < '0' || c > '9') return std::nullopt;
            p = p * 10u + static_cast<uint32_t>(c - '0');
        }
        if (p > 32u) return std::nullopt;
        prefix = static_cast<uint8_t>(p);
    }
    const uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32u - prefix));
    return IPv4Cidr{ip & mask, mask, prefix};
}

bool ActionSet::Matches(std::string_view host_lower, uint32_t ipv4_host_order, bool has_ipv4) const noexcept {
    if (!host_lower.empty()) {
        if (!full_domains.empty()) {
            auto it = std::lower_bound(full_domains.begin(), full_domains.end(), host_lower);
            if (it != full_domains.end() && *it == host_lower) return true;
        }
        if (!domain_suffixes.empty()) {
            // Walk dot boundaries from full host down to TLD for O(labels * log N) exact suffix lookup
            std::string_view probe = host_lower;
            while (!probe.empty()) {
                auto it = std::lower_bound(domain_suffixes.begin(), domain_suffixes.end(), probe);
                if (it != domain_suffixes.end() && *it == probe) return true;
                const size_t dot = probe.find('.');
                if (dot == std::string_view::npos) break;
                probe.remove_prefix(dot + 1);
            }
        }
        for (const auto& kw : keywords) {
            if (!kw.empty() && host_lower.find(kw) != std::string_view::npos) return true;
        }
    }
    if (has_ipv4) {
        for (const auto& c : cidrs) {
            if ((ipv4_host_order & c.mask_be) == c.net_be) return true;
        }
    }
    return false;
}

std::optional<CustomRules::Action> RulesIndex::Match(std::string_view host,
                                                     uint32_t ipv4_host_order,
                                                     bool has_ipv4,
                                                     bool is_udp,
                                                     uint16_t port) const noexcept {
    if (block_udp_443 && is_udp && port == 443) {
        return CustomRules::Action::Block;
    }
    std::string lower = ToLowerAscii(host);
    while (!lower.empty() && lower.back() == '.') lower.pop_back();

    uint32_t effective_ip = ipv4_host_order;
    bool effective_has_ip = has_ipv4;
    if (!effective_has_ip && !lower.empty()) {
        effective_has_ip = ParseIpv4Raw(lower, effective_ip);
    }

    if (block.Matches(lower, effective_ip, effective_has_ip)) return CustomRules::Action::Block;
    if (direct.Matches(lower, effective_ip, effective_has_ip)) return CustomRules::Action::Direct;
    if (proxy.Matches(lower, effective_ip, effective_has_ip)) return CustomRules::Action::Proxy;
    return std::nullopt;
}

bool ExtractGeoSiteCategoryDomains(const uint8_t* data,
                                   size_t len,
                                   std::string_view category_upper,
                                   std::vector<std::string>& out_full,
                                   std::vector<std::string>& out_suffix,
                                   std::vector<std::string>& out_keyword) {
    if (!data || len == 0 || category_upper.empty()) return false;
    const std::string target = ToUpperAscii(category_upper);
    bool found = false;

    PbReader list_r{data, len, 0};
    while (!list_r.Eof()) {
        uint64_t tag = 0;
        if (!list_r.ReadVarint(tag)) break;
        const uint32_t field = static_cast<uint32_t>(tag >> 3);
        const int wire = static_cast<int>(tag & 7u);
        if (field == 1 && wire == 2) {
            uint64_t entry_len = 0;
            if (!list_r.ReadVarint(entry_len) || entry_len > list_r.size - list_r.pos) break;
            const uint8_t* entry_ptr = list_r.data + list_r.pos;
            list_r.pos += static_cast<size_t>(entry_len);

            // Inspect entry country_code (field 1)
            PbReader er{entry_ptr, static_cast<size_t>(entry_len), 0};
            std::string code;
            while (!er.Eof()) {
                uint64_t etag = 0;
                if (!er.ReadVarint(etag)) break;
                const uint32_t ef = static_cast<uint32_t>(etag >> 3);
                const int ew = static_cast<int>(etag & 7u);
                if (ef == 1 && ew == 2) {
                    uint64_t clen = 0;
                    if (!er.ReadVarint(clen) || clen > er.size - er.pos) break;
                    code = ToUpperAscii(std::string_view(reinterpret_cast<const char*>(er.data + er.pos), static_cast<size_t>(clen)));
                    er.pos += static_cast<size_t>(clen);
                    break;
                } else {
                    if (!er.SkipValue(ew)) break;
                }
            }
            if (code != target) continue;
            found = true;

            // Extract repeated Domain messages (field 2)
            PbReader dr{entry_ptr, static_cast<size_t>(entry_len), 0};
            while (!dr.Eof()) {
                uint64_t dtag = 0;
                if (!dr.ReadVarint(dtag)) break;
                const uint32_t df = static_cast<uint32_t>(dtag >> 3);
                const int dw = static_cast<int>(dtag & 7u);
                if (df == 2 && dw == 2) {
                    uint64_t msg_len = 0;
                    if (!dr.ReadVarint(msg_len) || msg_len > dr.size - dr.pos) break;
                    PbReader mr{dr.data + dr.pos, static_cast<size_t>(msg_len), 0};
                    dr.pos += static_cast<size_t>(msg_len);

                    uint64_t dom_type = 0;  // 0=Plain, 1=Regex, 2=RootDomain, 3=Full
                    std::string val;
                    while (!mr.Eof()) {
                        uint64_t mtag = 0;
                        if (!mr.ReadVarint(mtag)) break;
                        const uint32_t mf = static_cast<uint32_t>(mtag >> 3);
                        const int mw = static_cast<int>(mtag & 7u);
                        if (mf == 1 && mw == 0) {
                            mr.ReadVarint(dom_type);
                        } else if (mf == 2 && mw == 2) {
                            uint64_t vlen = 0;
                            if (!mr.ReadVarint(vlen) || vlen > mr.size - mr.pos) break;
                            val = ToLowerAscii(std::string_view(reinterpret_cast<const char*>(mr.data + mr.pos), static_cast<size_t>(vlen)));
                            mr.pos += static_cast<size_t>(vlen);
                        } else {
                            if (!mr.SkipValue(mw)) break;
                        }
                    }
                    if (!val.empty()) {
                        if (dom_type == 3) out_full.push_back(std::move(val));
                        else if (dom_type == 2) out_suffix.push_back(std::move(val));
                        else if (dom_type == 0) out_keyword.push_back(std::move(val));
                    }
                } else {
                    if (!dr.SkipValue(dw)) break;
                }
            }
            break;
        } else {
            if (!list_r.SkipValue(wire)) break;
        }
    }
    return found;
}

bool ExtractGeoIpCategoryCidrs(const uint8_t* data,
                               size_t len,
                               std::string_view category_upper,
                               std::vector<IPv4Cidr>& out_cidrs) {
    if (!data || len == 0 || category_upper.empty()) return false;
    const std::string target = ToUpperAscii(category_upper);
    bool found = false;

    PbReader list_r{data, len, 0};
    while (!list_r.Eof()) {
        uint64_t tag = 0;
        if (!list_r.ReadVarint(tag)) break;
        const uint32_t field = static_cast<uint32_t>(tag >> 3);
        const int wire = static_cast<int>(tag & 7u);
        if (field == 1 && wire == 2) {
            uint64_t entry_len = 0;
            if (!list_r.ReadVarint(entry_len) || entry_len > list_r.size - list_r.pos) break;
            const uint8_t* entry_ptr = list_r.data + list_r.pos;
            list_r.pos += static_cast<size_t>(entry_len);

            PbReader er{entry_ptr, static_cast<size_t>(entry_len), 0};
            std::string code;
            while (!er.Eof()) {
                uint64_t etag = 0;
                if (!er.ReadVarint(etag)) break;
                const uint32_t ef = static_cast<uint32_t>(etag >> 3);
                const int ew = static_cast<int>(etag & 7u);
                if (ef == 1 && ew == 2) {
                    uint64_t clen = 0;
                    if (!er.ReadVarint(clen) || clen > er.size - er.pos) break;
                    code = ToUpperAscii(std::string_view(reinterpret_cast<const char*>(er.data + er.pos), static_cast<size_t>(clen)));
                    er.pos += static_cast<size_t>(clen);
                    break;
                } else {
                    if (!er.SkipValue(ew)) break;
                }
            }
            if (code != target) continue;
            found = true;

            PbReader cr{entry_ptr, static_cast<size_t>(entry_len), 0};
            while (!cr.Eof()) {
                uint64_t ctag = 0;
                if (!cr.ReadVarint(ctag)) break;
                const uint32_t cf = static_cast<uint32_t>(ctag >> 3);
                const int cw = static_cast<int>(ctag & 7u);
                if (cf == 2 && cw == 2) {
                    uint64_t msg_len = 0;
                    if (!cr.ReadVarint(msg_len) || msg_len > cr.size - cr.pos) break;
                    PbReader mr{cr.data + cr.pos, static_cast<size_t>(msg_len), 0};
                    cr.pos += static_cast<size_t>(msg_len);

                    uint32_t ip = 0;
                    bool has_ipv4 = false;
                    uint64_t prefix = 32;
                    while (!mr.Eof()) {
                        uint64_t mtag = 0;
                        if (!mr.ReadVarint(mtag)) break;
                        const uint32_t mf = static_cast<uint32_t>(mtag >> 3);
                        const int mw = static_cast<int>(mtag & 7u);
                        if (mf == 1 && mw == 2) {
                            uint64_t blen = 0;
                            if (!mr.ReadVarint(blen) || blen > mr.size - mr.pos) break;
                            if (blen == 4) {
                                const uint8_t* p = mr.data + mr.pos;
                                ip = (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]);
                                has_ipv4 = true;
                            }
                            mr.pos += static_cast<size_t>(blen);
                        } else if (mf == 2 && mw == 0) {
                            mr.ReadVarint(prefix);
                        } else {
                            if (!mr.SkipValue(mw)) break;
                        }
                    }
                    if (has_ipv4 && prefix <= 32u) {
                        const uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32u - prefix));
                        out_cidrs.push_back({ip & mask, mask, static_cast<uint8_t>(prefix)});
                    }
                } else {
                    if (!cr.SkipValue(cw)) break;
                }
            }
            break;
        } else {
            if (!list_r.SkipValue(wire)) break;
        }
    }
    return found;
}

RulesIndex CompileRulesIndex(const AppSettings& settings,
                               const std::vector<uint8_t>* geosite_dat,
                               const std::vector<uint8_t>* geoip_dat) {
    RulesIndex idx;
    idx.block_udp_443 = settings.block_quic;

    auto compile_list = [&](const std::vector<std::string>& items, ActionSet& target, bool is_block) {
        for (const auto& raw : items) {
            const std::string lower = ToLowerAscii(raw);
            if (is_block && lower == "udp:443") {
                idx.block_udp_443 = true;
                continue;
            }
            if (lower.starts_with("domain:")) {
                const std::string d = lower.substr(7);
                if (!d.empty()) target.domain_suffixes.push_back(d);
            } else if (lower.starts_with("full:")) {
                const std::string d = lower.substr(5);
                if (!d.empty()) target.full_domains.push_back(d);
            } else if (lower.starts_with("keyword:")) {
                const std::string kw = lower.substr(8);
                if (!kw.empty()) target.keywords.push_back(kw);
            } else if (lower.starts_with("geosite:")) {
                std::string cat = ToUpperAscii(raw.substr(8));
                const size_t at = cat.find('@');
                if (at != std::string::npos) cat.resize(at);
                bool loaded = false;
                if (geosite_dat && !geosite_dat->empty()) {
                    loaded = ExtractGeoSiteCategoryDomains(
                        geosite_dat->data(), geosite_dat->size(), cat,
                        target.full_domains, target.domain_suffixes, target.keywords);
                }
                if (!loaded) {
                    if (cat == "CATEGORY-RU" || cat == "RU") AddBuiltinRuPreset(target);
                    else if (cat == "CATEGORY-ADS-ALL" || cat == "CATEGORY-ADS") AddBuiltinAdsPreset(target);
                }
            } else if (lower.starts_with("geoip:")) {
                std::string cat = ToUpperAscii(raw.substr(6));
                if (!cat.empty() && cat.front() == '!') cat.erase(0, 1);
                if (geoip_dat && !geoip_dat->empty()) {
                    ExtractGeoIpCategoryCidrs(geoip_dat->data(), geoip_dat->size(), cat, target.cidrs);
                }
            } else if (auto cidr = ParseIPv4Cidr(raw)) {
                target.cidrs.push_back(*cidr);
            } else if (!lower.empty() && lower.find(':') == std::string::npos) {
                target.domain_suffixes.push_back(lower);
            }
        }
    };

    compile_list(settings.custom_rules.block, idx.block, true);
    compile_list(settings.custom_rules.direct, idx.direct, false);
    compile_list(settings.custom_rules.proxy, idx.proxy, false);

    if (settings.block_ads) {
        bool loaded_ads = false;
        if (geosite_dat && !geosite_dat->empty()) {
            loaded_ads = ExtractGeoSiteCategoryDomains(
                geosite_dat->data(), geosite_dat->size(), "CATEGORY-ADS-ALL",
                idx.block.full_domains, idx.block.domain_suffixes, idx.block.keywords);
        }
        if (!loaded_ads) AddBuiltinAdsPreset(idx.block);
    }

    auto sort_set = [](ActionSet& s) {
        SortUniqueStrings(s.full_domains);
        SortUniqueStrings(s.domain_suffixes);
        SortUniqueStrings(s.keywords);
        SortUniqueCidrs(s.cidrs);
    };
    sort_set(idx.block);
    sort_set(idx.direct);
    sort_set(idx.proxy);
    return idx;
}

std::vector<uint8_t> SerializeRulesBin(const RulesIndex& index) {
    std::vector<uint8_t> out;
    out.reserve(4096);
    auto u8 = [&](uint8_t v) { out.push_back(v); };
    auto u16 = [&](uint16_t v) { out.push_back(uint8_t(v)); out.push_back(uint8_t(v >> 8)); };
    auto u32 = [&](uint32_t v) {
        out.push_back(uint8_t(v));
        out.push_back(uint8_t(v >> 8));
        out.push_back(uint8_t(v >> 16));
        out.push_back(uint8_t(v >> 24));
    };
    auto str = [&](const std::string& s) {
        const uint16_t len = static_cast<uint16_t>(std::min<size_t>(s.size(), 512));
        u16(len);
        out.insert(out.end(), s.begin(), s.begin() + len);
    };
    auto write_set = [&](const ActionSet& set) {
        u32(static_cast<uint32_t>(set.full_domains.size()));
        for (const auto& s : set.full_domains) str(s);
        u32(static_cast<uint32_t>(set.domain_suffixes.size()));
        for (const auto& s : set.domain_suffixes) str(s);
        u32(static_cast<uint32_t>(set.keywords.size()));
        for (const auto& s : set.keywords) str(s);
        u32(static_cast<uint32_t>(set.cidrs.size()));
        for (const auto& c : set.cidrs) {
            u32(c.net_be);
            u8(c.prefix);
        }
    };

    u32(kRulesBinMagic);
    u16(kRulesBinVersion);
    u16(index.block_udp_443 ? 1u : 0u);
    write_set(index.block);
    write_set(index.direct);
    write_set(index.proxy);
    u32(Fnv1a32(out.data(), out.size()));
    return out;
}

std::optional<RulesIndex> DeserializeRulesBin(const std::vector<uint8_t>& bytes) {
    if (bytes.size() < 12) return std::nullopt;
    const size_t payload_sz = bytes.size() - 4;
    const uint32_t expected = uint32_t(bytes[payload_sz]) | (uint32_t(bytes[payload_sz + 1]) << 8) |
                              (uint32_t(bytes[payload_sz + 2]) << 16) | (uint32_t(bytes[payload_sz + 3]) << 24);
    if (Fnv1a32(bytes.data(), payload_sz) != expected) return std::nullopt;

    size_t pos = 0;
    auto r_u8 = [&](uint8_t& v) -> bool {
        if (pos + 1 > payload_sz) return false;
        v = bytes[pos++];
        return true;
    };
    auto r_u16 = [&](uint16_t& v) -> bool {
        if (pos + 2 > payload_sz) return false;
        v = uint16_t(bytes[pos]) | (uint16_t(bytes[pos + 1]) << 8);
        pos += 2;
        return true;
    };
    auto r_u32 = [&](uint32_t& v) -> bool {
        if (pos + 4 > payload_sz) return false;
        v = uint32_t(bytes[pos]) | (uint32_t(bytes[pos + 1]) << 8) |
            (uint32_t(bytes[pos + 2]) << 16) | (uint32_t(bytes[pos + 3]) << 24);
        pos += 4;
        return true;
    };
    auto r_str = [&](std::string& s) -> bool {
        uint16_t len = 0;
        if (!r_u16(len) || len > 512 || pos + len > payload_sz) return false;
        s.assign(reinterpret_cast<const char*>(bytes.data() + pos), len);
        pos += len;
        return true;
    };
    auto read_set = [&](ActionSet& set) -> bool {
        uint32_t cnt = 0;
        if (!r_u32(cnt) || cnt > 200000u) return false;
        set.full_domains.resize(cnt);
        for (uint32_t i = 0; i < cnt; ++i) if (!r_str(set.full_domains[i])) return false;

        if (!r_u32(cnt) || cnt > 200000u) return false;
        set.domain_suffixes.resize(cnt);
        for (uint32_t i = 0; i < cnt; ++i) if (!r_str(set.domain_suffixes[i])) return false;

        if (!r_u32(cnt) || cnt > 50000u) return false;
        set.keywords.resize(cnt);
        for (uint32_t i = 0; i < cnt; ++i) if (!r_str(set.keywords[i])) return false;

        if (!r_u32(cnt) || cnt > 200000u) return false;
        set.cidrs.resize(cnt);
        for (uint32_t i = 0; i < cnt; ++i) {
            uint32_t net = 0;
            uint8_t pref = 32;
            if (!r_u32(net) || !r_u8(pref) || pref > 32u) return false;
            const uint32_t mask = (pref == 0) ? 0u : (0xFFFFFFFFu << (32u - pref));
            set.cidrs[i] = {net & mask, mask, pref};
        }
        return true;
    };

    uint32_t magic = 0;
    uint16_t ver = 0, flags = 0;
    if (!r_u32(magic) || magic != kRulesBinMagic) return std::nullopt;
    if (!r_u16(ver) || ver != kRulesBinVersion) return std::nullopt;
    if (!r_u16(flags)) return std::nullopt;

    RulesIndex out;
    out.block_udp_443 = (flags & 1u) != 0;
    if (!read_set(out.block) || !read_set(out.direct) || !read_set(out.proxy)) return std::nullopt;
    if (pos != payload_sz) return std::nullopt;
    return out;
}

}  // namespace yumi_nx::rules
