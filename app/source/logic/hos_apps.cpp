#include "hos_apps.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <memory>

#include "sync_util.hpp"
#include "yumi_nx/socket_io.hpp"

#ifdef __SWITCH__
#include <switch.h>
#endif

namespace yumi_nx::logic {

namespace {

std::string FormatTidHex(uint64_t tid) {
    char buf[20];
    std::snprintf(buf, sizeof(buf), "%016llX", static_cast<unsigned long long>(tid));
    return std::string(buf);
}

bool EqualsCiTitle(const std::string& a, const std::string& b) noexcept {
    const size_t n = std::min(a.size(), b.size());
    for (size_t i = 0; i < n; ++i) {
        const unsigned char ca = static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(a[i])));
        const unsigned char cb = static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(b[i])));
        if (ca != cb) return ca < cb;
    }
    return a.size() < b.size();
}

size_t BoundedCStrLen(const char* s, size_t cap) noexcept {
    if (!s) return 0;
    size_t i = 0;
    while (i < cap && s[i] != '\0') ++i;
    return i;
}

}  // namespace

std::string GetLocalLanIpv4() {
#ifdef __SWITCH__
    u32 ip_be = 0;
    if (R_SUCCEEDED(nifmGetCurrentIpAddress(&ip_be)) && ip_be != 0) {
        const uint8_t* o = reinterpret_cast<const uint8_t*>(&ip_be);
        char buf[24];
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", o[0], o[1], o[2], o[3]);
        return std::string(buf);
    }
    return "127.0.0.1";
#else
    net::SocketLayerInit();
    net::NetSocket sock = net::NetSocket::CreateUdp(true);
    if (!sock.IsValid()) return "127.0.0.1";

    uint8_t sa_remote[16]{};
    net::EncodePlatformSockaddrIn(0x08080808u, 53, sa_remote);
    if (::connect(sock.Fd(), reinterpret_cast<const struct sockaddr*>(sa_remote), sizeof(sa_remote)) == 0) {
        uint8_t sa_local[16]{};
        socklen_t len = sizeof(sa_local);
        if (::getsockname(sock.Fd(), reinterpret_cast<struct sockaddr*>(sa_local), &len) == 0) {
            uint32_t local_ip = 0;
            uint16_t local_port = 0;
            if (net::DecodePlatformSockaddrIn(sa_local, len, local_ip, local_port) &&
                local_ip != 0 && local_ip != 0x7F000001u) {
                return FormatIpv4HostOrder(local_ip);
            }
        }
    }
    return "127.0.0.1";
#endif
}

std::vector<InstalledTitle> EnumerateInstalledTitles() {
    std::vector<InstalledTitle> out;
#ifdef __SWITCH__
    static constexpr s32 kMaxRecords = 256;
    std::vector<NsApplicationRecord> recs(static_cast<size_t>(kMaxRecords));
    s32 entry_count = 0;
    if (R_SUCCEEDED(nsListApplicationRecord(recs.data(), kMaxRecords, 0, &entry_count)) && entry_count > 0) {
        auto ctrl = std::unique_ptr<NsApplicationControlData>(new (std::nothrow) NsApplicationControlData{});
        for (s32 i = 0; i < entry_count && i < kMaxRecords; ++i) {
            const uint64_t tid = recs[static_cast<size_t>(i)].application_id;
            if (tid == 0) continue;

            InstalledTitle t;
            t.title_id = tid;
            t.title_id_hex = FormatTidHex(tid);
            t.name = "App " + t.title_id_hex;

            if (ctrl) {
                std::memset(ctrl.get(), 0, sizeof(NsApplicationControlData));
                u64 actual = 0;
                if (R_SUCCEEDED(nsGetApplicationControlData(NsApplicationControlSource_Storage, tid,
                                                            ctrl.get(), sizeof(NsApplicationControlData), &actual)) &&
                    actual >= sizeof(NacpStruct)) {
                    NacpLanguageEntry* lang = nullptr;
                    if (R_SUCCEEDED(nacpGetLanguageEntry(&ctrl->nacp, &lang)) && lang && lang->name[0] != '\0') {
                        t.name = std::string(lang->name, BoundedCStrLen(lang->name, sizeof(lang->name)));
                        if (lang->author[0] != '\0') {
                            t.publisher = std::string(lang->author, BoundedCStrLen(lang->author, sizeof(lang->author)));
                        }
                    }
                }
            }
            out.push_back(std::move(t));
        }
    }
    std::sort(out.begin(), out.end(), [](const InstalledTitle& a, const InstalledTitle& b) {
        return EqualsCiTitle(a.name, b.name);
    });
#else
    auto add = [&](uint64_t tid, const char* name, const char* pub) {
        out.push_back({tid, FormatTidHex(tid), name, pub});
    };
    add(0x01003A400C3DA000ULL, "YouTube", "Google LLC");
    add(0x010000000000100FULL, "Веб-браузер HOS", "Nintendo");
    add(0x050000BADDAD0000ULL, "Tinfoil", "Homebrew");
    add(0x0100000000008001ULL, "Moonlight-NX", "Homebrew");
    add(0x0100F2C0115B6000ULL, "Zelda: Tears of the Kingdom", "Nintendo");
    add(0x0100152000022000ULL, "Mario Kart 8 Deluxe", "Nintendo");
#endif
    return out;
}

}  // namespace yumi_nx::logic
