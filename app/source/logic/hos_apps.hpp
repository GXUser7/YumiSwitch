#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace yumi_nx::logic {

struct InstalledTitle {
    uint64_t title_id = 0;
    std::string title_id_hex;
    std::string name;
    std::string publisher;
};

/// Returns the device's active LAN IPv4 string ("192.168.x.x") or "127.0.0.1" if offline.
[[nodiscard]] std::string GetLocalLanIpv4();

/// Enumerates installed Horizon OS titles via `ns` (or sample titles on Desktop preview).
[[nodiscard]] std::vector<InstalledTitle> EnumerateInstalledTitles();

}  // namespace yumi_nx::logic
