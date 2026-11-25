#pragma once

#include <string>

namespace yumi_nx::paths {

#ifdef __SWITCH__
inline constexpr const char* kConfigDir = "sdmc:/config/yumi-nx";
inline constexpr const char* kFontDir = "romfs:/fonts";
#else
inline constexpr const char* kConfigDir = "run_config";
inline constexpr const char* kFontDir = "app/romfs/fonts";
#endif

inline std::string Join(const char* dir, const char* file) {
    std::string out(dir);
    if (!out.empty() && out.back() != '/' && out.back() != '\\') {
        out.push_back('/');
    }
    out.append(file);
    return out;
}

inline std::string SettingsFile() { return Join(kConfigDir, "settings.json"); }
inline std::string ActiveNodeFile() { return Join(kConfigDir, "active_node.bin"); }
inline std::string RulesBinFile() { return Join(kConfigDir, "rules.bin"); }
inline std::string SubscriptionsFile() { return Join(kConfigDir, "subscriptions.json"); }
inline std::string NodesFile() { return Join(kConfigDir, "nodes.json"); }
inline std::string QuickNodesFile() { return Join(kConfigDir, "quick_nodes.txt"); }
inline std::string ImportFile() { return Join(kConfigDir, "import.txt"); }
inline std::string LogFile() { return Join(kConfigDir, "yumi.log"); }

}  // namespace yumi_nx::paths
