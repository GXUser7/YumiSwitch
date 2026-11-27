#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

#include "sync_util.hpp"
#include "yumi_nx/models.hpp"

namespace yumi_nx::logic {

struct UpdateReleaseInfo {
    bool check_ok = false;
    bool update_available = false;
    std::string current_version;
    std::string latest_version;
    std::string changelog;
    std::string asset_name;
    std::string download_url;
    uint64_t asset_size = 0;
    std::string error;
};

struct UpdateProgressState {
    bool busy = false;
    bool finished = false;
    double progress_0_1 = 0.0;
    std::string status_line = "v1.0.1 · Актуально";
    std::string downloaded_path;
    UpdateReleaseInfo release{};
};

/// Compares semantic versions like `"v0.3.2"` vs `"0.3.1"` (`<0` if `a<b`, `0` if equal, `>0` if `a>b`).
[[nodiscard]] int CompareSemVer(std::string_view a, std::string_view b) noexcept;

/// Parses a GitHub Releases API JSON object (`tag_name`, `body`, `assets[]`).
[[nodiscard]] UpdateReleaseInfo ParseGitHubReleaseJson(std::string_view json_text,
                                                       std::string_view current_version,
                                                       std::string_view preferred_asset_ext = ".nro");

/// Fetches latest release metadata from GitHub Releases (with HEAD redirect tag fallback on 403 rate limit).
[[nodiscard]] UpdateReleaseInfo CheckLatestGitHubRelease(std::string_view owner_repo,
                                                         std::string_view current_version,
                                                         const AppSettings& settings = {},
                                                         const ProxyNode* via_node = nullptr,
                                                         std::string_view api_base_url_override = "",
                                                         std::string_view preferred_asset_ext = ".nro");

class AsyncUpdateChecker {
public:
    AsyncUpdateChecker() noexcept = default;
    ~AsyncUpdateChecker() { Stop(); }

    AsyncUpdateChecker(const AsyncUpdateChecker&) = delete;
    AsyncUpdateChecker& operator=(const AsyncUpdateChecker&) = delete;

    bool StartCheck(std::string owner_repo,
                    std::string current_version,
                    AppSettings settings,
                    const ProxyNode* via_node = nullptr,
                    bool auto_download_if_newer = false);

    void Stop() noexcept;

    [[nodiscard]] UpdateProgressState Snapshot();
    [[nodiscard]] bool IsBusy() const noexcept { return busy_.load(); }

private:
    static void ThreadEntry(void* arg);
    void Run();

    SimpleMutex mu_{};
    WorkerThread worker_{};
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> busy_{false};

    std::string owner_repo_ = "GXUser7/YumiSwitch";
    std::string current_version_ = "1.0.1";
    AppSettings settings_{};
    ProxyNode owned_via_node_{};
    bool has_via_node_ = false;
    bool auto_download_ = false;
    UpdateProgressState state_{};
};

}  // namespace yumi_nx::logic
