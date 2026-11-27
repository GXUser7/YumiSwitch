#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include "hos_apps.hpp"
#include "latency_tester.hpp"
#include "pairing_service.hpp"
#include "remote_service.hpp"
#include "speed_tester.hpp"
#include "sync_util.hpp"
#include "update_checker.hpp"
#include "yumi_nx/ipc_protocol.hpp"
#include "yumi_nx/models.hpp"
#include "yumi_nx/qr_matrix.hpp"
#include "yumi_nx/subscription_parser.hpp"
#include "visualizers.hpp"
#include "yumi_theme.hpp"

struct NVGcontext;

namespace yumi_nx::ui {

enum class UiTab : uint8_t {
    Connect = 0,
    Servers = 1,
    Subs = 2,
    Rules = 3,
    Settings = 4,
};

enum class SettingsCategory : uint8_t {
    Routing = 0,
    TitleId = 1,
    Dpi = 2,
    LogRules = 3,
    Remote = 4,
};

struct UiInputState {
    bool up = false;
    bool down = false;
    bool left = false;
    bool right = false;
    bool confirm = false;     // Joy-Con A / Enter / Space
    bool back = false;        // Joy-Con B / Esc
    bool action_x = false;    // Joy-Con X / X (measure latency / mode)
    bool action_y = false;    // Joy-Con Y / Y (SD import / reload)
    bool shoulder_l = false;  // Joy-Con L / Q / [
    bool shoulder_r = false;  // Joy-Con R / E / ]
    bool clicked = false;
    float pointer_x = 0.0f;
    float pointer_y = 0.0f;
    float scroll_delta = 0.0f;
};

struct UiServerEntry {
    std::string id;
    std::string cc;
    std::string short_name;
    std::string name;
    std::string proto_label;
    std::string transport_label;
    std::string flow_label;
    std::string sni;
    std::string utls;
    std::string endpoint;
    std::string sub_id;
    std::string sub_name;
    int ping_ms = -1;
    float lat_deg = 60.17f;
    float lon_deg = 24.94f;
    ProxyNode node{};
};

struct UiSubEntry {
    std::string id;
    std::string name;
    std::string url;
    int node_total = 0;
    int used_gb = 0;
    int limit_gb = 0;  // 0 = unlimited
    std::string expires;
    bool enabled = true;
};

struct UiTitleEntry {
    uint64_t tid = 0;
    std::string name;
    bool vpn_routed = false;
};

struct UiLogEntry {
    uint32_t sequence_id = 0;
    std::string host;
    uint16_t port = 443;
    std::string proto;
    std::string app_name;
    uint8_t route_action = 0;  // 0=Proxy, 1=Direct, 2=Block
    std::string badge;
    std::string time_str;
};

class YumiUiApp {
public:
    YumiUiApp(ipc::IYumiCtlClient& ctl_client, std::string font_dir, bool is_desktop_preview);
    ~YumiUiApp();

    YumiUiApp(const YumiUiApp&) = delete;
    YumiUiApp& operator=(const YumiUiApp&) = delete;

    bool Init(NVGcontext* vg);
    void Shutdown(NVGcontext* vg);

    void SetTab(UiTab tab) noexcept { active_tab_ = tab; focus_idx_ = 0; }
    void SetSettingsCategory(SettingsCategory cat) noexcept { settings_cat_ = cat; focus_idx_ = 0; }
    void SetVisualizerPlanet(bool planet) noexcept { vis_planet_ = planet; }
    void SetPalette(PaletteId id, bool amoled) noexcept {
        theme_ = BuildYumiTheme(id, amoled);
    }
    void SetHeadlessMode(bool headless) noexcept { headless_mode_ = headless; }

    void Update(double dt_sec, const UiInputState& input);
    void Render(NVGcontext* vg, int win_width, int win_height);

private:
    enum class HitAction : uint16_t {
        None = 0,
        ShoulderL,
        ShoulderR,
        SelectTab,
        ToggleTunnel,
        ToggleVis,
        SetRoute,
        GotoServers,
        GotoRules,
        FilterProto,
        PingAll,
        InspectNode,
        ConnectNode,
        PingOne,
        ToggleSub,
        RefreshSub,
        SdImport,
        SimScan,
        SetLogFilter,
        SimLog,
        AddRule,
        SetRuleBucket,
        DelRule,
        CycleTitleId,
        SetTitleIdMode,
        SetSettingsCat,
        ToggleQuic,
        ToggleDoh,
        ToggleAutoBoot,
        SetUtls,
        SetFragMode,
        RunSpeedTest,
        CheckUpdate,
        SelectPalette,
        ToggleAmoled,
    };

    struct HitZone {
        float x = 0.0f;
        float y = 0.0f;
        float w = 0.0f;
        float h = 0.0f;
        HitAction action = HitAction::None;
        int arg0 = 0;
        int arg1 = 0;
        bool focusable = true;
        float tl = 16.0f, tr = 16.0f, br = 16.0f, bl = 16.0f;
    };

    struct SubRefreshResult {
        std::string sub_id;
        bool ok = false;
        std::string error;
        std::vector<ProxyNode> nodes;
        std::optional<parse::SubscriptionUserInfo> user_info;
        std::string remote_title;
    };

    void InitSeedData();
    void LoadFromDisk();
    void SaveConfigAndSync();
    void SyncSubRecordsToUi();
    void StartBackgroundServices();
    void StopBackgroundServices();
    void PushRemoteSnapshot();
    void PollBackgroundServices();
    void HandleRemoteCommands();
    void StartSubscriptionRefresh(size_t sub_idx);
    void StartLoopbackPairSim();
    void RefreshFromCtl(bool force);
    void ToggleTunnel();
    void ShiftTab(int delta);
    void ExecuteHit(const HitZone& hz);
    void ShowToast(const std::string& msg);
    void AddCustomRuleAction(CustomRules::Action action, const std::string& host);
    void ImportFromSd();
    void RunPingMeasure(int node_idx_or_all);

    static void SubRefreshThreadEntry(void* arg);
    static void PairSimThreadEntry(void* arg);

    void RenderRail(NVGcontext* vg);
    void RenderConnectTab(NVGcontext* vg);
    void RenderServersTab(NVGcontext* vg);
    void RenderSubsTab(NVGcontext* vg);
    void RenderRulesTab(NVGcontext* vg);
    void RenderSettingsTab(NVGcontext* vg);
    void RenderTopBar(NVGcontext* vg, const char* title, const char* subtitle, bool show_status_pill);
    void RenderToast(NVGcontext* vg);

    void PushHit(float x, float y, float w, float h, HitAction act,
                 int arg0 = 0, int arg1 = 0, bool focusable = true,
                 float r_tl = 18.0f, float r_tr = 18.0f, float r_br = 18.0f, float r_bl = 18.0f);

    [[nodiscard]] const UiServerEntry& ActiveServer() const;
    [[nodiscard]] int ActiveServerIndex() const;
    [[nodiscard]] std::vector<int> FilteredServerIndices() const;
    [[nodiscard]] int CountCustomRules() const;
    [[nodiscard]] bool IsSubEnabled(const std::string& sub_id) const;
    [[nodiscard]] uint64_t ActiveConnectedSeconds() const noexcept;

    ipc::IYumiCtlClient& ctl_;
    std::string font_dir_;
    bool is_desktop_preview_ = false;
    bool headless_mode_ = false;
    std::string lan_ip_ = "127.0.0.1";

    int font_display_ = -1;
    int font_semibold_ = -1;
    int font_medium_ = -1;
    int font_regular_ = -1;
    int font_mono_ = -1;

    YumiTheme theme_{};
    UiTab active_tab_ = UiTab::Connect;
    SettingsCategory settings_cat_ = SettingsCategory::Routing;
    bool vis_planet_ = false;

    bool ctl_connected_ = false;
    ipc::IpcVersionInfo version_info_{};
    ipc::IpcStatus status_{};
    ipc::IpcTrafficStats stats_{};
    AppSettings settings_{};

    std::vector<UiServerEntry> servers_;
    std::vector<UiSubEntry> subs_;
    std::vector<parse::SubscriptionRecord> sub_records_;
    std::vector<UiTitleEntry> title_ids_;
    std::vector<UiLogEntry> logs_;
    uint32_t last_conn_seq_ = 0;

    int nodes_revision_ = 1;
    int subs_revision_ = 1;

    logic::PairingServer pairing_server_;
    logic::RemoteServer remote_server_;
    logic::RemoteBeacon remote_beacon_;
    logic::AsyncLatencyBatch latency_batch_;
    logic::AsyncSpeedTestRunner speed_runner_;
    logic::AsyncUpdateChecker update_checker_;

    logic::SimpleMutex async_mu_;
    logic::WorkerThread sub_refresh_worker_;
    std::atomic<bool> sub_refresh_busy_{false};
    parse::SubscriptionRecord sub_refresh_job_{};
    std::vector<SubRefreshResult> sub_refresh_done_;
    std::vector<logic::SubscriptionTransfer> pairing_done_;
    std::vector<std::string> pinging_ids_;

    logic::WorkerThread pair_sim_worker_;
    std::string pair_sim_uri_;

    std::string speedtest_url_dl_ = "https://speed.cloudflare.com/__down?bytes=2000000";
    std::string speedtest_url_ul_ = "https://speed.cloudflare.com/__up";
    std::string update_repo_ = "GXUser7/YumiSwitch";
    std::string app_version_ = "1.0.1";

    int inspected_node_idx_ = 0;
    int proto_filter_ = 0;      // 0=All, 1=VLESS, 2=WG, 3=Hy2, 4=Trojan, 5=SS
    int log_filter_ = 0;        // 0=All, 1=Proxy, 2=Direct, 3=Block
    int rule_bucket_ = 0;       // 0=Proxy, 1=Direct, 2=Block
    float list_scroll_servers_ = 0.0f;
    float list_scroll_logs_ = 0.0f;

    bool phone_scanned_ = false;
    bool sd_imported_ = false;
    std::string speedtest_result_ = "Не замерялось";
    std::string update_status_ = "v1.0.1 · Актуально";

    QrMatrix qr_pair_{};
    QrMatrix qr_remote_{};

    double anim_sec_ = 0.0;
    double connected_elapsed_sec_ = 0.0;
    double poll_timer_ = 0.0;
    float down_swell_ = 0.72f;
    float up_swell_ = 0.36f;
    PlanetCameraState planet_cam_{};
    int shoulder_flash_l_ = 0;
    int shoulder_flash_r_ = 0;

    std::string toast_msg_;
    double toast_ttl_ = 0.0;

    std::vector<HitZone> hit_zones_;
    int focus_idx_ = 0;
};

}  // namespace yumi_nx::ui
