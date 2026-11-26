#define TESLA_INIT_IMPL
#include <tesla.hpp>
#include <switch/sf/tipc.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "yumi_nx/ipc_protocol.hpp"
#include "yumi_nx/paths.hpp"

namespace {

using namespace yumi_nx;

/// Non-blocking Atmosphère AtmosphereHasService (TIPC 65100) probe so Tesla overlay
/// never hangs indefinitely in smGetService when yumi-sysmodule is stopped.
bool SmHasService(const char* name) noexcept {
    TipcService* sm = smGetServiceSessionTipc();
    if (!sm || sm->session == INVALID_HANDLE) return false;
    const SmServiceName encoded = smEncodeName(name);
    u8 has_service = 0;
    const TipcDispatchParams params{};
    const Result rc = tipcDispatchImpl(
        sm, 65100u, &encoded, sizeof(encoded), &has_service, sizeof(has_service), params);
    return R_SUCCEEDED(rc) && (has_service & 1u) != 0;
}

struct QuickNodeEntry {
    std::string id;
    std::string name;
    int ping_ms = -1;
};

bool CallCtlNoPayload(Service& srv, ipc::YumiCtlCmd cmd) {
    return R_SUCCEEDED(serviceDispatch(&srv, static_cast<u32>(cmd)));
}

template <typename Out>
bool CallCtlOut(Service& srv, ipc::YumiCtlCmd cmd, Out& out) {
    return R_SUCCEEDED(serviceDispatchOut(&srv, static_cast<u32>(cmd), out));
}

template <typename In>
bool CallCtlIn(Service& srv, ipc::YumiCtlCmd cmd, const In& in) {
    return R_SUCCEEDED(serviceDispatchIn(&srv, static_cast<u32>(cmd), in));
}

bool SelectNodeById(Service& srv, const std::string& id) {
    char id_buf[32]{};
    const size_t len = std::min<size_t>(id.size(), sizeof(id_buf) - 1);
    std::memcpy(id_buf, id.data(), len);
    return R_SUCCEEDED(serviceDispatchIn(&srv, static_cast<u32>(ipc::YumiCtlCmd::SelectActiveNode), id_buf));
}

std::vector<QuickNodeEntry> LoadQuickNodes() {
    std::vector<QuickNodeEntry> out;
    FILE* f = std::fopen(paths::QuickNodesFile().c_str(), "rb");
    if (!f) return out;
    char line[192];
    while (std::fgets(line, sizeof(line), f) && out.size() < 4) {
        std::string s(line);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
        const size_t p1 = s.find('|');
        const size_t p2 = (p1 != std::string::npos) ? s.find('|', p1 + 1) : std::string::npos;
        if (p1 == std::string::npos) continue;
        QuickNodeEntry e;
        e.id = s.substr(0, p1);
        e.name = (p2 != std::string::npos) ? s.substr(p1 + 1, p2 - p1 - 1) : s.substr(p1 + 1);
        if (p2 != std::string::npos) e.ping_ms = std::atoi(s.substr(p2 + 1).c_str());
        if (!e.id.empty() && !e.name.empty()) out.push_back(std::move(e));
    }
    std::fclose(f);
    return out;
}

class YumiOverlayGui final : public tsl::Gui {
public:
    YumiOverlayGui() = default;

    ~YumiOverlayGui() override {
        if (serviceIsActive(&ctl_)) {
            serviceClose(&ctl_);
        }
    }

    tsl::elm::Element* createUI() override {
        auto* frame = new tsl::elm::OverlayFrame("Yumi NX", "Tesla HUD · yumi.ovl · HOS 20.0+");
        auto* list = new tsl::elm::List();

        // Telemetry & sysmodule RAM card (Variant A)
        auto* hud_card = new tsl::elm::CustomDrawer([this](tsl::gfx::Renderer* r, s32 x, s32 y, s32 w, s32 h) {
            r->drawRect(x + 6, y + 6, w - 12, h - 12, tsl::Color{0x2, 0x2, 0x3, 0xD});

            const bool connected = serviceIsActive(&ctl_);
            const bool is_on = connected && status_.state == TunnelState::On;
            const double used_mb = connected ? (stats_.sysmodule_heap_used_bytes / (1024.0 * 1024.0)) : 0.0;
            const double total_mb = (connected && stats_.sysmodule_heap_total_bytes > 0)
                ? (stats_.sysmodule_heap_total_bytes / (1024.0 * 1024.0))
                : 1.5;
            const double pct = connected ? std::min(1.0, used_mb / std::max(0.5, total_mb)) : 0.0;

            char ram_line[48];
            if (connected) {
                std::snprintf(ram_line, sizeof(ram_line), "%.2f / %.1f MB (%d%%)",
                              used_mb, total_mb, static_cast<int>(pct * 100.0));
            } else {
                std::snprintf(ram_line, sizeof(ram_line), "sysmodule выкл");
            }
            r->drawString("RAM sysmodule", false, x + 18, y + 32, 16, tsl::Color{0xF, 0xF, 0xF, 0xF});
            r->drawString(ram_line, true, x + w - 175, y + 32, 16, tsl::Color{0xA, 0xC, 0xF, 0xF});

            // Progress track + bar (Glacier primary)
            const s32 bar_x = x + 18;
            const s32 bar_y = y + 46;
            const s32 bar_w = w - 36;
            r->drawRect(bar_x, bar_y, bar_w, 8, tsl::Color{0x3, 0x4, 0x5, 0xF});
            r->drawRect(bar_x, bar_y, static_cast<s32>(bar_w * pct), 8, tsl::Color{0xA, 0xC, 0xF, 0xF});

            char spd_line[64];
            if (is_on) {
                std::snprintf(spd_line, sizeof(spd_line), "%.1f / %.1f MB/s",
                              stats_.downlink_bps / (1024.0 * 1024.0),
                              stats_.uplink_bps / (1024.0 * 1024.0));
            } else if (connected) {
                std::snprintf(spd_line, sizeof(spd_line), "0 / 0 B/s  [%s]", ToString(status_.state));
            } else {
                std::snprintf(spd_line, sizeof(spd_line), "Нет связи с yumi:ctl");
            }
            r->drawString(spd_line, true, x + 18, y + 80, 15, tsl::Color{0xA, 0xB, 0xC, 0xF});
            r->drawString(is_on ? "ON" : "OFF", true, x + w - 58, y + 80, 15,
                          is_on ? tsl::Color{0x7, 0xE, 0xA, 0xF} : tsl::Color{0xF, 0x9, 0x8, 0xF});
        });
        list->addItem(hud_card, 102);

        list->addItem(new tsl::elm::CategoryHeader("Туннель"));

        toggle_item_ = new tsl::elm::ToggleListItem("VPN Туннель", false);
        toggle_item_->setStateChangedListener([this](bool enabled) {
            if (!EnsureConnected()) return;
            CallCtlNoPayload(ctl_, enabled ? ipc::YumiCtlCmd::Start : ipc::YumiCtlCmd::Stop);
            RefreshState();
        });
        list->addItem(toggle_item_);

        mode_item_ = new tsl::elm::ListItem("Маршрутизация", "Rules");
        mode_item_->setClickListener([this](u64 keys) {
            if (!(keys & HidNpadButton_A)) return false;
            if (!EnsureConnected()) return true;
            const u8 next = static_cast<u8>((static_cast<u8>(status_.routing_mode) + 1) % 3);
            CallCtlIn(ctl_, ipc::YumiCtlCmd::SetRoutingMode, next);
            RefreshState();
            return true;
        });
        list->addItem(mode_item_);

        list->addItem(new tsl::elm::CategoryHeader("Быстрые серверы (1 тап)"));
        quick_nodes_ = LoadQuickNodes();
        if (quick_nodes_.empty()) {
            active_fallback_item_ = new tsl::elm::ListItem("Активный сервер", "-");
            list->addItem(active_fallback_item_);
        } else {
            for (const auto& qn : quick_nodes_) {
                char pbuf[24];
                if (qn.ping_ms >= 0) std::snprintf(pbuf, sizeof(pbuf), "%d ms", qn.ping_ms);
                else std::snprintf(pbuf, sizeof(pbuf), "-");
                auto* item = new tsl::elm::ListItem(qn.name, pbuf);
                const std::string node_id = qn.id;
                item->setClickListener([this, node_id](u64 keys) {
                    if (!(keys & HidNpadButton_A)) return false;
                    if (!EnsureConnected()) return true;
                    SelectNodeById(ctl_, node_id);
                    CallCtlNoPayload(ctl_, ipc::YumiCtlCmd::Start);
                    RefreshState();
                    return true;
                });
                list->addItem(item);
                quick_items_.push_back(item);
            }
        }

        RefreshState();
        frame->setContent(list);
        return frame;
    }

    void update() override {
        if (++tick_counter_ >= 30) {
            tick_counter_ = 0;
            RefreshState();
        }
    }

private:
    void DisconnectCtl() noexcept {
        if (serviceIsActive(&ctl_)) {
            serviceClose(&ctl_);
        }
        status_ = ipc::IpcStatus{};
        stats_ = ipc::IpcTrafficStats{};
    }

    bool EnsureConnected() {
        if (serviceIsActive(&ctl_)) return true;
        if (!SmHasService(ipc::kYumiCtlServiceName)) return false;
        return R_SUCCEEDED(smGetService(&ctl_, ipc::kYumiCtlServiceName));
    }

    void RefreshState() {
        if (!EnsureConnected()) {
            toggle_item_->setState(false);
            if (active_fallback_item_) active_fallback_item_->setValue("sysmodule выкл");
            return;
        }
        if (!CallCtlOut(ctl_, ipc::YumiCtlCmd::GetStatus, status_)) {
            DisconnectCtl();
            toggle_item_->setState(false);
            if (active_fallback_item_) active_fallback_item_->setValue("sysmodule выкл");
            return;
        }
        toggle_item_->setState(status_.state == TunnelState::On ||
                               status_.state == TunnelState::Connecting);
        mode_item_->setValue(ToString(status_.routing_mode));
        if (active_fallback_item_) {
            active_fallback_item_->setValue(status_.active_node_name[0] ? status_.active_node_name : "-");
        }
        for (size_t i = 0; i < quick_nodes_.size() && i < quick_items_.size(); ++i) {
            char pbuf[32];
            const bool active = (quick_nodes_[i].id == status_.active_node_id);
            if (quick_nodes_[i].ping_ms >= 0) {
                std::snprintf(pbuf, sizeof(pbuf), active ? "* %d ms" : "%d ms", quick_nodes_[i].ping_ms);
            } else {
                std::snprintf(pbuf, sizeof(pbuf), active ? "*" : "-");
            }
            quick_items_[i]->setValue(pbuf, !active);
        }
        if (!CallCtlOut(ctl_, ipc::YumiCtlCmd::GetTrafficStats, stats_)) {
            DisconnectCtl();
        }
    }

    Service ctl_{};
    ipc::IpcStatus status_{};
    ipc::IpcTrafficStats stats_{};
    tsl::elm::ToggleListItem* toggle_item_ = nullptr;
    tsl::elm::ListItem* mode_item_ = nullptr;
    tsl::elm::ListItem* active_fallback_item_ = nullptr;
    std::vector<QuickNodeEntry> quick_nodes_;
    std::vector<tsl::elm::ListItem*> quick_items_;
    int tick_counter_ = 0;
};

class YumiOverlay final : public tsl::Overlay {
public:
    void initServices() override { smInitialize(); }
    void exitServices() override { smExit(); }
    std::unique_ptr<tsl::Gui> loadInitialGui() override {
        return initially<YumiOverlayGui>();
    }
};

}  // namespace

int main(int argc, char** argv) {
    return tsl::loop<YumiOverlay>(argc, argv);
}
