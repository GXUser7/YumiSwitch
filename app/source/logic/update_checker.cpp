#include "update_checker.hpp"

#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>

#include "http_client.hpp"
#include "yumi_nx/paths.hpp"

namespace yumi_nx::logic {

namespace {

void ParseVersionTuple(std::string_view v, uint64_t out[3]) noexcept {
    out[0] = out[1] = out[2] = 0;
    while (!v.empty() && (v.front() == 'v' || v.front() == 'V' || v.front() == ' ')) {
        v.remove_prefix(1);
    }
    size_t pos = 0;
    for (int part = 0; part < 3 && pos < v.size(); ++part) {
        uint64_t val = 0;
        bool any = false;
        while (pos < v.size() && v[pos] >= '0' && v[pos] <= '9') {
            val = val * 10ULL + static_cast<uint64_t>(v[pos] - '0');
            ++pos;
            any = true;
        }
        if (any) out[part] = val;
        if (pos < v.size() && v[pos] == '.') {
            ++pos;
        } else {
            break;
        }
    }
}

bool EndsWithCi(std::string_view s, std::string_view suffix) noexcept {
    if (suffix.empty()) return true;
    if (s.size() < suffix.size()) return false;
    const size_t off = s.size() - suffix.size();
    for (size_t i = 0; i < suffix.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(s[off + i])) !=
            std::tolower(static_cast<unsigned char>(suffix[i]))) {
            return false;
        }
    }
    return true;
}

std::string NormalizeTagVersion(std::string_view tag) {
    while (!tag.empty() && (tag.front() == 'v' || tag.front() == 'V' || tag.front() == ' ')) {
        tag.remove_prefix(1);
    }
    return std::string(tag);
}

}  // namespace

int CompareSemVer(std::string_view a, std::string_view b) noexcept {
    uint64_t va[3]{};
    uint64_t vb[3]{};
    ParseVersionTuple(a, va);
    ParseVersionTuple(b, vb);
    for (int i = 0; i < 3; ++i) {
        if (va[i] < vb[i]) return -1;
        if (va[i] > vb[i]) return 1;
    }
    return 0;
}

UpdateReleaseInfo ParseGitHubReleaseJson(std::string_view json_text,
                                         std::string_view current_version,
                                         std::string_view preferred_asset_ext) {
    UpdateReleaseInfo info;
    info.current_version = NormalizeTagVersion(current_version);

    auto doc = nlohmann::json::parse(json_text, nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) {
        info.error = "Invalid release JSON";
        return info;
    }
    if (!doc.contains("tag_name") || !doc["tag_name"].is_string()) {
        info.error = "Missing tag_name";
        return info;
    }

    info.latest_version = NormalizeTagVersion(doc["tag_name"].get<std::string>());
    if (doc.contains("body") && doc["body"].is_string()) {
        info.changelog = doc["body"].get<std::string>();
    }

    if (doc.contains("assets") && doc["assets"].is_array()) {
        bool picked_preferred = false;
        for (const auto& a : doc["assets"]) {
            if (!a.is_object()) continue;
            if (!a.contains("name") || !a["name"].is_string()) continue;
            if (!a.contains("browser_download_url") || !a["browser_download_url"].is_string()) continue;

            const std::string name = a["name"].get<std::string>();
            const std::string url = a["browser_download_url"].get<std::string>();
            const uint64_t sz = (a.contains("size") && a["size"].is_number_unsigned())
                ? a["size"].get<uint64_t>() : 0ULL;

            const bool is_pref = EndsWithCi(name, preferred_asset_ext);
            if (!picked_preferred || is_pref) {
                info.asset_name = name;
                info.download_url = url;
                info.asset_size = sz;
                if (is_pref) {
                    picked_preferred = true;
                    break;
                }
            }
        }
    }

    info.check_ok = !info.latest_version.empty();
    info.update_available = info.check_ok && (CompareSemVer(info.latest_version, info.current_version) > 0);
    return info;
}

UpdateReleaseInfo CheckLatestGitHubRelease(std::string_view owner_repo,
                                           std::string_view current_version,
                                           const AppSettings& settings,
                                           const ProxyNode* via_node,
                                           std::string_view api_base_url_override,
                                           std::string_view preferred_asset_ext) {
    UpdateReleaseInfo info;
    info.current_version = NormalizeTagVersion(current_version);
    if (owner_repo.empty()) {
        info.error = "Empty repository";
        return info;
    }

    std::string api_base = api_base_url_override.empty()
        ? std::string("https://api.github.com")
        : std::string(api_base_url_override);
    while (!api_base.empty() && api_base.back() == '/') api_base.pop_back();

    HttpRequest req;
    req.method = "GET";
    req.url = api_base + "/repos/" + std::string(owner_repo) + "/releases/latest";
    req.headers.emplace_back("Accept", "application/vnd.github+json");
    req.headers.emplace_back("X-GitHub-Api-Version", "2022-11-28");
    req.user_agent = "YumiSwitch/" + info.current_version;
    req.timeout_ms = 9000;
    req.via_node = via_node;
    req.settings = settings;

    const HttpResponse resp = ExecuteHttpRequest(req);
    if (resp.ok && resp.status_code >= 200 && resp.status_code < 300) {
        return ParseGitHubReleaseJson(resp.body, current_version, preferred_asset_ext);
    }

    // Fallback when API is rate-limited (403/429) on public GitHub host
    if (api_base_url_override.empty()) {
        HttpRequest head_req;
        head_req.method = "HEAD";
        head_req.url = "https://github.com/" + std::string(owner_repo) + "/releases/latest";
        head_req.follow_redirects = false;
        head_req.timeout_ms = 8000;
        head_req.via_node = via_node;
        head_req.settings = settings;
        const HttpResponse hresp = ExecuteHttpRequest(head_req);
        const std::string loc = hresp.Header("location");
        const size_t pos = loc.rfind("/releases/tag/");
        if (pos != std::string::npos) {
            info.latest_version = NormalizeTagVersion(loc.substr(pos + 14));
            info.check_ok = !info.latest_version.empty();
            info.update_available = info.check_ok && (CompareSemVer(info.latest_version, info.current_version) > 0);
            info.asset_name = "yumi.nro";
            info.download_url = "https://github.com/" + std::string(owner_repo) +
                                "/releases/download/v" + info.latest_version + "/yumi.nro";
            return info;
        }
    }

    info.error = resp.error.empty() ? ("HTTP " + std::to_string(resp.status_code)) : resp.error;
    return info;
}

bool AsyncUpdateChecker::StartCheck(std::string owner_repo,
                                    std::string current_version,
                                    AppSettings settings,
                                    const ProxyNode* via_node,
                                    bool auto_download_if_newer) {
    Stop();
    {
        SimpleLock lk(mu_);
        owner_repo_ = owner_repo.empty() ? std::string("GXUser7/YumiSwitch") : std::move(owner_repo);
        current_version_ = current_version.empty() ? std::string("1.0.1") : std::move(current_version);
        settings_ = std::move(settings);
        has_via_node_ = (via_node != nullptr);
        if (has_via_node_) owned_via_node_ = *via_node;
        auto_download_ = auto_download_if_newer;
        state_ = {};
        state_.busy = true;
        state_.status_line = "Проверка GitHub Releases…";
    }
    stop_requested_.store(false);
    busy_.store(true);
    if (!worker_.Start(&AsyncUpdateChecker::ThreadEntry, this, 0x10000)) {
        busy_.store(false);
        SimpleLock lk(mu_);
        state_.busy = false;
        state_.finished = true;
        state_.status_line = "Ошибка запуска проверки";
        return false;
    }
    return true;
}

void AsyncUpdateChecker::Stop() noexcept {
    stop_requested_.store(true);
    worker_.Join();
    busy_.store(false);
}

UpdateProgressState AsyncUpdateChecker::Snapshot() {
    SimpleLock lk(mu_);
    return state_;
}

void AsyncUpdateChecker::ThreadEntry(void* arg) {
    if (auto* self = static_cast<AsyncUpdateChecker*>(arg)) {
        self->Run();
    }
}

void AsyncUpdateChecker::Run() {
    std::string repo, ver;
    AppSettings cfg;
    const ProxyNode* via = nullptr;
    ProxyNode via_copy;
    bool auto_dl = false;
    {
        SimpleLock lk(mu_);
        repo = owner_repo_;
        ver = current_version_;
        cfg = settings_;
        if (has_via_node_) {
            via_copy = owned_via_node_;
            via = &via_copy;
        }
        auto_dl = auto_download_;
    }

    UpdateReleaseInfo rel = CheckLatestGitHubRelease(repo, ver, cfg, via);
    UpdateProgressState st;
    st.release = rel;
    if (!rel.check_ok) {
        st.busy = false;
        st.finished = true;
        st.status_line = "Ошибка проверки: " + rel.error;
    } else if (!rel.update_available) {
        st.busy = false;
        st.finished = true;
        st.progress_0_1 = 1.0;
        st.status_line = "v" + rel.current_version + " · Актуальная сборка";
    } else if (auto_dl && !rel.download_url.empty() && !stop_requested_.load()) {
        st.busy = true;
        st.status_line = "Загрузка v" + rel.latest_version + "…";
        {
            SimpleLock lk(mu_);
            state_ = st;
        }
        const std::string fname = rel.asset_name.empty() ? std::string("yumi.nro") : rel.asset_name;
        const std::string upd_dir = paths::Join(paths::kConfigDir, "updates");
        const std::string dest = paths::Join(upd_dir.c_str(), fname.c_str());
        HttpRequest dl_req;
        dl_req.method = "GET";
        dl_req.url = rel.download_url;
        dl_req.timeout_ms = 20000;
        dl_req.max_response_bytes = 32 * 1024 * 1024;
        dl_req.via_node = via;
        dl_req.settings = cfg;

        const HttpResponse dl = DownloadHttpFileAtomic(
            dl_req,
            dest,
            [&](uint64_t got, int64_t tot) {
                SimpleLock lk(mu_);
                if (tot > 0) {
                    state_.progress_0_1 = std::clamp(static_cast<double>(got) / static_cast<double>(tot), 0.0, 1.0);
                }
            },
            &stop_requested_);
        st.busy = false;
        st.finished = true;
        if (dl.ok && dl.status_code >= 200 && dl.status_code < 300) {
            st.progress_0_1 = 1.0;
            st.downloaded_path = dest;
            st.status_line = "Скачано v" + rel.latest_version + " -> updates/" + fname;
        } else {
            st.status_line = "Доступна v" + rel.latest_version + " (сбой загрузки)";
        }
    } else {
        st.busy = false;
        st.finished = true;
        st.progress_0_1 = 1.0;
        st.status_line = "Доступна v" + rel.latest_version + " (текущая v" + rel.current_version + ")";
    }

    {
        SimpleLock lk(mu_);
        state_ = std::move(st);
    }
    busy_.store(false);
}

}  // namespace yumi_nx::logic
