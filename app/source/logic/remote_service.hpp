#pragma once

#include <atomic>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "sync_util.hpp"
#include "yumi_nx/crypto.hpp"
#include "yumi_nx/models.hpp"
#include "yumi_nx/socket_io.hpp"
#include "yumi_nx/subscription_parser.hpp"

namespace yumi_nx::logic {

inline constexpr int kRemoteVersion = 1;
inline constexpr uint16_t kRemoteDefaultPort = 47654;
inline constexpr uint16_t kRemoteBeaconPort = 47655;
inline constexpr size_t kRemoteMaxFrameBytes = 512 * 1024;
inline constexpr int64_t kRemotePairingLifetimeMs = 5LL * 60 * 1000;

struct RemoteInviteInfo {
    bool valid = false;
    int version = kRemoteVersion;
    std::string host;
    uint16_t port = 0;
    std::string code;
    uint8_t host_pub65[65]{};
    std::string host_id;
    std::string host_name;
};

struct RemotePeer {
    std::string id;
    std::string name;
    std::string secret;
    int64_t paired_at_epoch_ms = 0;
    int64_t last_seen_epoch_ms = 0;
};

struct RemoteBond {
    bool valid = false;
    std::string host_id;
    std::string host_name;
    std::string host_public_key_b64;
    std::string peer_id;
    std::string secret;
    std::string last_host;
    uint16_t last_port = kRemoteDefaultPort;
};

struct RemoteBeaconSighting {
    bool valid = false;
    std::string host_id;
    std::string host_name;
    std::string host;
    uint16_t port = 0;
};

struct RemoteNodeSnapshot {
    std::string id;
    std::string name;
    std::string group;
    int latency_ms = -1;
    bool latency_failed = false;
    Protocol protocol = Protocol::Vless;
    std::vector<std::string> badges;
    std::string subscription_id;
};

struct RemoteSubSnapshot {
    std::string id;
    std::string name;
    std::string remote_title;
    std::string url_host;
    bool enabled = true;
    int node_count = 0;
    int64_t last_updated_epoch_ms = 0;
    std::string last_error;
    std::optional<parse::SubscriptionUserInfo> user_info;
    bool refreshing = false;
};

struct RemoteHostSnapshot {
    std::string host_name = "Nintendo Switch";
    std::string state = "Off";  // "Off", "Warming", "On", "Stopping", "Failed"
    std::string message;
    bool needs_consent_on_tv = false;
    std::string selected_node_id;
    int64_t connected_at_epoch_ms = 0;
    uint64_t download_bytes_per_sec = 0;
    uint64_t upload_bytes_per_sec = 0;
    int nodes_revision = 1;
    std::vector<RemoteNodeSnapshot> nodes;
    std::vector<std::string> pinging_node_ids;
    int subscriptions_revision = 1;
    std::vector<RemoteSubSnapshot> subscriptions;
    AppSettings settings{};
};

struct RemoteCommand {
    enum class Type : uint8_t {
        Look = 0,
        Connect,
        Disconnect,
        Select,
        PingAll,
        PingOne,
        AddSub,
        RefreshSub,
        RemoveSub,
        ToggleSub,
        UpdateSettings,
    };

    Type type = Type::Look;
    std::string node_id;
    std::vector<std::string> node_ids;
    std::string url;
    std::string name;
    std::string subscription_id;
    bool enabled = true;
    std::string settings_patch_json;
};

/// KDF matching Android `RemoteCrypto.sessionKey`:
/// material = shared32 || secret_utf8; salt = SHA256(sid);
/// extract = HMAC-SHA256(salt, material); key = HMAC-SHA256(extract, "yumi-remote-v1 ").
void DeriveRemoteSessionKey(const uint8_t shared32[32],
                            std::string_view session_id,
                            std::string_view secret_utf8,
                            uint8_t out_key32[32]) noexcept;

[[nodiscard]] std::string BuildRemoteAad(std::string_view session_id,
                                         bool from_phone,
                                         uint64_t counter);

[[nodiscard]] std::string BuildRemoteInviteUri(std::string_view host,
                                               uint16_t port,
                                               std::string_view code,
                                               const uint8_t host_pub65[65],
                                               std::string_view host_id,
                                               std::string_view host_name);

[[nodiscard]] RemoteInviteInfo ParseRemoteInviteUri(std::string_view uri);

class RemoteIdentityStore {
public:
    bool LoadOrInit(std::string identity_path, std::string default_host_name = "Nintendo Switch");
    bool Save() const;

    [[nodiscard]] const std::string& HostId() const noexcept { return host_id_; }
    [[nodiscard]] const std::string& HostName() const noexcept { return host_name_; }
    [[nodiscard]] const net::crypto::P256KeyPair& KeyPair() const noexcept { return keypair_; }
    [[nodiscard]] const std::vector<RemotePeer>& Peers() const noexcept { return peers_; }

    [[nodiscard]] std::string FindPeerSecret(std::string_view peer_id) const;
    void TouchPeer(std::string_view peer_id, int64_t now_epoch_ms);
    RemotePeer AddNewPeer(std::string_view device_name, int64_t now_epoch_ms);

private:
    std::string path_;
    std::string host_id_;
    std::string host_name_ = "Nintendo Switch";
    net::crypto::P256KeyPair keypair_{};
    std::vector<RemotePeer> peers_;
};

/// UDP discovery responder compatible with Android `RemoteDiscovery.kt` (`"yumi-remote-probe-v1"` -> Beacon JSON).
class RemoteBeacon {
public:
    RemoteBeacon() noexcept = default;
    ~RemoteBeacon() { Stop(); }

    RemoteBeacon(const RemoteBeacon&) = delete;
    RemoteBeacon& operator=(const RemoteBeacon&) = delete;

    bool Start(std::string host_id,
               std::string host_name,
               uint16_t tcp_port,
               bool loopback_only = false,
               uint16_t bind_port = kRemoteBeaconPort);

    void UpdateTcpPort(uint16_t tcp_port) noexcept { tcp_port_.store(tcp_port); }
    void Stop() noexcept;

    [[nodiscard]] uint16_t BoundPort() const noexcept { return bound_port_.load(); }
    [[nodiscard]] bool IsRunning() const noexcept { return running_.load(); }

private:
    static void ThreadEntry(void* arg);
    void RunLoop();

    SimpleMutex mu_{};
    WorkerThread worker_{};
    net::NetSocket sock_{};
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> running_{false};
    std::atomic<uint16_t> tcp_port_{0};
    std::atomic<uint16_t> bound_port_{0};
    std::string host_id_;
    std::string host_name_;
};

/// Persistent encrypted LAN remote-control host compatible with Android `RemoteServer`.
class RemoteServer {
public:
    RemoteServer() noexcept = default;
    ~RemoteServer() { Stop(); }

    RemoteServer(const RemoteServer&) = delete;
    RemoteServer& operator=(const RemoteServer&) = delete;

    bool Start(std::string advertise_host,
               std::string identity_path,
               std::string host_name = "Nintendo Switch",
               bool loopback_only = false,
               uint16_t preferred_port = kRemoteDefaultPort);

    void Stop() noexcept;

    void RotatePairingCode();
    void SetSnapshot(const RemoteHostSnapshot& snapshot);
    void DrainCommands(std::vector<RemoteCommand>& out);

    [[nodiscard]] std::string ShareUrl();
    [[nodiscard]] std::string HostId();
    [[nodiscard]] std::string HostName();
    [[nodiscard]] uint16_t Port() const noexcept { return port_.load(); }
    [[nodiscard]] size_t TrustedPeerCount();
    [[nodiscard]] size_t ActiveClientCount() const noexcept { return active_clients_.load(); }
    [[nodiscard]] bool IsRunning() const noexcept { return running_.load(); }

private:
    static constexpr size_t kMaxClients = 4;

    struct ClientSession {
        net::NetSocket sock;
        std::vector<uint8_t> rx_buf;
        std::vector<uint8_t> tx_buf;
        size_t tx_off = 0;

        bool handshaked = false;
        std::string session_id;
        std::string peer_id;
        uint8_t key[32]{};
        uint64_t send_counter = 1;
        uint64_t recv_counter = 1;
        int sent_nodes_rev = -1;
        int sent_subs_rev = -1;
        uint64_t last_send_ms = 0;
        uint64_t last_rx_ms = 0;
    };

    static void ThreadEntry(void* arg);
    void RunLoop();
    void AcceptNewClients();
    void CloseClient(size_t idx);
    bool ProcessClientRx(size_t idx);
    bool HandleGreetingFrame(ClientSession& cs, const std::string& json_str);
    bool HandleCommandFrame(ClientSession& cs, const std::string& json_str);
    bool QueueEncryptedSnapshot(ClientSession& cs, const RemoteHostSnapshot& snap);
    bool FlushClientTx(size_t idx);
    [[nodiscard]] std::string SerializeSnapshotJson(const RemoteHostSnapshot& snap,
                                                    bool include_nodes,
                                                    bool include_subs) const;

    SimpleMutex mu_{};
    WorkerThread worker_{};
    net::NetSocket listener_{};

    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> running_{false};
    std::atomic<uint16_t> port_{0};
    std::atomic<size_t> active_clients_{0};

    std::string advertise_host_;
    RemoteIdentityStore store_;
    std::string pairing_code_;
    int64_t pairing_expires_ms_ = 0;

    RemoteHostSnapshot snapshot_{};
    bool snapshot_dirty_ = false;
    std::vector<RemoteCommand> command_queue_;
    std::vector<ClientSession> clients_;
};

/// Applies a JSON settings patch received via `RemoteCommand::Type::UpdateSettings`.
bool ApplyRemoteSettingsPatch(std::string_view patch_json, AppSettings& in_out_settings);

// --- Client helpers (for E2E loopback testing and diagnostics) ---

[[nodiscard]] RemoteBeaconSighting ProbeRemoteBeacon(uint32_t target_ipv4_host,
                                                     uint16_t beacon_port,
                                                     int timeout_ms = 1200);

[[nodiscard]] RemoteBond RemoteClientPair(std::string_view invite_uri,
                                          std::string_view device_name,
                                          int timeout_ms = 5000);

[[nodiscard]] bool RemoteClientSessionExchange(const RemoteBond& bond,
                                               uint32_t host_ipv4,
                                               uint16_t port,
                                               std::string_view device_name,
                                               const std::vector<std::string>& raw_command_jsons,
                                               std::vector<std::string>& out_snapshot_jsons,
                                               int timeout_ms = 4000);

}  // namespace yumi_nx::logic
