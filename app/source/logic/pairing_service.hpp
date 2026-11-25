#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "sync_util.hpp"
#include "yumi_nx/crypto.hpp"
#include "yumi_nx/models.hpp"
#include "yumi_nx/socket_io.hpp"

namespace yumi_nx::logic {

inline constexpr int kPairingProtocolVersion = 1;
inline constexpr size_t kPairingMaxFrameBytes = 64 * 1024;
inline constexpr int64_t kPairingLifetimeMs = 5LL * 60 * 1000;

struct PairingLinkInfo {
    bool valid = false;
    int version = 1;
    std::string host;
    uint16_t port = 0;
    std::string session_id;
    uint8_t receiver_pub65[65]{};
    std::string receiver_name;
};

struct SubscriptionTransfer {
    int version = 1;
    std::string name;
    std::string url;
    std::string user_agent_override;
    std::vector<std::pair<std::string, std::string>> headers;
};

struct PairingResult {
    bool accepted = false;
    std::string status;
    std::string subscription_name;
};

enum class PairingServerState : uint8_t {
    Idle = 0,
    Listening = 1,
    AwaitingConfirm = 2,
    Completed = 3,
    Rejected = 4,
    Expired = 5,
    Error = 6,
};

struct PairingSessionSnapshot {
    PairingServerState state = PairingServerState::Idle;
    uint16_t port = 0;
    std::string session_id;
    std::string share_url;
    int64_t expires_at_epoch_ms = 0;
    std::optional<SubscriptionTransfer> pending_transfer;
    std::string status_message;
};

/// Derives 32-byte AES-256-GCM key matching Android `PairingProtocol.deriveKey`:
/// salt = SHA256(sid), extract = HMAC-SHA256(salt, shared32), key = HMAC-SHA256(extract, "yumi-pair-v1\x01").
void DerivePairingKey(const uint8_t shared32[32],
                      std::string_view session_id,
                      uint8_t out_key32[32]) noexcept;

[[nodiscard]] std::string BuildPairUri(std::string_view host,
                                       uint16_t port,
                                       std::string_view session_id,
                                       const uint8_t pub65[65],
                                       std::string_view host_name);

[[nodiscard]] PairingLinkInfo ParsePairUri(std::string_view uri);

/// LAN / loopback receiver compatible with Android `PairingTransport.kt` and `yumi://pair`.
class PairingServer {
public:
    using DecisionCallback = std::function<PairingResult(const SubscriptionTransfer&)>;

    PairingServer() noexcept = default;
    ~PairingServer() { Stop(); }

    PairingServer(const PairingServer&) = delete;
    PairingServer& operator=(const PairingServer&) = delete;

    /// Starts ephemeral P-256 ECDH session and TCP listener.
    /// If `on_transfer` is unset, enters `AwaitingConfirm` and waits up to 60s for `SubmitDecision(bool)`.
    bool Start(std::string advertise_host,
               std::string host_name,
               bool loopback_only = false,
               uint16_t preferred_port = 0,
               DecisionCallback on_transfer = {});

    void Stop() noexcept;

    void SubmitDecision(bool accept, std::string status_override = {});

    [[nodiscard]] PairingSessionSnapshot Snapshot();
    [[nodiscard]] std::string ShareUrl();
    [[nodiscard]] bool IsActive() const noexcept { return running_.load(); }

private:
    static void ThreadEntry(void* arg);
    void RunLoop();
    void HandleClient(net::NetSocket client);

    SimpleMutex mu_{};
    WorkerThread worker_{};
    net::NetSocket listener_{};

    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> running_{false};

    PairingServerState state_ = PairingServerState::Idle;
    uint16_t port_ = 0;
    std::string advertise_host_;
    std::string host_name_;
    std::string session_id_;
    std::string share_url_;
    net::crypto::P256KeyPair keypair_{};
    int64_t expires_at_ms_ = 0;

    DecisionCallback on_transfer_;
    std::optional<SubscriptionTransfer> pending_transfer_;
    bool decision_ready_ = false;
    bool decision_accept_ = false;
    std::string decision_status_;
    std::string status_message_;
};

/// Sends an encrypted `SubscriptionTransfer` to an active `yumi://pair?...` receiver and awaits its reply.
[[nodiscard]] PairingResult SendPairingSubscription(std::string_view pair_uri,
                                                    const SubscriptionTransfer& transfer,
                                                    int timeout_ms = 8000);

}  // namespace yumi_nx::logic
