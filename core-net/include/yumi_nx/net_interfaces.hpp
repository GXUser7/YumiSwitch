#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>

#include "yumi_nx/models.hpp"
#include "yumi_nx/rules_bin.hpp"
#include "yumi_nx/socket_io.hpp"

namespace yumi_nx::net {

struct Endpoint {
    std::string host;
    uint16_t port = 0;
    bool is_udp = false;
    uint64_t program_id = 0;  // Horizon OS TitleID/ProgramID of caller
};

enum class RouteAction : uint8_t {
    Proxy = 0,
    Direct = 1,
    Block = 2,
};

class IRouter {
public:
    virtual ~IRouter() = default;
    [[nodiscard]] virtual RouteAction Decide(const Endpoint& ep, const AppSettings& settings) const = 0;
};

class IDnsResolver {
public:
    virtual ~IDnsResolver() = default;
    [[nodiscard]] virtual bool ResolveIPv4(std::string_view host, uint32_t& out_ipv4_be) = 0;
};

class ITransportLayer {
public:
    virtual ~ITransportLayer() = default;
    [[nodiscard]] virtual TransportKind Kind() const noexcept = 0;
};

class IOutboundDialer {
public:
    virtual ~IOutboundDialer() = default;
    [[nodiscard]] virtual Protocol SupportedProtocol() const noexcept = 0;
    [[nodiscard]] virtual const char* Name() const noexcept = 0;
};

/// Bidirectional proxy stream interface used uniformly by TunnelEngine's non-blocking event loop.
class IOutboundStream {
public:
    virtual ~IOutboundStream() = default;
    [[nodiscard]] virtual Protocol Kind() const noexcept = 0;
    virtual bool Connect(const Endpoint& target, IDnsResolver& resolver, int timeout_ms = 6000) noexcept = 0;
    virtual IoResult WriteNonBlocking(const uint8_t* data, size_t len) noexcept = 0;
    virtual IoResult ReadNonBlocking(uint8_t* out, size_t cap) noexcept = 0;
    virtual bool FlushPending() noexcept = 0;
    [[nodiscard]] virtual bool HasPendingWrite() const noexcept = 0;
    [[nodiscard]] virtual SocketFd NativeFd() const noexcept = 0;
    virtual void Close() noexcept = 0;
};

/// Allocates only the active protocol's dialer stream (lazy RAM conservation on HOS 20.0+).
std::unique_ptr<IOutboundStream> CreateOutboundStream(const ProxyNode& node, const AppSettings& settings = {});

[[nodiscard]] bool ParseIPv4Be(std::string_view text, uint32_t& out_be) noexcept;
[[nodiscard]] bool IsLanOrSpecialIPv4(uint32_t ipv4_be) noexcept;
[[nodiscard]] bool IsLanOrSpecialHost(std::string_view host) noexcept;

class BasicRouter final : public IRouter {
public:
    void SetRulesIndex(rules::RulesIndex index) noexcept { rules_ = std::move(index); }
    bool LoadRulesBin(const std::string& path);
    [[nodiscard]] const rules::RulesIndex& Index() const noexcept { return rules_; }

    [[nodiscard]] RouteAction Decide(const Endpoint& ep, const AppSettings& settings) const override;

private:
    rules::RulesIndex rules_{};
};

}  // namespace yumi_nx::net
