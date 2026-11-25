#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace yumi_nx::net {

#ifdef _WIN32
using SocketFd = uintptr_t;
inline constexpr SocketFd kInvalidSocket = ~uintptr_t(0);
#else
using SocketFd = int;
inline constexpr SocketFd kInvalidSocket = -1;
#endif

enum class IoStatus : uint8_t {
    Ok = 0,
    WouldBlock = 1,
    Eof = 2,
    Error = 3,
};

struct IoResult {
    IoStatus status = IoStatus::Error;
    size_t bytes = 0;
};

struct PollItem {
    SocketFd fd = kInvalidSocket;
    bool want_read = false;
    bool want_write = false;
    bool rev_read = false;
    bool rev_write = false;
    bool rev_err = false;
};

/// Initializes Winsock (Windows) or Switch BSD socket driver (lean memory footprint).
bool SocketLayerInit() noexcept;
void SocketLayerShutdown() noexcept;

/// Monotonic millisecond clock.
[[nodiscard]] uint64_t MonotonicMs() noexcept;

/// Converts host-order IPv4 (0x7F000001) to/from native sockaddr_in bytes (FreeBSD on Switch, POSIX on Windows).
void EncodePlatformSockaddrIn(uint32_t ipv4_host_order, uint16_t port_host_order, uint8_t out_sa[16]) noexcept;
bool DecodePlatformSockaddrIn(const uint8_t* sa, size_t sa_len, uint32_t& out_ipv4_host, uint16_t& out_port_host) noexcept;

class NetSocket {
public:
    NetSocket() noexcept = default;
    explicit NetSocket(SocketFd fd) noexcept : fd_(fd) {}
    ~NetSocket() { Close(); }

    NetSocket(const NetSocket&) = delete;
    NetSocket& operator=(const NetSocket&) = delete;

    NetSocket(NetSocket&& other) noexcept : fd_(other.fd_) { other.fd_ = kInvalidSocket; }
    NetSocket& operator=(NetSocket&& other) noexcept {
        if (this != &other) {
            Close();
            fd_ = other.fd_;
            other.fd_ = kInvalidSocket;
        }
        return *this;
    }

    [[nodiscard]] bool IsValid() const noexcept { return fd_ != kInvalidSocket; }
    [[nodiscard]] SocketFd Fd() const noexcept { return fd_; }

    SocketFd Release() noexcept {
        const SocketFd tmp = fd_;
        fd_ = kInvalidSocket;
        return tmp;
    }

    void Close() noexcept;
    bool SetNonBlocking(bool non_blocking) noexcept;
    bool SetNoDelay(bool no_delay) noexcept;
    bool GetSocketError(int& out_err) const noexcept;
    bool GetLocalPort(uint16_t& out_port) const noexcept;

    IoResult SendSome(const void* data, size_t len) noexcept;
    IoResult RecvSome(void* data, size_t len) noexcept;

    bool SendAllBlocking(const void* data, size_t len, int timeout_ms) noexcept;
    IoResult RecvSomeBlocking(void* data, size_t len, int timeout_ms) noexcept;

    bool ConnectExactBlocking(uint32_t ipv4_host, uint16_t port_host, int timeout_ms) noexcept;

    static NetSocket CreateTcp(bool non_blocking = true) noexcept;
    static NetSocket CreateUdp(bool non_blocking = true) noexcept;
    static NetSocket TcpConnectAsync(uint32_t ipv4_host, uint16_t port_host, bool& out_connected) noexcept;
    static NetSocket TcpListenLoopback(uint16_t& in_out_port) noexcept;
    NetSocket Accept(uint32_t& out_peer_ipv4_host, uint16_t& out_peer_port_host) noexcept;

    bool UdpSendTo(uint32_t ipv4_host, uint16_t port_host, const void* data, size_t len) noexcept;
    IoResult UdpRecvFrom(void* data, size_t cap, uint32_t& out_ipv4_host, uint16_t& out_port_host) noexcept;

private:
    SocketFd fd_ = kInvalidSocket;
};

int PollSockets(PollItem* items, size_t count, int timeout_ms) noexcept;
bool WaitSingleSocket(SocketFd fd, bool read, bool write, int timeout_ms) noexcept;

}  // namespace yumi_nx::net
