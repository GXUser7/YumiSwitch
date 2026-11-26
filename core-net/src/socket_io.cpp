#include "yumi_nx/socket_io.hpp"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(__SWITCH__)
#include <switch.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#else
#include <arpa/inet.h>
#include <chrono>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace yumi_nx::net {

namespace {

std::atomic<bool> g_sock_inited{false};

bool IsWouldBlockError() noexcept {
#ifdef _WIN32
    const int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEALREADY;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS || errno == EALREADY;
#endif
}

bool IsConnectInProgressError() noexcept {
#ifdef _WIN32
    const int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS;
#else
    return errno == EINPROGRESS || errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

}  // namespace

bool SocketLayerInit(bool low_memory) noexcept {
    if (g_sock_inited.load()) return true;
#ifdef _WIN32
    (void)low_memory;
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return false;
    g_sock_inited.store(true);
    return true;
#elif defined(__SWITCH__)
    SocketInitConfig cfg = *socketGetDefaultInitConfig();
    if (low_memory) {
        // Lean footprint for sysmodule under HOS 20.0+ System RAM limits (~212 KB transfer memory).
        cfg.tcp_tx_buf_size = 0x4000;
        cfg.tcp_rx_buf_size = 0x4000;
        cfg.tcp_tx_buf_max_size = 0x8000;
        cfg.tcp_rx_buf_max_size = 0x8000;
        cfg.udp_tx_buf_size = 0x2400;
        cfg.udp_rx_buf_size = 0x8000;
        cfg.sb_efficiency = 2;
        cfg.num_bsd_sessions = 2;
    } else {
        // Application mode: enough concurrent BSD sessions for Remote/Pairing/HTTP threads.
        cfg.tcp_tx_buf_size = 0x4000;
        cfg.tcp_rx_buf_size = 0x4000;
        cfg.tcp_tx_buf_max_size = 0x8000;
        cfg.tcp_rx_buf_max_size = 0x8000;
        cfg.udp_tx_buf_size = 0x2400;
        cfg.udp_rx_buf_size = 0xA500;
        cfg.sb_efficiency = 4;
        cfg.num_bsd_sessions = 8;
    }
    cfg.bsd_service_type = BsdServiceType_User;
    const Result rc = socketInitialize(&cfg);
    if (R_SUCCEEDED(rc)) {
        g_sock_inited.store(true);
        return true;
    }
    return false;
#else
    (void)low_memory;
    g_sock_inited.store(true);
    return true;
#endif
}

void SocketLayerShutdown() noexcept {
    if (!g_sock_inited.exchange(false)) return;
#ifdef _WIN32
    WSACleanup();
#elif defined(__SWITCH__)
    socketExit();
#endif
}

uint64_t MonotonicMs() noexcept {
#ifdef __SWITCH__
    return armTicksToNs(armGetSystemTick()) / 1'000'000ULL;
#elif defined(_WIN32)
    return GetTickCount64();
#else
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
#endif
}

void EncodePlatformSockaddrIn(uint32_t ipv4_host_order, uint16_t port_host_order, uint8_t out_sa[16]) noexcept {
    std::memset(out_sa, 0, 16);
#ifdef __SWITCH__
    out_sa[0] = 16;  // FreeBSD sin_len
    out_sa[1] = 2;   // AF_INET
#else
    out_sa[0] = 2;   // Windows / Linux sa_family_t (LE 16-bit AF_INET)
    out_sa[1] = 0;
#endif
    out_sa[2] = static_cast<uint8_t>((port_host_order >> 8) & 0xFFu);
    out_sa[3] = static_cast<uint8_t>(port_host_order & 0xFFu);
    out_sa[4] = static_cast<uint8_t>((ipv4_host_order >> 24) & 0xFFu);
    out_sa[5] = static_cast<uint8_t>((ipv4_host_order >> 16) & 0xFFu);
    out_sa[6] = static_cast<uint8_t>((ipv4_host_order >> 8) & 0xFFu);
    out_sa[7] = static_cast<uint8_t>(ipv4_host_order & 0xFFu);
}

bool DecodePlatformSockaddrIn(const uint8_t* sa, size_t sa_len, uint32_t& out_ipv4_host, uint16_t& out_port_host) noexcept {
    if (!sa || sa_len < 8) return false;
    uint8_t fam = sa[1];
    if (fam == 0 && sa[0] == 2) fam = 2;  // POSIX little-endian AF_INET
    if (fam != 2) return false;
    out_port_host = static_cast<uint16_t>((uint16_t(sa[2]) << 8) | sa[3]);
    out_ipv4_host = (uint32_t(sa[4]) << 24) | (uint32_t(sa[5]) << 16) | (uint32_t(sa[6]) << 8) | uint32_t(sa[7]);
    return true;
}

void NetSocket::Close() noexcept {
    if (fd_ != kInvalidSocket) {
#ifdef _WIN32
        ::closesocket(fd_);
#else
        ::close(fd_);
#endif
        fd_ = kInvalidSocket;
    }
}

bool NetSocket::SetNonBlocking(bool non_blocking) noexcept {
    if (!IsValid()) return false;
#ifdef _WIN32
    u_long mode = non_blocking ? 1UL : 0UL;
    return ::ioctlsocket(fd_, FIONBIO, &mode) == 0;
#else
    int flags = ::fcntl(fd_, F_GETFL, 0);
    if (flags < 0) flags = 0;
    if (non_blocking) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    return ::fcntl(fd_, F_SETFL, flags) == 0;
#endif
}

bool NetSocket::SetNoDelay(bool no_delay) noexcept {
    if (!IsValid()) return false;
    int val = no_delay ? 1 : 0;
    return ::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&val), sizeof(val)) == 0;
}

bool NetSocket::GetSocketError(int& out_err) const noexcept {
    out_err = 0;
    if (!IsValid()) return false;
    socklen_t len = sizeof(out_err);
    return ::getsockopt(fd_, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&out_err), &len) == 0;
}

bool NetSocket::GetLocalPort(uint16_t& out_port) const noexcept {
    out_port = 0;
    if (!IsValid()) return false;
    struct sockaddr_in sa{};
    socklen_t len = sizeof(sa);
    if (::getsockname(fd_, reinterpret_cast<struct sockaddr*>(&sa), &len) != 0) return false;
    out_port = ntohs(sa.sin_port);
    return true;
}

IoResult NetSocket::SendSome(const void* data, size_t len) noexcept {
    if (!IsValid()) return {IoStatus::Error, 0};
    if (len == 0) return {IoStatus::Ok, 0};
#ifdef _WIN32
    const int n = ::send(fd_, static_cast<const char*>(data), static_cast<int>(len), 0);
    if (n > 0) return {IoStatus::Ok, static_cast<size_t>(n)};
    if (n == 0) return {IoStatus::Eof, 0};
    return IsWouldBlockError() ? IoResult{IoStatus::WouldBlock, 0} : IoResult{IoStatus::Error, 0};
#else
    const ssize_t n = ::send(fd_, data, len, 0);
    if (n > 0) return {IoStatus::Ok, static_cast<size_t>(n)};
    if (n == 0) return {IoStatus::Eof, 0};
    if (errno == EINTR) return {IoStatus::WouldBlock, 0};
    return IsWouldBlockError() ? IoResult{IoStatus::WouldBlock, 0} : IoResult{IoStatus::Error, 0};
#endif
}

IoResult NetSocket::RecvSome(void* data, size_t len) noexcept {
    if (!IsValid()) return {IoStatus::Error, 0};
    if (len == 0) return {IoStatus::Ok, 0};
#ifdef _WIN32
    const int n = ::recv(fd_, static_cast<char*>(data), static_cast<int>(len), 0);
    if (n > 0) return {IoStatus::Ok, static_cast<size_t>(n)};
    if (n == 0) return {IoStatus::Eof, 0};
    return IsWouldBlockError() ? IoResult{IoStatus::WouldBlock, 0} : IoResult{IoStatus::Error, 0};
#else
    const ssize_t n = ::recv(fd_, data, len, 0);
    if (n > 0) return {IoStatus::Ok, static_cast<size_t>(n)};
    if (n == 0) return {IoStatus::Eof, 0};
    if (errno == EINTR) return {IoStatus::WouldBlock, 0};
    return IsWouldBlockError() ? IoResult{IoStatus::WouldBlock, 0} : IoResult{IoStatus::Error, 0};
#endif
}

bool NetSocket::SendAllBlocking(const void* data, size_t len, int timeout_ms) noexcept {
    const auto* p = static_cast<const uint8_t*>(data);
    size_t sent = 0;
    const uint64_t deadline = MonotonicMs() + static_cast<uint64_t>(std::max(1, timeout_ms));
    while (sent < len) {
        const auto res = SendSome(p + sent, len - sent);
        if (res.status == IoStatus::Ok) {
            sent += res.bytes;
            continue;
        }
        if (res.status == IoStatus::WouldBlock) {
            const uint64_t now = MonotonicMs();
            if (now >= deadline) return false;
            const int rem = static_cast<int>(std::min<uint64_t>(deadline - now, 250ULL));
            if (!WaitSingleSocket(fd_, false, true, rem)) {
                if (MonotonicMs() >= deadline) return false;
            }
            continue;
        }
        return false;
    }
    return true;
}

IoResult NetSocket::RecvSomeBlocking(void* data, size_t len, int timeout_ms) noexcept {
    const uint64_t deadline = MonotonicMs() + static_cast<uint64_t>(std::max(1, timeout_ms));
    while (true) {
        const auto res = RecvSome(data, len);
        if (res.status != IoStatus::WouldBlock) return res;
        const uint64_t now = MonotonicMs();
        if (now >= deadline) return {IoStatus::WouldBlock, 0};
        const int rem = static_cast<int>(std::min<uint64_t>(deadline - now, 250ULL));
        WaitSingleSocket(fd_, true, false, rem);
    }
}

NetSocket NetSocket::CreateTcp(bool non_blocking) noexcept {
    SocketLayerInit();
    SocketFd fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == kInvalidSocket) return {};
    NetSocket s(fd);
    s.SetNonBlocking(non_blocking);
    s.SetNoDelay(true);
    return s;
}

NetSocket NetSocket::CreateUdp(bool non_blocking) noexcept {
    SocketLayerInit();
    SocketFd fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == kInvalidSocket) return {};
    NetSocket s(fd);
    s.SetNonBlocking(non_blocking);
    return s;
}

NetSocket NetSocket::TcpConnectAsync(uint32_t ipv4_host, uint16_t port_host, bool& out_connected) noexcept {
    out_connected = false;
    NetSocket s = CreateTcp(true);
    if (!s.IsValid()) return {};

    struct sockaddr_in sa{};
    EncodePlatformSockaddrIn(ipv4_host, port_host, reinterpret_cast<uint8_t*>(&sa));
    const int rc = ::connect(s.Fd(), reinterpret_cast<const struct sockaddr*>(&sa), sizeof(sa));
    if (rc == 0) {
        out_connected = true;
        return s;
    }
    if (!IsConnectInProgressError()) {
        return {};
    }
    return s;
}

bool NetSocket::ConnectExactBlocking(uint32_t ipv4_host, uint16_t port_host, int timeout_ms) noexcept {
    Close();
    bool connected = false;
    *this = TcpConnectAsync(ipv4_host, port_host, connected);
    if (!IsValid()) return false;
    if (connected) return true;

    PollItem item{};
    item.fd = fd_;
    item.want_write = true;
    const int rc = PollSockets(&item, 1, timeout_ms);
    if (rc <= 0 || (!item.rev_write && !item.rev_err)) {
        Close();
        return false;
    }
    int err = 0;
    if (!GetSocketError(err) || err != 0) {
        Close();
        return false;
    }
    return true;
}

NetSocket NetSocket::TcpListenLoopback(uint16_t& in_out_port) noexcept {
    NetSocket s = CreateTcp(true);
    if (!s.IsValid()) return {};

    int reuse = 1;
    ::setsockopt(s.Fd(), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    struct sockaddr_in sa{};
    EncodePlatformSockaddrIn(0x7F000001u, in_out_port, reinterpret_cast<uint8_t*>(&sa));
    if (::bind(s.Fd(), reinterpret_cast<const struct sockaddr*>(&sa), sizeof(sa)) != 0) {
        return {};
    }
    if (::listen(s.Fd(), 16) != 0) {
        return {};
    }
    uint16_t actual_port = 0;
    if (!s.GetLocalPort(actual_port) || actual_port == 0) {
        return {};
    }
    in_out_port = actual_port;
    return s;
}

NetSocket NetSocket::Accept(uint32_t& out_peer_ipv4_host, uint16_t& out_peer_port_host) noexcept {
    out_peer_ipv4_host = 0;
    out_peer_port_host = 0;
    if (!IsValid()) return {};
    struct sockaddr_in sa{};
    socklen_t len = sizeof(sa);
    SocketFd cli = ::accept(fd_, reinterpret_cast<struct sockaddr*>(&sa), &len);
    if (cli == kInvalidSocket) return {};
    NetSocket s(cli);
    s.SetNonBlocking(true);
    s.SetNoDelay(true);
    DecodePlatformSockaddrIn(reinterpret_cast<const uint8_t*>(&sa), len, out_peer_ipv4_host, out_peer_port_host);
    return s;
}

bool NetSocket::UdpSendTo(uint32_t ipv4_host, uint16_t port_host, const void* data, size_t len) noexcept {
    if (!IsValid()) return false;
    struct sockaddr_in sa{};
    EncodePlatformSockaddrIn(ipv4_host, port_host, reinterpret_cast<uint8_t*>(&sa));
#ifdef _WIN32
    const int n = ::sendto(fd_, static_cast<const char*>(data), static_cast<int>(len), 0,
                           reinterpret_cast<const struct sockaddr*>(&sa), sizeof(sa));
    return n == static_cast<int>(len);
#else
    const ssize_t n = ::sendto(fd_, data, len, 0, reinterpret_cast<const struct sockaddr*>(&sa), sizeof(sa));
    return n == static_cast<ssize_t>(len);
#endif
}

IoResult NetSocket::UdpRecvFrom(void* data, size_t cap, uint32_t& out_ipv4_host, uint16_t& out_port_host) noexcept {
    out_ipv4_host = 0;
    out_port_host = 0;
    if (!IsValid()) return {IoStatus::Error, 0};
    struct sockaddr_in sa{};
    socklen_t len = sizeof(sa);
#ifdef _WIN32
    const int n = ::recvfrom(fd_, static_cast<char*>(data), static_cast<int>(cap), 0,
                             reinterpret_cast<struct sockaddr*>(&sa), &len);
    if (n > 0) {
        DecodePlatformSockaddrIn(reinterpret_cast<const uint8_t*>(&sa), len, out_ipv4_host, out_port_host);
        return {IoStatus::Ok, static_cast<size_t>(n)};
    }
    if (n == 0) return {IoStatus::Eof, 0};
    return IsWouldBlockError() ? IoResult{IoStatus::WouldBlock, 0} : IoResult{IoStatus::Error, 0};
#else
    const ssize_t n = ::recvfrom(fd_, data, cap, 0, reinterpret_cast<struct sockaddr*>(&sa), &len);
    if (n > 0) {
        DecodePlatformSockaddrIn(reinterpret_cast<const uint8_t*>(&sa), len, out_ipv4_host, out_port_host);
        return {IoStatus::Ok, static_cast<size_t>(n)};
    }
    if (n == 0) return {IoStatus::Eof, 0};
    return IsWouldBlockError() ? IoResult{IoStatus::WouldBlock, 0} : IoResult{IoStatus::Error, 0};
#endif
}

int PollSockets(PollItem* items, size_t count, int timeout_ms) noexcept {
    if (!items || count == 0) return 0;
    std::vector<struct pollfd> fds(count);
    for (size_t i = 0; i < count; ++i) {
        items[i].rev_read = false;
        items[i].rev_write = false;
        items[i].rev_err = false;
        fds[i].fd = items[i].fd;
        fds[i].events = static_cast<short>((items[i].want_read ? POLLIN : 0) | (items[i].want_write ? POLLOUT : 0));
        fds[i].revents = 0;
    }
#ifdef _WIN32
    const int rc = WSAPoll(fds.data(), static_cast<ULONG>(count), timeout_ms);
#else
    const int rc = ::poll(fds.data(), static_cast<nfds_t>(count), timeout_ms);
#endif
    if (rc > 0) {
        for (size_t i = 0; i < count; ++i) {
            items[i].rev_read = (fds[i].revents & POLLIN) != 0;
            items[i].rev_write = (fds[i].revents & POLLOUT) != 0;
            items[i].rev_err = (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0;
        }
    }
    return rc;
}

bool WaitSingleSocket(SocketFd fd, bool read, bool write, int timeout_ms) noexcept {
    PollItem p{};
    p.fd = fd;
    p.want_read = read;
    p.want_write = write;
    const int rc = PollSockets(&p, 1, timeout_ms);
    return rc > 0 && ((read && p.rev_read) || (write && p.rev_write) || p.rev_err);
}

}  // namespace yumi_nx::net
