#pragma once

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>
#include <string_view>

#include "yumi_nx/net_interfaces.hpp"
#include "yumi_nx/socket_io.hpp"

#ifdef __SWITCH__
#include <malloc.h>
#include <netinet/in.h>
#include <switch.h>
#include <sys/socket.h>
#else
#include <chrono>
#include <mutex>
#include <thread>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
#endif

namespace yumi_nx::logic {

class SimpleMutex {
public:
    SimpleMutex() noexcept {
#ifdef __SWITCH__
        mutexInit(&mu_);
#endif
    }
    void Lock() noexcept {
#ifdef __SWITCH__
        mutexLock(&mu_);
#else
        mu_.lock();
#endif
    }
    void Unlock() noexcept {
#ifdef __SWITCH__
        mutexUnlock(&mu_);
#else
        mu_.unlock();
#endif
    }

private:
#ifdef __SWITCH__
    Mutex mu_{};
#else
    std::mutex mu_{};
#endif
};

class SimpleLock {
public:
    explicit SimpleLock(SimpleMutex& m) noexcept : m_(m) { m_.Lock(); }
    ~SimpleLock() { m_.Unlock(); }
    SimpleLock(const SimpleLock&) = delete;
    SimpleLock& operator=(const SimpleLock&) = delete;

private:
    SimpleMutex& m_;
};

inline void SleepMs(uint32_t ms) noexcept {
#ifdef __SWITCH__
    svcSleepThread(static_cast<uint64_t>(ms) * 1000000ULL);
#else
    std::this_thread::sleep_for(std::chrono::milliseconds(ms));
#endif
}

[[nodiscard]] inline int64_t CurrentEpochMs() noexcept {
#ifdef __SWITCH__
    return static_cast<int64_t>(std::time(nullptr)) * 1000LL;
#else
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
#endif
}

[[nodiscard]] inline uint32_t CurrentEpochSec() noexcept {
    const std::time_t now = std::time(nullptr);
    return (now > 0) ? static_cast<uint32_t>(now) : 0U;
}

/// Cross-platform background thread avoiding std::thread exceptions/TLS bloat on Horizon OS.
class WorkerThread {
public:
    using EntryFn = void (*)(void*);

    WorkerThread() noexcept = default;
    ~WorkerThread() { Join(); }

    WorkerThread(const WorkerThread&) = delete;
    WorkerThread& operator=(const WorkerThread&) = delete;

    bool Start(EntryFn fn, void* arg, size_t stack_bytes = 0x10000) noexcept {
        Join();
#ifdef __SWITCH__
        void* stack = ::memalign(0x1000, stack_bytes);
        if (!stack) return false;
        if (R_FAILED(threadCreate(&thread_, fn, arg, stack, stack_bytes, 0x3B, -2)) ||
            R_FAILED(threadStart(&thread_))) {
            std::free(stack);
            return false;
        }
        stack_ = stack;
        running_ = true;
        return true;
#else
        (void)stack_bytes;
        thread_ = std::thread(fn, arg);
        running_ = true;
        return true;
#endif
    }

    void Join() noexcept {
        if (!running_) return;
#ifdef __SWITCH__
        threadWaitForExit(&thread_);
        threadClose(&thread_);
        std::free(stack_);
        stack_ = nullptr;
#else
        if (thread_.joinable()) thread_.join();
#endif
        running_ = false;
    }

    [[nodiscard]] bool IsStarted() const noexcept { return running_; }

private:
#ifdef __SWITCH__
    Thread thread_{};
    void* stack_ = nullptr;
#else
    std::thread thread_{};
#endif
    bool running_ = false;
};

[[nodiscard]] inline bool ParseIpv4HostOrder(std::string_view host, uint32_t& out_ipv4_host) noexcept {
    if (host == "localhost" || host == "LOCALHOST") {
        out_ipv4_host = 0x7F000001u;
        return true;
    }
    return net::ParseIPv4Be(host, out_ipv4_host);
}

[[nodiscard]] inline std::string FormatIpv4HostOrder(uint32_t ipv4_host) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  static_cast<unsigned>((ipv4_host >> 24) & 0xFFu),
                  static_cast<unsigned>((ipv4_host >> 16) & 0xFFu),
                  static_cast<unsigned>((ipv4_host >> 8) & 0xFFu),
                  static_cast<unsigned>(ipv4_host & 0xFFu));
    return std::string(buf);
}

[[nodiscard]] inline net::NetSocket TcpListenSocket(bool loopback_only, uint16_t& in_out_port) noexcept {
    net::NetSocket s = net::NetSocket::CreateTcp(true);
    if (!s.IsValid()) return {};

    int reuse = 1;
    ::setsockopt(s.Fd(), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    uint8_t sa[16]{};
    net::EncodePlatformSockaddrIn(loopback_only ? 0x7F000001u : 0x00000000u, in_out_port, sa);
    if (::bind(s.Fd(), reinterpret_cast<const struct sockaddr*>(sa), sizeof(sa)) != 0) {
        return {};
    }
    if (::listen(s.Fd(), 8) != 0) {
        return {};
    }
    uint16_t actual = 0;
    if (!s.GetLocalPort(actual) || actual == 0) return {};
    in_out_port = actual;
    return s;
}

[[nodiscard]] inline net::NetSocket UdpBindSocket(bool loopback_only,
                                                  uint16_t& in_out_port,
                                                  bool enable_broadcast = false) noexcept {
    net::NetSocket s = net::NetSocket::CreateUdp(true);
    if (!s.IsValid()) return {};

    int reuse = 1;
    ::setsockopt(s.Fd(), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    if (enable_broadcast) {
        int bcast = 1;
        ::setsockopt(s.Fd(), SOL_SOCKET, SO_BROADCAST, reinterpret_cast<const char*>(&bcast), sizeof(bcast));
    }

    uint8_t sa[16]{};
    net::EncodePlatformSockaddrIn(loopback_only ? 0x7F000001u : 0x00000000u, in_out_port, sa);
    if (::bind(s.Fd(), reinterpret_cast<const struct sockaddr*>(sa), sizeof(sa)) != 0) {
        return {};
    }
    uint16_t actual = 0;
    if (!s.GetLocalPort(actual) || actual == 0) return {};
    in_out_port = actual;
    return s;
}

/// Resolves numeric IPv4 / localhost immediately, else tries `resolver` (DoH/UDP), else falls back to OS getaddrinfo.
[[nodiscard]] inline bool ResolveHostIpv4Order(std::string_view host,
                                               net::IDnsResolver* resolver,
                                               uint32_t& out_ipv4_host) noexcept {
    if (ParseIpv4HostOrder(host, out_ipv4_host)) return true;

    if (resolver) {
        uint32_t be = 0;
        if (resolver->ResolveIPv4(host, be) && be != 0) {
            out_ipv4_host = ((be & 0xFFu) << 24) | ((be & 0xFF00u) << 8) | ((be >> 8) & 0xFF00u) | ((be >> 24) & 0xFFu);
            return true;
        }
    }

#ifndef __SWITCH__
    if (host.empty() || host.size() > 255) return false;
    std::string h(host);
    struct addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (::getaddrinfo(h.c_str(), nullptr, &hints, &res) == 0 && res) {
        bool ok = false;
        for (auto* it = res; it != nullptr; it = it->ai_next) {
            if (it->ai_family == AF_INET && it->ai_addrlen >= sizeof(struct sockaddr_in)) {
                uint16_t unused_port = 0;
                if (net::DecodePlatformSockaddrIn(reinterpret_cast<const uint8_t*>(it->ai_addr),
                                                  it->ai_addrlen, out_ipv4_host, unused_port) &&
                    out_ipv4_host != 0) {
                    ok = true;
                    break;
                }
            }
        }
        ::freeaddrinfo(res);
        return ok;
    }
#endif
    return false;
}

[[nodiscard]] inline bool ParseUnsignedDecimal(std::string_view s, uint64_t& out) noexcept {
    if (s.empty()) return false;
    uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (v > (UINT64_MAX - digit) / 10ULL) return false;
        v = v * 10ULL + digit;
    }
    out = v;
    return true;
}

[[nodiscard]] inline std::string UrlDecode(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    auto hex_val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            const int hi = hex_val(s[i + 1]);
            const int lo = hex_val(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        } else if (s[i] == '+') {
            out.push_back(' ');
            continue;
        }
        out.push_back(s[i]);
    }
    return out;
}

[[nodiscard]] inline std::string UrlEncode(std::string_view s) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        const bool unreserved =
            (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHex[(c >> 4) & 0x0Fu]);
            out.push_back(kHex[c & 0x0Fu]);
        }
    }
    return out;
}

}  // namespace yumi_nx::logic
