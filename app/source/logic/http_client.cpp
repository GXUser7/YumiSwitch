#include "http_client.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>

#include "sync_util.hpp"
#include "yumi_nx/dns_engine.hpp"
#include "yumi_nx/socket_io.hpp"
#include "yumi_nx/tls13_reality.hpp"
#include "yumi_nx/tunnel_engine.hpp"

namespace yumi_nx::logic {

namespace {

std::string ToLowerAscii(std::string_view s) {
    std::string out(s);
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

bool EqualsCi(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

std::string TrimOws(std::string_view s) {
    size_t b = 0;
    size_t e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
    return std::string(s.substr(b, e - b));
}

bool ParseHexSize(std::string_view s, size_t& out) noexcept {
    const std::string t = TrimOws(s);
    if (t.empty()) return false;
    size_t semi = t.find(';');
    std::string_view tok = (semi == std::string::npos) ? std::string_view(t) : std::string_view(t).substr(0, semi);
    size_t v = 0;
    bool any = false;
    for (char c : tok) {
        if (c == ' ' || c == '\t') break;
        int d = -1;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        any = true;
        if (v > (SIZE_MAX - static_cast<size_t>(d)) / 16) return false;
        v = v * 16 + static_cast<size_t>(d);
    }
    if (!any) return false;
    out = v;
    return true;
}

struct ChunkedDecoder {
    enum class State { SizeLine, Data, DataCrLf, Done, Error };
    State state = State::SizeLine;
    size_t chunk_rem = 0;
    std::string line_buf;

    bool Feed(const uint8_t* data,
              size_t len,
              const std::function<bool(const uint8_t*, size_t)>& sink) {
        size_t pos = 0;
        while (pos < len && state != State::Done && state != State::Error) {
            if (state == State::SizeLine) {
                while (pos < len) {
                    const char ch = static_cast<char>(data[pos++]);
                    line_buf.push_back(ch);
                    if (ch == '\n') break;
                    if (line_buf.size() > 256) {
                        state = State::Error;
                        return false;
                    }
                }
                if (!line_buf.empty() && line_buf.back() == '\n') {
                    size_t csz = 0;
                    if (!ParseHexSize(line_buf, csz)) {
                        state = State::Error;
                        return false;
                    }
                    line_buf.clear();
                    if (csz == 0) {
                        state = State::Done;
                        return true;
                    }
                    chunk_rem = csz;
                    state = State::Data;
                }
            } else if (state == State::Data) {
                const size_t take = std::min(chunk_rem, len - pos);
                if (take > 0) {
                    if (!sink(data + pos, take)) {
                        state = State::Error;
                        return false;
                    }
                    pos += take;
                    chunk_rem -= take;
                }
                if (chunk_rem == 0) {
                    state = State::DataCrLf;
                }
            } else if (state == State::DataCrLf) {
                const char ch = static_cast<char>(data[pos++]);
                if (ch == '\n') {
                    state = State::SizeLine;
                } else if (ch != '\r') {
                    state = State::Error;
                    return false;
                }
            }
        }
        return state != State::Error;
    }
};

struct RawTransportConn {
    std::unique_ptr<net::TunnelEngine> transient_tunnel;
    std::unique_ptr<net::IOutboundStream> direct_stream;
    net::NetSocket sock;
    net::Tls13Client tls;
    bool via_stream = false;
    bool use_tls = false;

    bool WriteAll(const uint8_t* data, size_t len, int timeout_ms) noexcept {
        if (via_stream) {
            size_t sent = 0;
            const uint64_t dl = net::MonotonicMs() + static_cast<uint64_t>(std::max(1, timeout_ms));
            while (sent < len) {
                const auto res = direct_stream->WriteNonBlocking(data + sent, len - sent);
                if (res.status == net::IoStatus::Ok && res.bytes > 0) {
                    sent += res.bytes;
                    continue;
                }
                if (res.status == net::IoStatus::WouldBlock) {
                    direct_stream->FlushPending();
                    if (net::MonotonicMs() >= dl) return false;
                    net::SocketFd fd = direct_stream->NativeFd();
                    if (fd != net::kInvalidSocket) net::WaitSingleSocket(fd, false, true, 25);
                    else SleepMs(5);
                    continue;
                }
                return false;
            }
            const uint64_t fl_dl = net::MonotonicMs() + static_cast<uint64_t>(std::max(1, timeout_ms));
            while (direct_stream->HasPendingWrite()) {
                direct_stream->FlushPending();
                if (net::MonotonicMs() >= fl_dl) return false;
                net::SocketFd fd = direct_stream->NativeFd();
                if (fd != net::kInvalidSocket) net::WaitSingleSocket(fd, false, true, 20);
                else SleepMs(5);
            }
            return true;
        }
        if (use_tls) return tls.WriteBlocking(sock, data, len, timeout_ms);
        return sock.SendAllBlocking(data, len, timeout_ms);
    }

    net::IoResult ReadSome(uint8_t* buf, size_t cap, int timeout_ms) noexcept {
        if (via_stream) {
            const uint64_t dl = net::MonotonicMs() + static_cast<uint64_t>(std::max(1, timeout_ms));
            while (true) {
                direct_stream->FlushPending();
                const auto res = direct_stream->ReadNonBlocking(buf, cap);
                if (res.status != net::IoStatus::WouldBlock) return res;
                if (net::MonotonicMs() >= dl) return {net::IoStatus::WouldBlock, 0};
                net::SocketFd fd = direct_stream->NativeFd();
                if (fd != net::kInvalidSocket) net::WaitSingleSocket(fd, true, false, 30);
                else SleepMs(5);
            }
        }
        if (use_tls) return tls.ReadBlocking(sock, buf, cap, timeout_ms);
        return sock.RecvSomeBlocking(buf, cap, timeout_ms);
    }

    void Close() noexcept {
        if (direct_stream) {
            direct_stream->Close();
            direct_stream.reset();
        }
        if (use_tls && sock.IsValid()) {
            tls.SendCloseNotify(sock);
        }
        sock.Close();
        if (transient_tunnel) {
            transient_tunnel->Stop();
            transient_tunnel.reset();
        }
    }
};

std::string BuildHttpRequestWire(const HttpRequest& req, const ParsedUrl& url) {
    std::string out;
    out.reserve(512 + req.body.size());
    out += (req.method.empty() ? std::string("GET") : req.method);
    out += " ";
    out += (url.path_and_query.empty() ? std::string("/") : url.path_and_query);
    out += " HTTP/1.1\r\n";

    std::string host_hdr = url.host;
    const uint16_t def_port = url.is_https ? 443 : 80;
    if (url.port != def_port) {
        host_hdr += ":" + std::to_string(url.port);
    }
    out += "Host: " + host_hdr + "\r\n";

    bool has_ua = false;
    bool has_conn = false;
    bool has_accept_enc = false;
    bool has_len = false;
    for (const auto& kv : req.headers) {
        if (EqualsCi(kv.first, "host")) continue;
        if (EqualsCi(kv.first, "user-agent")) has_ua = true;
        if (EqualsCi(kv.first, "connection")) has_conn = true;
        if (EqualsCi(kv.first, "accept-encoding")) has_accept_enc = true;
        if (EqualsCi(kv.first, "content-length")) has_len = true;
        out += kv.first + ": " + kv.second + "\r\n";
    }
    if (!has_ua && !req.user_agent.empty()) {
        out += "User-Agent: " + req.user_agent + "\r\n";
    }
    if (!has_accept_enc) {
        out += "Accept-Encoding: identity\r\n";
    }
    if (!has_conn) {
        out += "Connection: close\r\n";
    }
    if (!req.body.empty() && !has_len) {
        out += "Content-Length: " + std::to_string(req.body.size()) + "\r\n";
    }
    out += "\r\n";
    if (!req.body.empty()) out += req.body;
    return out;
}

bool ParseHttpResponseHead(std::string_view head_block, HttpResponse& resp) {
    const size_t first_rn = head_block.find('\n');
    const std::string_view status_line = (first_rn == std::string::npos) ? head_block : head_block.substr(0, first_rn);
    const size_t sp1 = status_line.find(' ');
    if (sp1 == std::string::npos) return false;
    size_t pos = sp1 + 1;
    while (pos < status_line.size() && status_line[pos] == ' ') ++pos;
    int code = 0;
    int digits = 0;
    while (pos < status_line.size() && digits < 3 &&
           status_line[pos] >= '0' && status_line[pos] <= '9') {
        code = code * 10 + (status_line[pos] - '0');
        ++pos;
        ++digits;
    }
    if (digits != 3) return false;
    resp.status_code = code;

    if (first_rn == std::string::npos) return true;
    size_t cur = first_rn + 1;
    while (cur < head_block.size()) {
        const size_t nxt = head_block.find('\n', cur);
        const std::string_view line = (nxt == std::string::npos)
            ? head_block.substr(cur)
            : head_block.substr(cur, nxt - cur);
        const size_t col = line.find(':');
        if (col != std::string::npos) {
            std::string k = ToLowerAscii(TrimOws(line.substr(0, col)));
            std::string v = TrimOws(line.substr(col + 1));
            if (!k.empty()) resp.headers.emplace_back(std::move(k), std::move(v));
        }
        if (nxt == std::string::npos) break;
        cur = nxt + 1;
    }
    return true;
}

HttpResponse ExecuteSingleHttp(const HttpRequest& req,
                               const std::string& target_url,
                               const std::function<bool(const HttpResponse&)>& on_headers,
                               const std::function<bool(const uint8_t*, size_t)>& on_body_chunk) {
    const uint64_t t0 = net::MonotonicMs();
    HttpResponse resp;
    resp.final_url = target_url;

    const ParsedUrl url = ParseHttpUrl(target_url);
    if (!url.valid) {
        resp.error = "Invalid HTTP URL";
        return resp;
    }

    net::SocketLayerInit();
    net::DohResolver fallback_dns(req.settings);
    net::IDnsResolver* dns = req.resolver ? req.resolver : &fallback_dns;

    RawTransportConn conn;
    if (req.via_node != nullptr && req.via_node->protocol != Protocol::Direct) {
        if (!url.is_https) {
            conn.direct_stream = net::CreateOutboundStream(*req.via_node, req.settings);
            if (!conn.direct_stream) {
                resp.error = "Unsupported proxy protocol";
                return resp;
            }
            net::Endpoint ep;
            ep.host = url.host;
            ep.port = url.port;
            ep.is_udp = false;
            if (!conn.direct_stream->Connect(ep, *dns, req.timeout_ms)) {
                resp.error = "Proxy outbound connect failed";
                return resp;
            }
            conn.via_stream = true;
        } else {
            conn.transient_tunnel = std::make_unique<net::TunnelEngine>();
            if (!conn.transient_tunnel->Start(*req.via_node, req.settings, true, 0)) {
                resp.error = "Transient tunnel failed";
                return resp;
            }
            const uint16_t relay_port = conn.transient_tunnel->RelayPort();
            conn.sock = net::NetSocket::CreateTcp(false);
            if (!conn.sock.IsValid()) {
                conn.Close();
                resp.error = "Loopback socket creation failed";
                return resp;
            }
            uint8_t local_bind[16]{};
            net::EncodePlatformSockaddrIn(0x7F000001u, 0, local_bind);
            if (::bind(conn.sock.Fd(), reinterpret_cast<const struct sockaddr*>(local_bind), sizeof(local_bind)) != 0) {
                conn.Close();
                resp.error = "Loopback bind failed";
                return resp;
            }
            uint16_t client_src_port = 0;
            conn.sock.GetLocalPort(client_src_port);
            net::Endpoint ep;
            ep.host = url.host;
            ep.port = url.port;
            ep.is_udp = false;
            conn.transient_tunnel->RegisterPendingTarget(client_src_port, ep);

            uint8_t sa_dst[16]{};
            net::EncodePlatformSockaddrIn(0x7F000001u, relay_port, sa_dst);
            if (::connect(conn.sock.Fd(), reinterpret_cast<const struct sockaddr*>(sa_dst), sizeof(sa_dst)) != 0) {
                conn.Close();
                resp.error = "Transient relay connect failed";
                return resp;
            }
            conn.sock.SetNonBlocking(true);
            conn.sock.SetNoDelay(true);
            const auto frag = net::MakeFragmentConfig(req.settings);
            const auto fp = net::ResolveEffectiveFingerprint(req.settings.tls_fingerprint, "");
            if (!conn.tls.Handshake(conn.sock, url.host, {"http/1.1"}, nullptr,
                                    CurrentEpochSec(), req.timeout_ms, fp, &frag)) {
                conn.Close();
                resp.error = "TLS handshake via proxy failed";
                return resp;
            }
            conn.use_tls = true;
        }
    } else {
        uint32_t ipv4_host = 0;
        if (!ResolveHostIpv4Order(url.host, dns, ipv4_host)) {
            resp.error = "DNS resolution failed";
            return resp;
        }
        if (!conn.sock.ConnectExactBlocking(ipv4_host, url.port, req.timeout_ms)) {
            resp.error = "TCP connect failed";
            return resp;
        }
        if (url.is_https) {
            const auto frag = net::MakeFragmentConfig(req.settings);
            const auto fp = net::ResolveEffectiveFingerprint(req.settings.tls_fingerprint, "");
            if (!conn.tls.Handshake(conn.sock, url.host, {"http/1.1"}, nullptr,
                                    CurrentEpochSec(), req.timeout_ms, fp, &frag)) {
                conn.Close();
                resp.error = "TLS 1.3 handshake failed";
                return resp;
            }
            conn.use_tls = true;
        }
    }

    const std::string wire = BuildHttpRequestWire(req, url);
    if (!conn.WriteAll(reinterpret_cast<const uint8_t*>(wire.data()), wire.size(), req.timeout_ms)) {
        conn.Close();
        resp.error = "HTTP request send failed";
        return resp;
    }

    std::string hdr_acc;
    hdr_acc.reserve(2048);
    bool headers_done = false;
    bool chunked = false;
    bool has_content_len = false;
    uint64_t content_len = 0;
    uint64_t received = 0;
    ChunkedDecoder chunk_dec;
    uint8_t buf[8192];

    const uint64_t deadline = net::MonotonicMs() + static_cast<uint64_t>(std::max(1000, req.timeout_ms));
    bool clean_done = false;

    auto consume_body = [&](const uint8_t* ptr, size_t len) -> bool {
        if (len == 0) return true;
        if (chunked) {
            return chunk_dec.Feed(ptr, len, [&](const uint8_t* d, size_t n) {
                received += n;
                if (received > req.max_response_bytes) return false;
                return on_body_chunk ? on_body_chunk(d, n) : true;
            });
        }
        size_t take = len;
        if (has_content_len && received + take > content_len) {
            take = static_cast<size_t>(content_len - received);
        }
        if (take > 0) {
            received += take;
            if (received > req.max_response_bytes) return false;
            if (on_body_chunk && !on_body_chunk(ptr, take)) return false;
        }
        return true;
    };

    while (net::MonotonicMs() < deadline) {
        const int rem = static_cast<int>(std::clamp<uint64_t>(deadline - net::MonotonicMs(), 50ULL, 2000ULL));
        const auto r = conn.ReadSome(buf, sizeof(buf), rem);
        if (r.status == net::IoStatus::Ok && r.bytes > 0) {
            if (!headers_done) {
                hdr_acc.append(reinterpret_cast<const char*>(buf), r.bytes);
                size_t sep = hdr_acc.find("\r\n\r\n");
                size_t sep_len = 4;
                if (sep == std::string::npos) {
                    sep = hdr_acc.find("\n\n");
                    sep_len = 2;
                }
                if (sep != std::string::npos) {
                    if (!ParseHttpResponseHead(std::string_view(hdr_acc).substr(0, sep), resp)) {
                        conn.Close();
                        resp.error = "Malformed HTTP status line";
                        return resp;
                    }
                    headers_done = true;
                    const std::string te = ToLowerAscii(resp.Header("transfer-encoding"));
                    chunked = (te.find("chunked") != std::string::npos);
                    const std::string cl_str = resp.Header("content-length");
                    if (!cl_str.empty() && ParseUnsignedDecimal(cl_str, content_len)) {
                        has_content_len = true;
                    }
                    if (on_headers && !on_headers(resp)) {
                        conn.Close();
                        resp.error = "Aborted by caller";
                        return resp;
                    }
                    if (EqualsCi(req.method, "HEAD") || resp.status_code == 204 || resp.status_code == 304) {
                        clean_done = true;
                        break;
                    }
                    const size_t body_off = sep + sep_len;
                    if (body_off < hdr_acc.size()) {
                        if (!consume_body(reinterpret_cast<const uint8_t*>(hdr_acc.data() + body_off),
                                          hdr_acc.size() - body_off)) {
                            conn.Close();
                            resp.error = "Body size or sink error";
                            return resp;
                        }
                    }
                    hdr_acc.clear();
                    if ((chunked && chunk_dec.state == ChunkedDecoder::State::Done) ||
                        (has_content_len && received >= content_len)) {
                        clean_done = true;
                        break;
                    }
                } else if (hdr_acc.size() > 32768) {
                    conn.Close();
                    resp.error = "HTTP headers too large";
                    return resp;
                }
            } else {
                if (!consume_body(buf, r.bytes)) {
                    conn.Close();
                    resp.error = "Body size or sink error";
                    return resp;
                }
                if ((chunked && chunk_dec.state == ChunkedDecoder::State::Done) ||
                    (has_content_len && received >= content_len)) {
                    clean_done = true;
                    break;
                }
            }
            continue;
        }
        if (r.status == net::IoStatus::Eof) {
            if (headers_done) {
                if (!chunked && (!has_content_len || received >= content_len)) {
                    clean_done = true;
                } else if (chunked && chunk_dec.state == ChunkedDecoder::State::Done) {
                    clean_done = true;
                }
            }
            break;
        }
        if (r.status == net::IoStatus::Error) {
            break;
        }
    }

    conn.Close();
    resp.elapsed_ms = static_cast<int>(net::MonotonicMs() - t0);
    if (!clean_done) {
        if (resp.error.empty()) resp.error = headers_done ? "Truncated HTTP body" : "HTTP read timeout";
        return resp;
    }
    resp.ok = true;
    return resp;
}

bool IsRedirectStatus(int code) noexcept {
    return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
}

}  // namespace

std::string HttpResponse::Header(std::string_view name_ci) const {
    for (const auto& kv : headers) {
        if (EqualsCi(kv.first, name_ci)) return kv.second;
    }
    return {};
}

ParsedUrl ParseHttpUrl(std::string_view url) {
    ParsedUrl u;
    std::string_view rest = url;
    if (rest.rfind("https://", 0) == 0) {
        u.is_https = true;
        u.port = 443;
        rest.remove_prefix(8);
    } else if (rest.rfind("http://", 0) == 0) {
        u.is_https = false;
        u.port = 80;
        rest.remove_prefix(7);
    } else {
        return {};
    }

    const size_t slash = rest.find('/');
    const size_t qmark = rest.find('?');
    size_t auth_end = rest.size();
    if (slash != std::string::npos) auth_end = std::min(auth_end, slash);
    if (qmark != std::string::npos) auth_end = std::min(auth_end, qmark);

    const std::string_view auth = rest.substr(0, auth_end);
    if (auth.empty()) return {};

    const size_t at = auth.rfind('@');
    const std::string_view hostport = (at == std::string::npos) ? auth : auth.substr(at + 1);
    if (hostport.empty()) return {};

    if (hostport.front() == '[') {
        const size_t rb = hostport.find(']');
        if (rb == std::string::npos) return {};
        u.host = std::string(hostport.substr(1, rb - 1));
        if (rb + 1 < hostport.size() && hostport[rb + 1] == ':') {
            uint64_t p = 0;
            if (!ParseUnsignedDecimal(hostport.substr(rb + 2), p) || p == 0 || p > 65535) return {};
            u.port = static_cast<uint16_t>(p);
        }
    } else {
        const size_t col = hostport.rfind(':');
        if (col != std::string::npos) {
            u.host = std::string(hostport.substr(0, col));
            uint64_t p = 0;
            if (!ParseUnsignedDecimal(hostport.substr(col + 1), p) || p == 0 || p > 65535) return {};
            u.port = static_cast<uint16_t>(p);
        } else {
            u.host = std::string(hostport);
        }
    }

    if (u.host.empty()) return {};
    if (auth_end < rest.size()) {
        const std::string_view tail = rest.substr(auth_end);
        u.path_and_query = (tail.front() == '/') ? std::string(tail) : ("/" + std::string(tail));
    } else {
        u.path_and_query = "/";
    }
    u.valid = true;
    return u;
}

std::string ResolveRedirectUrl(std::string_view base_url, std::string_view location) {
    if (location.rfind("https://", 0) == 0 || location.rfind("http://", 0) == 0) {
        return std::string(location);
    }
    const ParsedUrl base = ParseHttpUrl(base_url);
    if (!base.valid) return std::string(location);
    const std::string scheme = base.is_https ? "https:" : "http:";
    if (location.rfind("//", 0) == 0) {
        return scheme + std::string(location);
    }
    const uint16_t def_port = base.is_https ? 443 : 80;
    std::string origin = scheme + "//" + base.host;
    if (base.port != def_port) origin += ":" + std::to_string(base.port);
    if (!location.empty() && location.front() == '/') {
        return origin + std::string(location);
    }
    return origin + "/" + std::string(location);
}

HttpResponse ExecuteHttpRequest(const HttpRequest& req) {
    HttpRequest cur = req;
    std::string url = req.url;
    HttpResponse last;
    for (int hop = 0; hop <= std::max(0, req.max_redirects); ++hop) {
        last.body.clear();
        std::string captured_body;
        last = ExecuteSingleHttp(
            cur,
            url,
            nullptr,
            [&](const uint8_t* ptr, size_t n) {
                captured_body.append(reinterpret_cast<const char*>(ptr), n);
                return true;
            });
        if (!last.ok) return last;
        last.body = std::move(captured_body);

        if (req.follow_redirects && IsRedirectStatus(last.status_code)) {
            const std::string loc = last.Header("location");
            if (!loc.empty() && hop < req.max_redirects) {
                url = ResolveRedirectUrl(url, loc);
                if (last.status_code == 303 ||
                    ((last.status_code == 301 || last.status_code == 302) && !EqualsCi(cur.method, "HEAD"))) {
                    if (!EqualsCi(cur.method, "HEAD")) cur.method = "GET";
                    cur.body.clear();
                }
                continue;
            }
        }
        return last;
    }
    return last;
}

HttpResponse DownloadHttpFileAtomic(const HttpRequest& req,
                                      const std::string& dest_path,
                                      const DownloadProgressCallback& on_progress,
                                      std::atomic<bool>* cancel) {
    HttpRequest cur = req;
    std::string url = req.url;
    const std::string part_path = dest_path + ".part";
    std::error_code ec;
    const std::filesystem::path p_dest(dest_path);
    if (p_dest.has_parent_path()) {
        std::filesystem::create_directories(p_dest.parent_path(), ec);
    }

    HttpResponse last;
    for (int hop = 0; hop <= std::max(0, req.max_redirects); ++hop) {
        if (cancel && cancel->load()) {
            last.ok = false;
            last.error = "Cancelled";
            return last;
        }
        int64_t expected_total = -1;
        uint64_t received = 0;
        std::ofstream part_out;
        bool write_to_disk = true;

        last = ExecuteSingleHttp(
            cur,
            url,
            [&](const HttpResponse& hdr_resp) {
                if (cancel && cancel->load()) return false;
                if (req.follow_redirects && IsRedirectStatus(hdr_resp.status_code)) {
                    write_to_disk = false;
                    return true;
                }
                if (hdr_resp.status_code < 200 || hdr_resp.status_code >= 300) {
                    write_to_disk = false;
                    return true;
                }
                uint64_t cl = 0;
                const std::string cl_s = hdr_resp.Header("content-length");
                if (!cl_s.empty() && ParseUnsignedDecimal(cl_s, cl)) {
                    expected_total = static_cast<int64_t>(cl);
                }
                part_out.open(part_path, std::ios::binary | std::ios::trunc);
                return part_out.is_open();
            },
            [&](const uint8_t* ptr, size_t n) {
                if (cancel && cancel->load()) return false;
                if (!write_to_disk) return true;
                if (!part_out.is_open()) return false;
                part_out.write(reinterpret_cast<const char*>(ptr), static_cast<std::streamsize>(n));
                if (!part_out.good()) return false;
                received += n;
                if (on_progress) on_progress(received, expected_total);
                return true;
            });

        if (part_out.is_open()) {
            part_out.flush();
            part_out.close();
        }
        if (!last.ok) {
            std::filesystem::remove(part_path, ec);
            return last;
        }

        if (req.follow_redirects && IsRedirectStatus(last.status_code)) {
            const std::string loc = last.Header("location");
            if (!loc.empty() && hop < req.max_redirects) {
                url = ResolveRedirectUrl(url, loc);
                cur.method = "GET";
                cur.body.clear();
                continue;
            }
        }

        if (last.status_code >= 200 && last.status_code < 300) {
            ec.clear();
            std::filesystem::rename(part_path, p_dest, ec);
            if (ec) {
                std::filesystem::remove(p_dest, ec);
                ec.clear();
                std::filesystem::rename(part_path, p_dest, ec);
            }
            if (ec) {
                last.ok = false;
                last.error = "Atomic rename failed";
                std::filesystem::remove(part_path, ec);
            }
        } else {
            std::filesystem::remove(part_path, ec);
        }
        return last;
    }
    std::filesystem::remove(part_path, ec);
    return last;
}

}  // namespace yumi_nx::logic
