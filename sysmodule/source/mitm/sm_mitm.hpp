#pragma once

#include <switch.h>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace yumi_nx::sys::mitm_ipc {

struct alignas(4) SmServiceName {
    char chars[8] = {};

    static SmServiceName FromCString(const char* s) noexcept {
        SmServiceName out{};
        if (s) {
            for (size_t i = 0; i < 8 && s[i] != '\0'; ++i) {
                out.chars[i] = s[i];
            }
        }
        return out;
    }
};
static_assert(sizeof(SmServiceName) == 8);

struct MitmProcessInfo {
    uint64_t process_id;
    uint64_t program_id;
    uint64_t override_keys_held;
    uint64_t override_flags;
};
static_assert(sizeof(MitmProcessInfo) == 0x20);

/// Calls Atmosphère `sm:` TIPC command 65000 (`InstallMitm`).
Result SmInstallMitm(const char* service_name, Handle& out_server_port, Handle& out_query_session) noexcept;

/// Calls Atmosphère `sm:` TIPC command 65001 (`UninstallMitm`).
Result SmUninstallMitm(const char* service_name) noexcept;

/// Calls Atmosphère `sm:` TIPC command 65003 (`AcknowledgeMitmSession`).
Result SmAcknowledgeMitmSession(const char* service_name, MitmProcessInfo& out_info, Handle& out_fwd_handle) noexcept;

/// Prepares thread-local IPC buffer with RecvList slots pointing to `rx_ptr_buf` before svcReplyAndReceive.
void PrepareTlsRecvList(void* tls_base, uint8_t* rx_ptr_buf, size_t slot_count, size_t slot_size) noexcept;

/// Serves one `ShouldMitm` IPC loop iteration on `query_session` using `ShouldMitmProgramId`.
/// Sets `in_out_reply_target` to `query_session` on valid reply or `0` if session closed.
bool ServeQueryIteration(Handle query_session, Handle& in_out_reply_target, uint8_t* scratch_buf, size_t scratch_size) noexcept;

/// Context for inspecting and/or overriding a forwarded HIPC request cleanly without zero-copy aliasing violations.
struct ParsedRequestInfo {
    uint16_t hipc_type = 0;
    uint32_t cmif_cmd_id = 0;
    bool has_cmif_in_header = false;
    bool is_domain = false;
    uint8_t* aligned_data_start = nullptr;
    uint32_t cmif_payload_size = 0;
    uint8_t* cmif_payload = nullptr;
    uint16_t* out_pointer_sizes = nullptr;
    uint32_t out_pointer_count = 0;

    // Input pointers/buffers copied into sysmodule memory so callers' MemAttr_IsIpcMapped buffers are readable & safely forwardable.
    static constexpr size_t kMaxBufs = 8;
    const uint8_t* send_ptr[kMaxBufs] = {};
    uint32_t send_ptr_size[kMaxBufs] = {};
    uint32_t send_ptr_count = 0;

    uint8_t* send_buf_copy[kMaxBufs] = {};
    uint32_t send_buf_size[kMaxBufs] = {};
    uint32_t send_buf_count = 0;
};

/// Reads the incoming HIPC request in TLS into sysmodule staging memory and extracts CMIF command metadata.
bool ParseIncomingHipc(void* tls_base, ParsedRequestInfo& out_info) noexcept;

/// Writes a CMIF response, optionally attaching one Move handle and/or one SendStatic pointer buffer.
void WriteSimpleCmifResponse(void* tls_base,
                             Result rc,
                             const void* payload,
                             uint32_t payload_size,
                             Handle move_handle = INVALID_HANDLE,
                             const void* send_static_ptr = nullptr,
                             uint32_t send_static_size = 0) noexcept;

/// Issues bsd:u Bind(13) to 127.0.0.1:0 followed by GetSockName(16) on `fwd_handle` to capture the ephemeral source port.
bool MitmCallBsdBindLoopback(Handle fwd_handle, int32_t fd, uint16_t& out_ephemeral_port) noexcept;

/// Clamps CMIF payload + staging buffers, optionally overrides SendStatic[0]/SendBuffer[0],
/// forwards TLS request synchronously to `fwd_handle`, copies output buffers/handles back, and prepares reply TLS.
Result ForwardParsedHipc(void* tls_base,
                         Handle fwd_handle,
                         const ParsedRequestInfo& parsed_in,
                         uint8_t* pointer_buf,
                         size_t pointer_slot_size,
                         uint8_t* staging_buf,
                         size_t staging_cap,
                         Handle* out_close_after_reply,
                         u32 out_close_cap,
                         u32* out_close_count,
                         Result* out_cmif_rc,
                         int32_t* out_bsd_ret,
                         int32_t* out_bsd_errno,
                         const uint8_t* override_in0_data = nullptr,
                         size_t override_in0_len = 0) noexcept;

}  // namespace yumi_nx::sys::mitm_ipc
