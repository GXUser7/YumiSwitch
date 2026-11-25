#include "mitm/sm_mitm.hpp"

#include <switch/sf/cmif.h>
#include <switch/sf/tipc.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>

#include "hos_compat.hpp"
#include "yumi_nx/mitm_policy.hpp"
#include "yumi_nx/socket_io.hpp"

namespace yumi_nx::sys::mitm_ipc {

namespace {

Result TipcSmDispatch(u32 cmd_id,
                      const void* in_data,
                      u32 in_size,
                      void* out_data,
                      u32 out_size,
                      u32 num_out_handles,
                      Handle* out_handles) noexcept {
    TipcService* sm = smGetServiceSessionTipc();
    if (!sm || sm->session == INVALID_HANDLE) {
        return MAKERESULT(Module_Libnx, LibnxError_NotInitialized);
    }

    TipcDispatchParams params{};
    if (num_out_handles >= 1) params.out_handle_attrs.attr0 = SfOutHandleAttr_HipcMove;
    if (num_out_handles >= 2) params.out_handle_attrs.attr1 = SfOutHandleAttr_HipcMove;
    if (num_out_handles >= 3) params.out_handle_attrs.attr2 = SfOutHandleAttr_HipcMove;
    if (num_out_handles >= 4) params.out_handle_attrs.attr3 = SfOutHandleAttr_HipcMove;
    params.out_handles = out_handles;
    return tipcDispatchImpl(sm, cmd_id, in_data, in_size, out_data, out_size, params);
}

struct StagingRecvMap {
    void* client_addr = nullptr;
    uint8_t* staging_ptr = nullptr;
    size_t size = 0;
};

}  // namespace

Result SmInstallMitm(const char* service_name, Handle& out_server_port, Handle& out_query_session) noexcept {
    out_server_port = INVALID_HANDLE;
    out_query_session = INVALID_HANDLE;

    const SmServiceName name = SmServiceName::FromCString(service_name);
    Handle handles[2] = {INVALID_HANDLE, INVALID_HANDLE};
    const Result rc = TipcSmDispatch(sm_mitm_cmd::kAtmosphereInstallMitm, &name, sizeof(name), nullptr, 0, 2, handles);
    if (R_SUCCEEDED(rc)) {
        out_server_port = handles[0];
        out_query_session = handles[1];
    }
    return rc;
}

Result SmUninstallMitm(const char* service_name) noexcept {
    const SmServiceName name = SmServiceName::FromCString(service_name);
    return TipcSmDispatch(sm_mitm_cmd::kAtmosphereUninstallMitm, &name, sizeof(name), nullptr, 0, 0, nullptr);
}

Result SmAcknowledgeMitmSession(const char* service_name, MitmProcessInfo& out_info, Handle& out_fwd_handle) noexcept {
    out_info = {};
    out_fwd_handle = INVALID_HANDLE;

    const SmServiceName name = SmServiceName::FromCString(service_name);
    Handle fwd = INVALID_HANDLE;
    const Result rc = TipcSmDispatch(sm_mitm_cmd::kAtmosphereAcknowledgeMitmSession, &name, sizeof(name), &out_info,
                                     sizeof(out_info), 1, &fwd);
    if (R_SUCCEEDED(rc)) {
        out_fwd_handle = fwd;
    }
    return rc;
}

void PrepareTlsRecvList(void* tls_base, uint8_t* rx_ptr_buf, size_t slot_count, size_t slot_size) noexcept {
    HipcMetadata meta{};
    meta.type = 0;
    meta.num_recv_statics = static_cast<u32>(slot_count);
    HipcRequest req = hipcMakeRequest(tls_base, meta);
    if (!rx_ptr_buf) {
        return;
    }
    for (size_t i = 0; i < slot_count; ++i) {
        req.recv_list[i] = hipcMakeRecvStatic(rx_ptr_buf + i * slot_size, slot_size);
    }
}

bool ServeQueryIteration(Handle query_session, Handle& in_out_reply_target, uint8_t* /*scratch_buf*/, size_t /*scratch_size*/) noexcept {
    if (in_out_reply_target == 0) {
        std::memset(armGetTls(), 0, 16);
    }

    s32 idx = -1;
    const Result rc = svcReplyAndReceive(&idx, &query_session, 1, in_out_reply_target, 100'000'000ULL);
    if (rc == 0xEA01) {  // KernelError_TimedOut
        in_out_reply_target = 0;
        return true;
    }
    if (R_FAILED(rc)) {
        in_out_reply_target = 0;
        return false;
    }

    void* tls = armGetTls();
    const u16 type = *static_cast<const u16*>(tls);
    if (type == CmifCommandType_Close || type == 15) {
        WriteSimpleCmifResponse(tls, 0, nullptr, 0);
        in_out_reply_target = 0;
        return false;
    }

    const HipcParsedRequest parsed = hipcParseRequest(tls);
    MitmProcessInfo proc_info{};
    bool valid_query = false;
    bool is_tipc = false;

    if (type == CmifCommandType_Request || type == CmifCommandType_RequestWithContext) {
        auto* hdr = static_cast<CmifInHeader*>(cmifGetAlignedDataStart(parsed.data.data_words, tls));
        if (hdr->magic == CMIF_IN_HEADER_MAGIC && hdr->command_id == sm_mitm_cmd::kQueryShouldMitm) {
            std::memcpy(&proc_info, hdr + 1, sizeof(proc_info));
            valid_query = true;
        }
    } else if (type >= 16 && (type - 16u) == sm_mitm_cmd::kQueryShouldMitm) {
        std::memcpy(&proc_info, parsed.data.data_words, sizeof(proc_info));
        valid_query = true;
        is_tipc = true;
    }

    const uint8_t decision = (valid_query && mitm::ShouldMitmProgramId(proc_info.program_id)) ? 1u : 0u;
    if (is_tipc) {
        HipcMetadata meta{};
        meta.type = type;
        meta.num_data_words = 2;
        HipcRequest out_req = hipcMakeRequest(tls, meta);
        out_req.data_words[0] = 0;
        out_req.data_words[1] = decision;
    } else {
        WriteSimpleCmifResponse(tls, 0, &decision, sizeof(decision));
    }

    in_out_reply_target = query_session;
    return true;
}

bool ParseIncomingHipc(void* tls_base, ParsedRequestInfo& out_info) noexcept {
    out_info = {};
    const HipcParsedRequest parsed = hipcParseRequest(tls_base);
    out_info.hipc_type = static_cast<uint16_t>(parsed.meta.type);

    out_info.send_ptr_count = std::min<uint32_t>(parsed.meta.num_send_statics, ParsedRequestInfo::kMaxBufs);
    for (uint32_t i = 0; i < out_info.send_ptr_count; ++i) {
        out_info.send_ptr[i] = static_cast<const uint8_t*>(hipcGetStaticAddress(&parsed.data.send_statics[i]));
        out_info.send_ptr_size[i] = static_cast<uint32_t>(hipcGetStaticSize(&parsed.data.send_statics[i]));
    }

    out_info.send_buf_count = std::min<uint32_t>(parsed.meta.num_send_buffers, ParsedRequestInfo::kMaxBufs);
    for (uint32_t i = 0; i < out_info.send_buf_count; ++i) {
        out_info.send_buf_copy[i] = static_cast<uint8_t*>(hipcGetBufferAddress(&parsed.data.send_buffers[i]));
        out_info.send_buf_size[i] = static_cast<uint32_t>(hipcGetBufferSize(&parsed.data.send_buffers[i]));
    }

    if (out_info.hipc_type == CmifCommandType_Request ||
        out_info.hipc_type == CmifCommandType_RequestWithContext ||
        out_info.hipc_type == CmifCommandType_Control ||
        out_info.hipc_type == CmifCommandType_ControlWithContext) {
        auto* start = static_cast<uint8_t*>(cmifGetAlignedDataStart(parsed.data.data_words, tls_base));
        out_info.aligned_data_start = start;
        const size_t data_bytes = parsed.meta.num_data_words * sizeof(uint32_t);
        const size_t header_offset = static_cast<size_t>(start - reinterpret_cast<uint8_t*>(parsed.data.data_words));
        if (data_bytes >= header_offset + sizeof(CmifInHeader)) {
            const auto* in_hdr = reinterpret_cast<const CmifInHeader*>(start);
            if (in_hdr->magic == CMIF_IN_HEADER_MAGIC) {
                out_info.has_cmif_in_header = true;
                out_info.cmif_cmd_id = in_hdr->command_id;
                out_info.cmif_payload = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(in_hdr + 1));
                out_info.cmif_payload_size =
                    static_cast<uint32_t>(data_bytes - header_offset - sizeof(CmifInHeader));
            }
        }
    }

    return true;
}

void WriteSimpleCmifResponse(void* tls_base,
                             Result rc,
                             const void* payload,
                             uint32_t payload_size,
                             Handle move_handle,
                             const void* send_static_ptr,
                             uint32_t send_static_size) noexcept {
    const uint32_t aligned_bytes = (payload_size + 3u) & ~3u;
    const uint32_t data_words = (16u + sizeof(CmifOutHeader) + aligned_bytes) / 4u;
    const bool has_static = (send_static_ptr != nullptr && send_static_size > 0);

    HipcMetadata meta{};
    meta.type = 0;
    meta.num_send_statics = has_static ? 1u : 0u;
    meta.num_data_words = data_words;
    meta.num_move_handles = (move_handle != INVALID_HANDLE) ? 1u : 0u;
    HipcRequest req = hipcMakeRequest(tls_base, meta);
    if (has_static) {
        req.send_statics[0] = hipcMakeSendStatic(send_static_ptr, send_static_size, 0);
    }
    if (move_handle != INVALID_HANDLE) {
        req.move_handles[0] = move_handle;
    }
    auto* hdr = static_cast<CmifOutHeader*>(cmifGetAlignedDataStart(req.data_words, tls_base));
    *hdr = CmifOutHeader{
        .magic = CMIF_OUT_HEADER_MAGIC,
        .version = 0,
        .result = rc,
        .token = 0,
    };
    if (payload && payload_size > 0) {
        std::memcpy(hdr + 1, payload, payload_size);
    }
}

bool MitmCallBsdBindLoopback(Handle fwd_handle, int32_t fd, uint16_t& out_ephemeral_port) noexcept {
    out_ephemeral_port = 0;
    if (fwd_handle == INVALID_HANDLE || fd < 0) return false;

    void* tls = armGetTls();
    alignas(16) uint32_t saved_tls[64]{};
    std::memcpy(saved_tls, tls, sizeof(saved_tls));

    // 1. Bind(13) to 127.0.0.1:0 so kernel allocates local source port on real bsd:u before Connect(14)
    {
        alignas(16) uint8_t bind_sa[16]{};
        net::EncodePlatformSockaddrIn(0x7F000001u, 0, bind_sa);
        CmifRequestFormat fmt{};
        fmt.request_id = bsd_cmd::kBind;
        fmt.data_size = sizeof(uint32_t);
        fmt.num_in_auto_buffers = 1;
        fmt.server_pointer_size = 0;
        CmifRequest req = cmifMakeRequest(tls, fmt);
        std::memcpy(req.data, &fd, sizeof(fd));
        cmifRequestInAutoBuffer(&req, bind_sa, sizeof(bind_sa), HipcBufferMode_Normal);
        (void)svcSendSyncRequest(fwd_handle);
    }

    // 2. GetSockName(16) to capture assigned ephemeral source port
    bool ok = false;
    {
        alignas(16) uint8_t out_sa[128]{};
        CmifRequestFormat fmt{};
        fmt.request_id = 16u;  // bsd:u GetSockName
        fmt.data_size = sizeof(uint32_t);
        fmt.num_out_auto_buffers = 1;
        fmt.server_pointer_size = 0;
        CmifRequest req = cmifMakeRequest(tls, fmt);
        std::memcpy(req.data, &fd, sizeof(fd));
        cmifRequestOutAutoBuffer(&req, out_sa, sizeof(out_sa), HipcBufferMode_Normal);
        if (R_SUCCEEDED(svcSendSyncRequest(fwd_handle))) {
            CmifResponse resp{};
            if (R_SUCCEEDED(cmifParseResponse(&resp, tls, false, 12))) {
                const auto* words = static_cast<const int32_t*>(resp.data);
                if (words[0] == 0) {
                    uint32_t dummy_ip = 0;
                    ok = net::DecodePlatformSockaddrIn(out_sa, sizeof(out_sa), dummy_ip, out_ephemeral_port) &&
                         out_ephemeral_port != 0;
                }
            }
        }
    }

    std::memcpy(tls, saved_tls, sizeof(saved_tls));
    return ok;
}

Result ForwardParsedHipc(void* tls_base,
                         Handle fwd_handle,
                         const ParsedRequestInfo& /*parsed_in*/,
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
                         const uint8_t* override_in0_data,
                         size_t override_in0_len) noexcept {
    if (out_close_count) *out_close_count = 0;
    if (out_cmif_rc) *out_cmif_rc = 0;
    if (out_bsd_ret) *out_bsd_ret = 0;
    if (out_bsd_errno) *out_bsd_errno = 0;

    alignas(16) uint32_t saved_req_tls[64] = {};
    std::memcpy(saved_req_tls, tls_base, sizeof(saved_req_tls));
    const HipcParsedRequest in = hipcParseRequest(saved_req_tls);

    size_t total_staging = 0;
    for (u32 i = 0; i < in.meta.num_send_buffers; ++i) {
        total_staging += (hipcGetBufferSize(&in.data.send_buffers[i]) + 15u) & ~size_t(15);
    }
    for (u32 i = 0; i < in.meta.num_recv_buffers; ++i) {
        total_staging += (hipcGetBufferSize(&in.data.recv_buffers[i]) + 15u) & ~size_t(15);
    }
    for (u32 i = 0; i < in.meta.num_exch_buffers; ++i) {
        total_staging += (hipcGetBufferSize(&in.data.exch_buffers[i]) + 15u) & ~size_t(15);
    }

    uint8_t* dyn_staging = nullptr;
    uint8_t* stage_base = staging_buf;
    if (total_staging > staging_cap) {
        if (total_staging > (512u * 1024u)) {
            WriteSimpleCmifResponse(tls_base, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory), nullptr, 0);
            return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
        }
        dyn_staging = static_cast<uint8_t*>(std::malloc(total_staging));
        if (!dyn_staging) {
            WriteSimpleCmifResponse(tls_base, MAKERESULT(Module_Libnx, LibnxError_OutOfMemory), nullptr, 0);
            return MAKERESULT(Module_Libnx, LibnxError_OutOfMemory);
        }
        stage_base = dyn_staging;
    }

    HipcMetadata fwd_meta{};
    fwd_meta.type = in.meta.type;
    fwd_meta.num_send_statics = in.meta.num_send_statics;
    fwd_meta.num_send_buffers = in.meta.num_send_buffers;
    fwd_meta.num_recv_buffers = in.meta.num_recv_buffers;
    fwd_meta.num_exch_buffers = in.meta.num_exch_buffers;
    fwd_meta.num_data_words = in.meta.num_data_words;
    fwd_meta.num_recv_statics = in.meta.num_recv_statics;
    fwd_meta.send_pid = in.meta.send_pid;
    fwd_meta.num_copy_handles = in.meta.num_copy_handles;
    fwd_meta.num_move_handles = in.meta.num_move_handles;
    HipcRequest fwd = hipcMakeRequest(tls_base, fwd_meta);

    for (u32 i = 0; i < in.meta.num_copy_handles; ++i) {
        fwd.copy_handles[i] = in.data.copy_handles[i];
    }
    for (u32 i = 0; i < in.meta.num_move_handles; ++i) {
        fwd.move_handles[i] = in.data.move_handles[i];
    }
    bool override_applied = false;
    for (u32 i = 0; i < in.meta.num_send_statics; ++i) {
        fwd.send_statics[i] = in.data.send_statics[i];
        void* s_addr = hipcGetStaticAddress(&in.data.send_statics[i]);
        const size_t s_sz = hipcGetStaticSize(&in.data.send_statics[i]);
        if (!override_applied && override_in0_data && override_in0_len > 0 && s_addr && s_sz >= override_in0_len) {
            std::memcpy(s_addr, override_in0_data, override_in0_len);
            override_applied = true;
        }
    }

    size_t stage_off = 0;
    for (u32 i = 0; i < in.meta.num_send_buffers; ++i) {
        void* c_addr = hipcGetBufferAddress(&in.data.send_buffers[i]);
        const size_t sz = hipcGetBufferSize(&in.data.send_buffers[i]);
        const auto mode = static_cast<HipcBufferMode>(in.data.send_buffers[i].mode);
        if (sz > 0 && c_addr != nullptr) {
            uint8_t* dst = stage_base + stage_off;
            stage_off += (sz + 15u) & ~size_t(15);
            std::memcpy(dst, c_addr, sz);
            if (!override_applied && override_in0_data && override_in0_len > 0 && sz >= override_in0_len) {
                std::memcpy(dst, override_in0_data, override_in0_len);
                override_applied = true;
            }
            fwd.send_buffers[i] = hipcMakeBuffer(dst, sz, mode);
        } else {
            fwd.send_buffers[i] = hipcMakeBuffer(nullptr, 0, mode);
        }
    }

    StagingRecvMap recv_maps[ParsedRequestInfo::kMaxBufs]{};
    const u32 recv_count = std::min<u32>(in.meta.num_recv_buffers, ParsedRequestInfo::kMaxBufs);
    for (u32 i = 0; i < in.meta.num_recv_buffers; ++i) {
        void* c_addr = hipcGetBufferAddress(&in.data.recv_buffers[i]);
        const size_t sz = hipcGetBufferSize(&in.data.recv_buffers[i]);
        const auto mode = static_cast<HipcBufferMode>(in.data.recv_buffers[i].mode);
        if (sz > 0 && c_addr != nullptr) {
            uint8_t* dst = stage_base + stage_off;
            stage_off += (sz + 15u) & ~size_t(15);
            if (i < recv_count) {
                recv_maps[i] = {c_addr, dst, sz};
            }
            fwd.recv_buffers[i] = hipcMakeBuffer(dst, sz, mode);
        } else {
            fwd.recv_buffers[i] = hipcMakeBuffer(nullptr, 0, mode);
        }
    }

    StagingRecvMap exch_maps[ParsedRequestInfo::kMaxBufs]{};
    const u32 exch_count = std::min<u32>(in.meta.num_exch_buffers, ParsedRequestInfo::kMaxBufs);
    for (u32 i = 0; i < in.meta.num_exch_buffers; ++i) {
        void* c_addr = hipcGetBufferAddress(&in.data.exch_buffers[i]);
        const size_t sz = hipcGetBufferSize(&in.data.exch_buffers[i]);
        const auto mode = static_cast<HipcBufferMode>(in.data.exch_buffers[i].mode);
        if (sz > 0 && c_addr != nullptr) {
            uint8_t* dst = stage_base + stage_off;
            stage_off += (sz + 15u) & ~size_t(15);
            std::memcpy(dst, c_addr, sz);
            if (i < exch_count) {
                exch_maps[i] = {c_addr, dst, sz};
            }
            fwd.exch_buffers[i] = hipcMakeBuffer(dst, sz, mode);
        } else {
            fwd.exch_buffers[i] = hipcMakeBuffer(nullptr, 0, mode);
        }
    }

    if (in.meta.num_data_words > 0) {
        std::memcpy(fwd.data_words, in.data.data_words, in.meta.num_data_words * sizeof(uint32_t));
    }

    if (in.meta.num_recv_statics == HIPC_AUTO_RECV_STATIC) {
        fwd.recv_list[0] = hipcMakeRecvStatic(pointer_buf, pointer_buf ? (4u * pointer_slot_size) : 0u);
    } else {
        for (u32 i = 0; i < in.meta.num_recv_statics; ++i) {
            if (pointer_buf && i < 4u) {
                fwd.recv_list[i] = hipcMakeRecvStatic(pointer_buf + i * pointer_slot_size, pointer_slot_size);
            } else {
                fwd.recv_list[i] = hipcMakeRecvStatic(nullptr, 0);
            }
        }
    }

    const Result fwd_rc = svcSendSyncRequest(fwd_handle);

    // Close caller-transferred input copy handles now that fwd_handle has received them.
    // Note: caller move handles sent to fwd_handle were already moved out by the kernel on svcSendSyncRequest success.
    for (u32 i = 0; i < in.meta.num_copy_handles; ++i) {
        if (in.data.copy_handles[i] != INVALID_HANDLE) {
            svcCloseHandle(in.data.copy_handles[i]);
        }
    }
    if (R_FAILED(fwd_rc)) {
        for (u32 i = 0; i < in.meta.num_move_handles; ++i) {
            if (in.data.move_handles[i] != INVALID_HANDLE) {
                svcCloseHandle(in.data.move_handles[i]);
            }
        }
        if (dyn_staging) std::free(dyn_staging);
        WriteSimpleCmifResponse(tls_base, fwd_rc, nullptr, 0);
        return fwd_rc;
    }

    for (u32 i = 0; i < recv_count; ++i) {
        if (recv_maps[i].size > 0 && recv_maps[i].client_addr && recv_maps[i].staging_ptr) {
            std::memcpy(recv_maps[i].client_addr, recv_maps[i].staging_ptr, recv_maps[i].size);
        }
    }
    for (u32 i = 0; i < exch_count; ++i) {
        if (exch_maps[i].size > 0 && exch_maps[i].client_addr && exch_maps[i].staging_ptr) {
            std::memcpy(exch_maps[i].client_addr, exch_maps[i].staging_ptr, exch_maps[i].size);
        }
    }
    if (dyn_staging) {
        std::free(dyn_staging);
        dyn_staging = nullptr;
    }

    alignas(16) uint32_t saved_resp_tls[64] = {};
    std::memcpy(saved_resp_tls, tls_base, sizeof(saved_resp_tls));
    const HipcResponse resp = hipcParseResponse(saved_resp_tls);

    // Inspect SFCO header + BSD ret/errno if present.
    const auto* resp_start = static_cast<const uint8_t*>(cmifGetAlignedDataStart(resp.data_words, saved_resp_tls));
    const size_t resp_bytes = resp.num_data_words * sizeof(uint32_t);
    const size_t resp_off = static_cast<size_t>(resp_start - reinterpret_cast<const uint8_t*>(resp.data_words));
    if (resp_bytes >= resp_off + sizeof(CmifOutHeader)) {
        const auto* out_hdr = reinterpret_cast<const CmifOutHeader*>(resp_start);
        if (out_hdr->magic == CMIF_OUT_HEADER_MAGIC) {
            if (out_cmif_rc) *out_cmif_rc = out_hdr->result;
            const size_t payload_bytes = resp_bytes - resp_off - sizeof(CmifOutHeader);
            if (payload_bytes >= 8) {
                const auto* words = reinterpret_cast<const int32_t*>(out_hdr + 1);
                if (out_bsd_ret) *out_bsd_ret = words[0];
                if (out_bsd_errno) *out_bsd_errno = words[1];
            }
        }
    }

    HipcMetadata rep_meta{};
    rep_meta.type = 0;
    rep_meta.num_send_statics = resp.num_statics;
    rep_meta.num_data_words = resp.num_data_words;
    rep_meta.num_copy_handles = resp.num_copy_handles;
    rep_meta.num_move_handles = resp.num_move_handles;
    HipcRequest reply = hipcMakeRequest(tls_base, rep_meta);

    u32 close_cnt = 0;
    for (u32 i = 0; i < resp.num_copy_handles; ++i) {
        reply.copy_handles[i] = resp.copy_handles[i];
        if (out_close_after_reply && close_cnt < out_close_cap && resp.copy_handles[i] != INVALID_HANDLE) {
            out_close_after_reply[close_cnt++] = resp.copy_handles[i];
        }
    }
    if (out_close_count) {
        *out_close_count = close_cnt;
    }

    for (u32 i = 0; i < resp.num_move_handles; ++i) {
        reply.move_handles[i] = resp.move_handles[i];
    }
    for (u32 i = 0; i < resp.num_statics; ++i) {
        reply.send_statics[i] = resp.statics[i];
    }
    if (resp.num_data_words > 0) {
        std::memcpy(reply.data_words, resp.data_words, resp.num_data_words * sizeof(uint32_t));
    }

    return 0;
}

}  // namespace yumi_nx::sys::mitm_ipc
