#include <switch.h>
#include <cstdint>

#include "hos_compat.hpp"
#include "ipc/yumi_ctl_server.hpp"
#include "mitm/network_mitm.hpp"
#include "power/power_net_monitor.hpp"
#include "yumi_nx/socket_io.hpp"
#include "yumi_nx/tunnel_engine.hpp"
#include <new>

// Phase 2 sysmodule inner heap: 3 MB total (leaves 2.5 MB margin below HOS 20.0+ 5.5 MB budget).
#define YUMI_INNER_HEAP_SIZE 0x300000

extern "C" {

u32 __nx_applet_type = AppletType_None;
u32 __nx_fs_num_sessions = 1;

void __libnx_initheap(void) {
    alignas(16) static u8 inner_heap[YUMI_INNER_HEAP_SIZE];
    extern void* fake_heap_start;
    extern void* fake_heap_end;
    fake_heap_start = inner_heap;
    fake_heap_end = inner_heap + sizeof(inner_heap);
}

void __appInit(void) {
    Result rc = smInitialize();
    if (R_FAILED(rc)) {
        diagAbortWithResult(MAKERESULT(Module_Libnx, LibnxError_InitFail_SM));
    }

    rc = setsysInitialize();
    if (R_SUCCEEDED(rc)) {
        SetSysFirmwareVersion fw{};
        if (R_SUCCEEDED(setsysGetFirmwareVersion(&fw))) {
            hosversionSet(MAKEHOSVERSION(fw.major, fw.minor, fw.micro));
        }
        setsysExit();
    }

    rc = fsInitialize();
    if (R_FAILED(rc)) {
        diagAbortWithResult(MAKERESULT(Module_Libnx, LibnxError_InitFail_FS));
    }
    fsdevMountSdmc();
    // Keep sm active so YumiCtlServer can register yumi:ctl in main().
}

void __appExit(void) {
    fsdevUnmountAll();
    fsExit();
    smExit();
}

}  // extern "C"

int main(int, char**) {
    const auto hos = yumi_nx::sys::DetectHosCompat();
    yumi_nx::net::SocketLayerInit();

    yumi_nx::sys::YumiCtlServer server(hos, YUMI_INNER_HEAP_SIZE);
    if (!server.StartService()) {
        yumi_nx::net::SocketLayerShutdown();
        return 1;
    }

    auto* tunnel = new (std::nothrow) yumi_nx::net::TunnelEngine();
    if (tunnel) {
        tunnel->SetCallbacks(
            [&server](uint64_t up, uint64_t down) { server.AddTrafficBytes(up, down); },
            [&server](yumi_nx::LogLevel lvl, const char* msg) { server.AppendLog(lvl, msg); });
        server.SetTunnelEngine(tunnel);
    }

    auto* mitm_mgr = new (std::nothrow) yumi_nx::sys::NetworkMitmManager(&server);
    if (mitm_mgr) {
        server.SetMitmManager(mitm_mgr);
        if (!mitm_mgr->Start()) {
            server.AppendLog(yumi_nx::LogLevel::Warn, "Network MITM started without sm: hook (fallback telemetry mode)");
        }
    }

    auto* power_net = new (std::nothrow) yumi_nx::sys::PowerNetMonitor(&server);
    if (power_net) {
        power_net->Start();
    }

    server.RunLoop();

    if (power_net) {
        power_net->Stop();
        delete power_net;
    }
    if (mitm_mgr) {
        mitm_mgr->Stop();
        delete mitm_mgr;
    }
    if (tunnel) {
        tunnel->Stop();
        server.SetTunnelEngine(nullptr);
        delete tunnel;
    }

    server.StopService();
    yumi_nx::net::SocketLayerShutdown();
    return 0;
}
