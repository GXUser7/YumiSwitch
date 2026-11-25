cmake_minimum_required(VERSION 3.20)
project(YumiSwitchDesktop LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Third-party: Yoga (static C++20)
file(GLOB_RECURSE YOGA_SOURCES CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/yoga/yoga/*.cpp"
)
add_library(yumi_yoga STATIC ${YOGA_SOURCES})
target_include_directories(yumi_yoga PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/yoga"
)
if(MINGW)
    target_compile_options(yumi_yoga PRIVATE -O2)
endif()

# Shared common library
add_library(yumi_common STATIC
    common/src/models.cpp
    common/src/config_store.cpp
    common/src/qr_matrix.cpp
    common/src/subscription_parser.cpp
    common/src/rules_bin.cpp
)
target_include_directories(yumi_common PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/common/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party"
)

# Core networking library (crypto, sockets, DNS/DoH, TLS 1.3/REALITY/uTLS/Fragment, transports, dialers, TunnelEngine)
add_library(yumi_core_net STATIC
    core-net/src/router_stub.cpp
    core-net/src/crypto_primitives.cpp
    core-net/src/p256_ecdh.cpp
    core-net/src/socket_io.cpp
    core-net/src/dns_engine.cpp
    core-net/src/tls13_reality.cpp
    core-net/src/transports.cpp
    core-net/src/vless_dialer.cpp
    core-net/src/wireguard_dialer.cpp
    core-net/src/shadowsocks_dialer.cpp
    core-net/src/trojan_dialer.cpp
    core-net/src/vmess_dialer.cpp
    core-net/src/hysteria2_dialer.cpp
    core-net/src/simple_dialers.cpp
    core-net/src/tunnel_engine.cpp
)
target_include_directories(yumi_core_net PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/core-net/include"
)
target_link_libraries(yumi_core_net PUBLIC yumi_common)
if(WIN32)
    target_link_libraries(yumi_core_net PUBLIC ws2_32 bcrypt)
endif()

# Application logic services (HTTP client, QR pairing, latency tester, LAN remote, HOS apps, SpeedTest, GitHub updater)
add_library(yumi_app_logic STATIC
    app/source/logic/http_client.cpp
    app/source/logic/pairing_service.cpp
    app/source/logic/latency_tester.cpp
    app/source/logic/remote_service.cpp
    app/source/logic/hos_apps.cpp
    app/source/logic/speed_tester.cpp
    app/source/logic/update_checker.cpp
)
target_include_directories(yumi_app_logic PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/app/source/logic"
)
target_link_libraries(yumi_app_logic PUBLIC yumi_core_net yumi_common)

# NanoVG vector renderer (no GL backend symbols inside library itself)
add_library(yumi_nanovg STATIC
    third_party/nanovg/src/nanovg.c
)
target_include_directories(yumi_nanovg PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/nanovg/src"
)

# Unit tests executable
add_executable(yumi_tests
    tests/test_main.cpp
    app/source/ui/yumi_theme.cpp
)
target_include_directories(yumi_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/app/source"
)
target_link_libraries(yumi_tests PRIVATE yumi_app_logic yumi_core_net yumi_common yumi_nanovg)
if(MINGW)
    target_compile_options(yumi_tests PRIVATE -Wall -Wextra -fno-exceptions)
endif()

# Desktop UI preview executable (1280x720 GLFW + OpenGL3 + NanoVG + Yoga)
find_package(OpenGL REQUIRED)
find_package(GLEW REQUIRED)
find_package(glfw3 REQUIRED)

add_executable(desktop_preview
    app/source/ui/yumi_theme.cpp
    app/source/ui/visualizers.cpp
    app/source/ui/ui_app.cpp
    app/source/platform/desktop/main_desktop.cpp
)
target_include_directories(desktop_preview PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/app/source/ui"
    "${CMAKE_CURRENT_SOURCE_DIR}/app/source/logic"
    "${CMAKE_CURRENT_SOURCE_DIR}/app/source/platform/desktop"
)
target_link_libraries(desktop_preview PRIVATE
    yumi_app_logic
    yumi_core_net
    yumi_common
    yumi_yoga
    yumi_nanovg
    GLEW::GLEW
    glfw
    OpenGL::GL
)
if(MINGW)
    target_compile_options(desktop_preview PRIVATE -Wall -Wextra -fno-exceptions)
endif()
