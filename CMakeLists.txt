cmake_minimum_required(VERSION 3.16)
project(CANShield VERSION 0.1.0 LANGUAGES CXX)

# ---------------------------------------------------------------------------
# CANShield - Automotive CAN bus security research testbed
#
# Portability model:
#   * On Linux we compile the real SocketCAN transport (CANSHIELD_HAVE_SOCKETCAN)
#     so the same binaries run against vcan0 / a Raspberry Pi CAN HAT.
#   * On macOS / other platforms only the cross-platform VirtualCanBus is built,
#     so the ECU simulator, attack injector, IDS and evaluation harness all run
#     and can be developed/tested without CAN hardware.
# ---------------------------------------------------------------------------

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)  # feeds clangd / the editor LSP

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

# Detect SocketCAN (Linux only).
include(CheckIncludeFileCXX)
check_include_file_cxx("linux/can.h" CANSHIELD_HAVE_SOCKETCAN)

# ---------------------------------------------------------------------------
# Core library
# ---------------------------------------------------------------------------
file(GLOB CANSHIELD_SOURCES CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/src/*.cpp")
add_library(canshield STATIC ${CANSHIELD_SOURCES})
target_include_directories(canshield PUBLIC "${CMAKE_SOURCE_DIR}/include")

find_package(Threads REQUIRED)
target_link_libraries(canshield PUBLIC Threads::Threads)

if(CANSHIELD_HAVE_SOCKETCAN)
    target_compile_definitions(canshield PUBLIC CANSHIELD_HAVE_SOCKETCAN=1)
    message(STATUS "CANShield: SocketCAN available -> real CAN transport enabled")
else()
    message(STATUS "CANShield: SocketCAN NOT available -> VirtualCanBus only "
                   "(fine for development on macOS/Windows)")
endif()

# ---------------------------------------------------------------------------
# Applications (one executable per apps/*.cpp)
# ---------------------------------------------------------------------------
file(GLOB CANSHIELD_APPS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/apps/*.cpp")
foreach(app_src ${CANSHIELD_APPS})
    get_filename_component(app_name "${app_src}" NAME_WE)
    add_executable(${app_name} "${app_src}")
    target_link_libraries(${app_name} PRIVATE canshield)
endforeach()

# ---------------------------------------------------------------------------
# Tests (one executable per tests/test_*.cpp, registered with ctest)
# ---------------------------------------------------------------------------
enable_testing()
file(GLOB CANSHIELD_TESTS CONFIGURE_DEPENDS "${CMAKE_SOURCE_DIR}/tests/test_*.cpp")
foreach(test_src ${CANSHIELD_TESTS})
    get_filename_component(test_name "${test_src}" NAME_WE)
    add_executable(${test_name} "${test_src}")
    target_link_libraries(${test_name} PRIVATE canshield)
    target_include_directories(${test_name} PRIVATE "${CMAKE_SOURCE_DIR}/tests")
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()
