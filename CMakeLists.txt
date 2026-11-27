cmake_minimum_required(VERSION 3.20)
project(syncstream VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SYNCSTREAM_STRICT "Enable strict warnings" ON)
option(SYNCSTREAM_BUILD_EXAMPLES "Build integration examples" ON)

find_package(OpenSSL REQUIRED)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_library(syncstream STATIC
    src/secure_channel.cpp
    src/middleware.cpp
    src/keychain.cpp
    src/edge_hub.cpp
    src/api.cpp
)

target_include_directories(syncstream
    PUBLIC
        $<BUILD_INTERFACE:\${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:\${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(syncstream PUBLIC OpenSSL::Crypto)

if(SYNCSTREAM_STRICT)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(syncstream PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wformat=2 -Werror)
    elseif(MSVC)
        target_compile_options(syncstream PRIVATE /W4 /WX)
    endif()
endif()

add_executable(syncstream_cli src/main.cpp)
target_link_libraries(syncstream_cli PRIVATE syncstream)

if(SYNCSTREAM_BUILD_EXAMPLES)
    add_executable(syncstream_mobile_bridge examples/mobile_bridge.cpp)
    target_link_libraries(syncstream_mobile_bridge PRIVATE syncstream)

    add_executable(syncstream_edge_hub_demo examples/edge_hub_demo.cpp)
    target_link_libraries(syncstream_edge_hub_demo PRIVATE syncstream)
endif()

enable_testing()

add_executable(syncstream_secure_channel_tests tests/secure_channel_test.cpp)
target_link_libraries(syncstream_secure_channel_tests PRIVATE syncstream)
add_test(NAME syncstream_secure_channel_tests COMMAND syncstream_secure_channel_tests)

add_executable(syncstream_middleware_tests tests/middleware_test.cpp)
target_link_libraries(syncstream_middleware_tests PRIVATE syncstream)
add_test(NAME syncstream_middleware_tests COMMAND syncstream_middleware_tests)

add_executable(syncstream_edge_hub_tests tests/edge_hub_test.cpp)
target_link_libraries(syncstream_edge_hub_tests PRIVATE syncstream)
add_test(NAME syncstream_edge_hub_tests COMMAND syncstream_edge_hub_tests)

add_executable(syncstream_api_tests tests/api_test.cpp)
target_link_libraries(syncstream_api_tests PRIVATE syncstream)
add_test(NAME syncstream_api_tests COMMAND syncstream_api_tests)

install(
    TARGETS syncstream
    EXPORT SyncStreamTargets
    ARCHIVE DESTINATION \${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION \${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION \${CMAKE_INSTALL_BINDIR}
)

install(
    DIRECTORY include/
    DESTINATION \${CMAKE_INSTALL_INCLUDEDIR}
)

install(
    EXPORT SyncStreamTargets
    FILE SyncStreamTargets.cmake
    NAMESPACE SyncStream::
    DESTINATION \${CMAKE_INSTALL_LIBDIR}/cmake/SyncStream
)

configure_package_config_file(
    \${CMAKE_CURRENT_SOURCE_DIR}/cmake/SyncStreamConfig.cmake.in
    \${CMAKE_CURRENT_BINARY_DIR}/SyncStreamConfig.cmake
    INSTALL_DESTINATION \${CMAKE_INSTALL_LIBDIR}/cmake/SyncStream
)

write_basic_package_version_file(
    \${CMAKE_CURRENT_BINARY_DIR}/SyncStreamConfigVersion.cmake
    VERSION \${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(
    FILES
        \${CMAKE_CURRENT_BINARY_DIR}/SyncStreamConfig.cmake
        \${CMAKE_CURRENT_BINARY_DIR}/SyncStreamConfigVersion.cmake
    DESTINATION \${CMAKE_INSTALL_LIBDIR}/cmake/SyncStream
)
