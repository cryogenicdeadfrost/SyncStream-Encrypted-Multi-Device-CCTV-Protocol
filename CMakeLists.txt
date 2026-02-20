cmake_minimum_required(VERSION 3.20)
project(syncstream LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(SYNCSTREAM_STRICT "Enable strict warnings" ON)

find_package(OpenSSL REQUIRED)

add_library(syncstream STATIC
    src/secure_channel.cpp
    src/middleware.cpp
    src/keychain.cpp
    src/edge_hub.cpp
)

target_include_directories(syncstream PUBLIC include)
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

add_executable(syncstream_mobile_bridge examples/mobile_bridge.cpp)
target_link_libraries(syncstream_mobile_bridge PRIVATE syncstream)

add_executable(syncstream_edge_hub_demo examples/edge_hub_demo.cpp)
target_link_libraries(syncstream_edge_hub_demo PRIVATE syncstream)

enable_testing()
add_executable(syncstream_tests tests/secure_channel_test.cpp)
target_link_libraries(syncstream_tests PRIVATE syncstream)
add_test(NAME syncstream_tests COMMAND syncstream_tests)

add_executable(syncstream_middleware_tests tests/middleware_test.cpp)
target_link_libraries(syncstream_middleware_tests PRIVATE syncstream)
add_test(NAME syncstream_middleware_tests COMMAND syncstream_middleware_tests)

add_executable(syncstream_edge_hub_tests tests/edge_hub_test.cpp)
target_link_libraries(syncstream_edge_hub_tests PRIVATE syncstream)
add_test(NAME syncstream_edge_hub_tests COMMAND syncstream_edge_hub_tests)
