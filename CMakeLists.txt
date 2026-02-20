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

enable_testing()
add_executable(syncstream_tests tests/secure_channel_test.cpp)
target_link_libraries(syncstream_tests PRIVATE syncstream)
add_test(NAME syncstream_tests COMMAND syncstream_tests)
