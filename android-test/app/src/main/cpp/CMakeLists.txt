cmake_minimum_required(VERSION 3.22.1)
project(syncstream_android_test LANGUAGES CXX)

set(SYNCSTREAM_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SYNCSTREAM_STRICT OFF CACHE BOOL "" FORCE)
add_subdirectory(../../../../ syncstream-build EXCLUDE_FROM_ALL)

add_library(syncstream_android SHARED native_bridge.cpp)

target_compile_features(syncstream_android PRIVATE cxx_std_20)
target_link_libraries(syncstream_android PRIVATE syncstream log)

target_include_directories(syncstream_android PRIVATE
    ../../../../include
)
