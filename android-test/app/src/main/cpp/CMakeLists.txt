cmake_minimum_required(VERSION 3.22.1)
project(syncstream_android_test LANGUAGES CXX)

# The Android build consumes an ABI-specific OpenSSL/libcrypto prefix produced
# by scripts/build_android_openssl.sh. This keeps the protocol implementation
# identical to desktop builds while allowing Android to package libcrypto.
set(SYNCSTREAM_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SYNCSTREAM_STRICT OFF CACHE BOOL "" FORCE)
set(SYNCSTREAM_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SYNCSTREAM_BUILD_CLI OFF CACHE BOOL "" FORCE)

set(SYNCSTREAM_ANDROID_OPENSSL_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../../../third_party/android-openssl/${ANDROID_ABI}" CACHE PATH "" FORCE)
set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_LIST_DIR}/../../../../../third_party/android-openssl/${ANDROID_ABI}")
set(OPENSSL_USE_STATIC_LIBS TRUE)
set(CMAKE_PREFIX_PATH "${OPENSSL_ROOT_DIR};${CMAKE_PREFIX_PATH}")
set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include")
set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/lib/libcrypto.a")
add_subdirectory(../../../../../ syncstream-build EXCLUDE_FROM_ALL)

find_library(log-lib log)

add_library(syncstream_android SHARED native_bridge.cpp)

target_compile_features(syncstream_android PRIVATE cxx_std_20)
target_link_libraries(syncstream_android PRIVATE syncstream ${log-lib} dl)

target_include_directories(syncstream_android PRIVATE
    ../../../../../include
)
