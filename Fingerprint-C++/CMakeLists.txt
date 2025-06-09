# CMakeLists.txt
cmake_minimum_required(VERSION 3.15)
project(FingerprintCLI CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 自动查找并使用vcpkg安装的库
find_package(protobuf CONFIG REQUIRED)
find_package(oqs CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

# Protobuf C++代码生成
set(PROTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(PROTO_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/proto_gen")
file(GLOB PROTO_FILES "${PROTO_DIR}/*.proto")
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})
include_directories(${PROTO_OUT_DIR})

# 添加源文件
add_executable(FingerprintCLI
    src/main.cpp
    src/pqc_config_handler.cpp
    src/crypto_handler.cpp
    src/tpm_handler.cpp
    src/cpu_fetcher.cpp
    src/smbios_fetcher.cpp
    src/disk_fetcher.cpp
    src/gpu_fetcher.cpp
    src/os_benchmark_fetcher.cpp
    src/sgx_fetcher.cpp
    ${PROTO_SRCS}
    ${PROTO_HDRS}
)

# 链接所需的库
target_link_libraries(FingerprintCLI
    PRIVATE
    protobuf::libprotobuf
    oqs::oqs
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Windows特定库
if(WIN32)
    target_link_libraries(FingerprintCLI PRIVATE ws2_32 ncrypt.lib dxgi.lib)
endif()
