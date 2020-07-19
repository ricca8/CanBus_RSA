cmake_minimum_required(VERSION 3.10)
project(ACS_Project)

set(CMAKE_CXX_STANDARD 14)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(include)

add_executable(ACS_Project
        main.cpp
        crypto.cpp
        include/crypto.h
        include/socketcan_cpp.h
        include/socketcan_cpp_export.h
        socketcan_cpp.cpp
        )

target_link_libraries(ACS_Project ${OPENSSL_LIBRARIES})