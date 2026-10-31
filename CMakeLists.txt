cmake_minimum_required(VERSION 3.16)
project(nftpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


#-----------------------
option(NFTPP_ENABLE_SANITIZERS "Build with AddressSanitizer + UBSan" OFF)
option(NFTPP_BUILD_EXAMPLES "Build programs in examples/" OFF)


#Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNFTNL REQUIRED IMPORTED_TARGET libnftnl)
pkg_check_modules(LIBMNL REQUIRED IMPORTED_TARGET libmnl)


#---Library---
add_library(nftpp
    src/expr_builders.hpp
    src/table.cpp
    src/rule.cpp
    src/chain.cpp
    src/firewall.cpp
    src/batch.cpp
    src/expr.cpp
    src/verdict.cpp
    )

add_library(nftpp::nftpp ALIAS nftpp)


target_include_directories(nftpp
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>

    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src #expr_builders.hpp 
)

target_link_libraries(nftpp
    PUBLIC
        PkgConfig::LIBMNL
        PkgConfig::LIBNFTNL
)













