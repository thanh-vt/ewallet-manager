cmake_minimum_required(VERSION 3.31)
project(cotp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Define NO_OPENSSL to disable OpenSSL dependency
add_definitions(-DNO_OPENSSL)

# Add library
add_library(cotp STATIC
    src/cotp.cpp
)

# Include directories
target_include_directories(cotp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
) 