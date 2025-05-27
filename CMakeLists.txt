cmake_minimum_required(VERSION 3.31)
project(ewallet-manager)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Fully static linking
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static")

# Add cpp-otp library
add_subdirectory(deps/cpp-otp)

# Add source files
set(SOURCES
    src/main.cpp
    src/user.cpp
    src/wallet.cpp
    src/database.cpp
    src/ui.cpp
)

# Add header files
set(HEADERS
    include/user.hpp
    include/wallet.hpp
    include/database.hpp
    include/ui.hpp
    include/hmac.hpp
)

# Create executable
add_executable(ewallet-manager ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(ewallet-manager PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/cpp-otp/src
)

# Link libraries
target_link_libraries(ewallet-manager PRIVATE
    cotp
)
