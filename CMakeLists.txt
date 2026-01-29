cmake_minimum_required(VERSION 3.14)
project(binary-protocol-fuzzer VERSION 1.0.0 LANGUAGES CXX)

# Require C++17 for std::optional, std::byte, and other modern features
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings for better code quality
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion)
    add_compile_options(-Wsign-conversion -Wnull-dereference -Wdouble-promotion)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    add_compile_options(-Wduplicated-cond -Wduplicated-branches)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wimplicit-fallthrough)
endif()

# Debug and release build configurations
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG")

# Default to Release build if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Main fuzzer executable
add_executable(fuzzer
    src/main.cpp
    src/fuzzer.cpp
    src/protocol.cpp
)

target_include_directories(fuzzer PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Enable threading support
find_package(Threads REQUIRED)
target_link_libraries(fuzzer PRIVATE Threads::Threads)

# Test executable
enable_testing()

add_executable(test_fuzzer
    tests/test_fuzzer.cpp
    src/fuzzer.cpp
    src/protocol.cpp
)

target_include_directories(test_fuzzer PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(test_fuzzer PRIVATE Threads::Threads)

# Register tests with CTest
add_test(NAME ProtocolTests COMMAND test_fuzzer)

# Install targets
install(TARGETS fuzzer DESTINATION bin)

# Generate config header with version info
configure_file(
    ${CMAKE_SOURCE_DIR}/cmake/config.h.in
    ${CMAKE_BINARY_DIR}/generated/config.h
    @ONLY
)

target_include_directories(fuzzer PRIVATE ${CMAKE_BINARY_DIR}/generated)

# Custom target for running the fuzzer with default settings
add_custom_target(run-fuzzer
    COMMAND $<TARGET_FILE:fuzzer> -n 10000 -v
    DEPENDS fuzzer
    COMMENT "Running fuzzer with default settings"
)

# Custom target for building with sanitizers (for development)
option(ENABLE_SANITIZERS "Enable address and undefined behavior sanitizers" OFF)

if(ENABLE_SANITIZERS)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(fuzzer PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(fuzzer PRIVATE -fsanitize=address,undefined)
        
        target_compile_options(test_fuzzer PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(test_fuzzer PRIVATE -fsanitize=address,undefined)
    endif()
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "Binary Protocol Fuzzer Configuration:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "  Sanitizers: ${ENABLE_SANITIZERS}")
message(STATUS "")
