cmake_minimum_required(VERSION 3.10)
project(simple_antivirus)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add source files
add_executable(simple_antivirus
    src/main.cpp
    src/scanner.cpp
    src/realtime_monitor.cpp
)

# Include directories
target_include_directories(simple_antivirus PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    src
)

# Link libraries
target_link_libraries(simple_antivirus PRIVATE
    ${OPENSSL_LIBRARIES}
)
