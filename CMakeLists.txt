cmake_minimum_required(VERSION 3.15)
project(SimpleAntivirus VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)

# Source files
set(SOURCES
    src/main.cpp
    src/scanner.cpp
    src/realtime_monitor.cpp
)

# Create executable
add_executable(simple_av ${SOURCES})

# Include directories
target_include_directories(simple_av PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(simple_av PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Optional: Build tests if GTest is found
find_package(GTest)
if(GTest_FOUND)
    enable_testing()
    
    set(TEST_SOURCES
        tests/run_tests.cpp
        tests/unit_tests/scanner_tests.cpp
        tests/unit_tests/ml_detector_tests.cpp
        tests/unit_tests/behavior_analyzer_tests.cpp
        tests/unit_tests/sandbox_tests.cpp
    )
    
    add_executable(run_tests ${TEST_SOURCES})
    target_link_libraries(run_tests PRIVATE
        GTest::GTest
        GTest::Main
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    
    add_test(NAME unit_tests COMMAND run_tests)
endif()
