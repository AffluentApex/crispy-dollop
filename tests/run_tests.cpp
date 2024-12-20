#include <gtest/gtest.h>
#include "test_framework.h"
#include <iostream>
#include <chrono>

int main(int argc, char** argv) {
    std::cout << "Starting SimpleAV Test Suite..." << std::endl;
    auto startTime = std::chrono::high_resolution_clock::now();

    // Initialize Google Test
    testing::InitGoogleTest(&argc, argv);
    
    // Run all tests
    int result = RUN_ALL_TESTS();
    
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
    
    std::cout << "\nTest Summary:" << std::endl;
    std::cout << "-------------" << std::endl;
    std::cout << "Total Duration: " << duration.count() << " seconds" << std::endl;
    
    if (result == 0) {
        std::cout << "All tests passed successfully!" << std::endl;
    } else {
        std::cout << "Some tests failed. Check the output above for details." << std::endl;
    }
    
    return result;
}
