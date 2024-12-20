#pragma once
#include <string>
#include <vector>
#include <functional>
#include <chrono>
#include <iostream>
#include <fstream>
#include <gtest/gtest.h>

class TestFramework {
public:
    struct TestResult {
        std::string testName;
        bool passed;
        std::string message;
        std::chrono::milliseconds duration;
    };

    struct TestSuite {
        std::string name;
        std::vector<TestResult> results;
        bool allPassed;
        std::chrono::milliseconds totalDuration;
    };

    // Test registration
    void addTest(const std::string& name, std::function<bool()> testFunc);
    void addTestSuite(const std::string& name);
    
    // Test execution
    bool runAllTests();
    bool runTestSuite(const std::string& suiteName);
    bool runSingleTest(const std::string& testName);
    
    // Results
    void generateReport(const std::string& outputPath);
    std::vector<TestSuite> getResults() const;
    
    // Utilities
    static void createTestFile(const std::string& path, const std::vector<uint8_t>& content);
    static void cleanupTestFiles();
    
private:
    std::vector<std::pair<std::string, std::function<bool()>>> tests;
    std::vector<TestSuite> testSuites;
    std::vector<std::string> testFiles;
};
