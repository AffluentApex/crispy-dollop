#include <gtest/gtest.h>
#include "../../src/scanner.h"
#include "../test_framework.h"

class ScannerTest : public ::testing::Test {
protected:
    Scanner scanner;
    std::string testDir = "C:/Users/Ronit/CascadeProjects/simple_antivirus/tests/samples/";

    void SetUp() override {
        // Create test files
        createEicarFile();
        createCleanFile();
        createSuspiciousFile();
    }

    void TearDown() override {
        // Cleanup test files
        cleanupFiles();
    }

    void createEicarFile() {
        std::ofstream file(testDir + "eicar.txt");
        file << "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    }

    void createCleanFile() {
        std::ofstream file(testDir + "clean.txt");
        file << "This is a clean file with normal content.";
    }

    void createSuspiciousFile() {
        std::ofstream file(testDir + "suspicious.exe");
        file << "MZ" << std::string(50, '\0') << "CreateRemoteThread";
    }

    void cleanupFiles() {
        remove((testDir + "eicar.txt").c_str());
        remove((testDir + "clean.txt").c_str());
        remove((testDir + "suspicious.exe").c_str());
    }
};

TEST_F(ScannerTest, DetectsEicarFile) {
    EXPECT_TRUE(scanner.scanFile(testDir + "eicar.txt"));
}

TEST_F(ScannerTest, IdentifiesCleanFile) {
    EXPECT_FALSE(scanner.scanFile(testDir + "clean.txt"));
}

TEST_F(ScannerTest, DetectsSuspiciousPatterns) {
    EXPECT_TRUE(scanner.scanFile(testDir + "suspicious.exe"));
}

TEST_F(ScannerTest, HandlesNonexistentFile) {
    EXPECT_FALSE(scanner.scanFile(testDir + "nonexistent.txt"));
}

TEST_F(ScannerTest, CalculatesCorrectHash) {
    std::string hash = scanner.calculateFileHash(testDir + "clean.txt");
    EXPECT_FALSE(hash.empty());
    EXPECT_EQ(hash.length(), 32); // MD5 hash length
}

TEST_F(ScannerTest, DetectsMultipleThreats) {
    scanner.scanDirectory(testDir);
    EXPECT_GE(scanner.getTotalThreats(), 2);
}
