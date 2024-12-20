#include <gtest/gtest.h>
#include "../../src/sandbox/sandbox_manager.h"
#include "../test_framework.h"

class SandboxTest : public ::testing::Test {
protected:
    SandboxManager sandbox;
    std::string testDir = "C:/Users/Ronit/CascadeProjects/simple_antivirus/tests/samples/";

    void SetUp() override {
        // Create test files
        createTestExecutable();
        createTestScript();
        sandbox.initializeSandbox("test_sandbox");
    }

    void TearDown() override {
        sandbox.terminateSandbox();
        cleanupFiles();
    }

    void createTestExecutable() {
        std::ofstream file(testDir + "test.exe", std::ios::binary);
        // Write minimal PE header
        const char mz[] = "MZ";
        file.write(mz, 2);
        file.write("\0", 1024); // Padding
    }

    void createTestScript() {
        std::ofstream file(testDir + "test.bat");
        file << "@echo off\n";
        file << "echo Hello from sandbox\n";
        file << "dir C:\\\n";
    }

    void cleanupFiles() {
        remove((testDir + "test.exe").c_str());
        remove((testDir + "test.bat").c_str());
    }
};

TEST_F(SandboxTest, InitializesSandbox) {
    EXPECT_TRUE(sandbox.initializeSandbox("new_sandbox"));
}

TEST_F(SandboxTest, ExecutesFile) {
    EXPECT_TRUE(sandbox.executeFile(testDir + "test.bat"));
    auto activities = sandbox.getActivities();
    EXPECT_FALSE(activities.empty());
}

TEST_F(SandboxTest, RestrictsNetwork) {
    sandbox.enableNetwork(false);
    EXPECT_TRUE(sandbox.executeFile(testDir + "test.exe"));
    auto activities = sandbox.getActivities();
    
    bool networkBlocked = false;
    for (const auto& activity : activities) {
        if (activity.type == "network" && activity.wasBlocked) {
            networkBlocked = true;
            break;
        }
    }
    EXPECT_TRUE(networkBlocked);
}

TEST_F(SandboxTest, RestrictsFileSystem) {
    std::vector<std::string> rules = {
        "deny_write C:\\Windows\\*",
        "allow_read C:\\Program Files\\*",
        "allow_all " + testDir + "*"
    };
    sandbox.setFileSystemRules(rules);
    
    EXPECT_TRUE(sandbox.executeFile(testDir + "test.bat"));
    auto activities = sandbox.getActivities();
    
    bool fileAccessBlocked = false;
    for (const auto& activity : activities) {
        if (activity.type == "filesystem" && activity.wasBlocked) {
            fileAccessBlocked = true;
            break;
        }
    }
    EXPECT_TRUE(fileAccessBlocked);
}

TEST_F(SandboxTest, EnforcesResourceLimits) {
    sandbox.setMemoryLimit(1024 * 1024); // 1MB
    sandbox.setCPULimit(10); // 10%
    sandbox.setTimeLimit(std::chrono::seconds(5));
    
    EXPECT_TRUE(sandbox.executeFile(testDir + "test.exe"));
    auto activities = sandbox.getActivities();
    
    bool resourceLimited = false;
    for (const auto& activity : activities) {
        if (activity.type == "resource" && activity.wasBlocked) {
            resourceLimited = true;
            break;
        }
    }
    EXPECT_TRUE(resourceLimited);
}

TEST_F(SandboxTest, HandlesRegistryAccess) {
    sandbox.enableRegistry(false);
    EXPECT_TRUE(sandbox.executeFile(testDir + "test.exe"));
    auto activities = sandbox.getActivities();
    
    bool registryBlocked = false;
    for (const auto& activity : activities) {
        if (activity.type == "registry" && activity.wasBlocked) {
            registryBlocked = true;
            break;
        }
    }
    EXPECT_TRUE(registryBlocked);
}
