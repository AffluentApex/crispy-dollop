#include <gtest/gtest.h>
#include "../../src/behavioral/behavior_analyzer.h"
#include "../test_framework.h"
#include <windows.h>
#include <psapi.h>

class BehaviorAnalyzerTest : public ::testing::Test {
protected:
    BehaviorAnalyzer analyzer;
    DWORD testProcessId;
    std::string testDir = "C:/Users/Ronit/CascadeProjects/simple_antivirus/tests/samples/";

    void SetUp() override {
        // Create and start a test process
        STARTUPINFO si = {sizeof(STARTUPINFO)};
        PROCESS_INFORMATION pi;
        CreateProcess(NULL, (LPSTR)"notepad.exe", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
        testProcessId = pi.dwProcessId;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    void TearDown() override {
        // Terminate test process
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, testProcessId);
        if (hProcess) {
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }
    }
};

TEST_F(BehaviorAnalyzerTest, DetectsAPICall) {
    analyzer.startProcessMonitoring();
    analyzer.hookProcess(testProcessId);
    
    // Wait for some API calls
    Sleep(1000);
    
    auto apiCalls = analyzer.getAPIHistory(testProcessId);
    EXPECT_FALSE(apiCalls.empty());
}

TEST_F(BehaviorAnalyzerTest, DetectsFileOperations) {
    analyzer.startProcessMonitoring();
    analyzer.hookProcess(testProcessId);
    
    // Create a file operation
    std::string testFile = testDir + "test.txt";
    HANDLE hFile = CreateFile(testFile.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 
                            FILE_ATTRIBUTE_NORMAL, NULL);
    CloseHandle(hFile);
    
    auto fileActivities = analyzer.getFileActivity(testProcessId);
    EXPECT_FALSE(fileActivities.empty());
    
    // Cleanup
    DeleteFile(testFile.c_str());
}

TEST_F(BehaviorAnalyzerTest, DetectsNetworkActivity) {
    analyzer.startProcessMonitoring();
    analyzer.hookProcess(testProcessId);
    
    // Create network activity
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    closesocket(sock);
    WSACleanup();
    
    auto networkActivities = analyzer.getNetworkActivity(testProcessId);
    EXPECT_FALSE(networkActivities.empty());
}

TEST_F(BehaviorAnalyzerTest, DetectsMemoryOperations) {
    analyzer.startProcessMonitoring();
    analyzer.hookProcess(testProcessId);
    
    // Perform memory operations
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, testProcessId);
    if (hProcess) {
        VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_READWRITE);
        CloseHandle(hProcess);
    }
    
    analyzer.scanProcessMemory(testProcessId);
    EXPECT_TRUE(analyzer.detectCodeInjection(testProcessId));
}

TEST_F(BehaviorAnalyzerTest, CalculatesRiskScore) {
    analyzer.startProcessMonitoring();
    analyzer.hookProcess(testProcessId);
    
    // Perform suspicious operations
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, testProcessId);
    if (hProcess) {
        void* addr = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(hProcess, addr, "test", 4, NULL);
        CloseHandle(hProcess);
    }
    
    float riskScore = analyzer.analyzeProcessBehavior(testProcessId);
    EXPECT_GT(riskScore, 0.5f); // High risk score expected
}

TEST_F(BehaviorAnalyzerTest, DetectsProcessHollowing) {
    analyzer.startProcessMonitoring();
    analyzer.hookProcess(testProcessId);
    
    EXPECT_FALSE(analyzer.detectHollowingAttempt(testProcessId)); // No hollowing in notepad
}
