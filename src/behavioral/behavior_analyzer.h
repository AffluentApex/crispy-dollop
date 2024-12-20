#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <map>
#include <thread>
#include <mutex>

class BehaviorAnalyzer {
public:
    BehaviorAnalyzer();
    ~BehaviorAnalyzer();

    // Process monitoring
    void startProcessMonitoring();
    void stopProcessMonitoring();
    bool hookProcess(DWORD processId);
    
    // API monitoring
    struct APICall {
        std::string name;
        std::vector<std::string> parameters;
        DWORD threadId;
        DWORD processId;
        std::chrono::system_clock::time_point timestamp;
    };
    
    std::vector<APICall> getAPIHistory(DWORD processId);
    void clearAPIHistory(DWORD processId);
    
    // Behavioral patterns
    struct BehaviorPattern {
        std::string name;
        float risk_score;
        std::vector<std::string> required_apis;
        std::vector<std::string> indicators;
    };
    
    // Analysis
    float analyzeProcessBehavior(DWORD processId);
    std::vector<std::string> detectAnomalies(DWORD processId);
    bool isProcessMalicious(DWORD processId);
    
    // Memory analysis
    void scanProcessMemory(DWORD processId);
    bool detectCodeInjection(DWORD processId);
    bool detectHollowingAttempt(DWORD processId);
    
    // Network behavior
    struct NetworkActivity {
        std::string protocol;
        std::string localAddress;
        std::string remoteAddress;
        uint16_t localPort;
        uint16_t remotePort;
        size_t bytesTransferred;
        std::chrono::system_clock::time_point timestamp;
    };
    
    std::vector<NetworkActivity> getNetworkActivity(DWORD processId);
    bool isNetworkBehaviorMalicious(DWORD processId);
    
    // File system monitoring
    struct FileActivity {
        std::string path;
        std::string operation;
        std::chrono::system_clock::time_point timestamp;
        bool wasBlocked;
    };
    
    std::vector<FileActivity> getFileActivity(DWORD processId);
    bool isFileOperationMalicious(const std::string& path, const std::string& operation);
    
private:
    // Internal monitoring
    std::thread monitorThread;
    std::mutex dataMutex;
    bool isMonitoring;
    
    // Hooks
    struct Hook {
        void* original;
        void* detour;
        std::string apiName;
    };
    std::map<std::string, Hook> hooks;
    
    // Pattern database
    std::vector<BehaviorPattern> knownPatterns;
    
    // Process data
    struct ProcessData {
        std::vector<APICall> apiCalls;
        std::vector<NetworkActivity> networkActivities;
        std::vector<FileActivity> fileActivities;
        float riskScore;
    };
    std::map<DWORD, ProcessData> processDatabase;
    
    // Analysis helpers
    float calculateRiskScore(const ProcessData& data);
    bool matchesPattern(const std::vector<APICall>& calls, const BehaviorPattern& pattern);
    void updateProcessDatabase(DWORD processId, const APICall& call);
};
