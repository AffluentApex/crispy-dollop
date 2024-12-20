#pragma once
#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <windows.h>
#include <winternl.h>

class SandboxManager {
public:
    SandboxManager();
    ~SandboxManager();

    // Sandbox environment
    struct SandboxEnvironment {
        std::string name;
        std::string rootPath;
        bool networkEnabled;
        bool fileSystemEnabled;
        bool registryEnabled;
        std::vector<std::string> allowedAPIs;
    };

    // Execution control
    bool initializeSandbox(const std::string& name);
    bool executeFile(const std::string& filePath);
    void terminateSandbox();
    
    // Monitoring
    struct SandboxActivity {
        std::string type;
        std::string details;
        std::chrono::system_clock::time_point timestamp;
        bool wasBlocked;
    };
    
    std::vector<SandboxActivity> getActivities();
    void clearActivities();
    
    // Resource management
    void setMemoryLimit(size_t bytes);
    void setCPULimit(int percentage);
    void setTimeLimit(std::chrono::seconds duration);
    
    // Network control
    void enableNetwork(bool enable);
    void addAllowedHost(const std::string& host);
    void setNetworkRules(const std::vector<std::string>& rules);
    
    // File system
    void mountDirectory(const std::string& realPath, const std::string& sandboxPath);
    void addWritablePath(const std::string& path);
    void setFileSystemRules(const std::vector<std::string>& rules);
    
    // Registry
    void enableRegistry(bool enable);
    void addAllowedKey(const std::string& keyPath);
    void setRegistryRules(const std::vector<std::string>& rules);
    
private:
    // Internal state
    struct SandboxState {
        HANDLE processHandle;
        DWORD processId;
        bool isRunning;
        std::chrono::system_clock::time_point startTime;
        std::vector<SandboxActivity> activities;
    } state;
    
    // Resource limits
    struct ResourceLimits {
        size_t memoryBytes;
        int cpuPercentage;
        std::chrono::seconds timeLimit;
    } limits;
    
    // Security
    struct SecurityPolicy {
        bool networkEnabled;
        bool fileSystemEnabled;
        bool registryEnabled;
        std::vector<std::string> allowedHosts;
        std::vector<std::string> allowedPaths;
        std::vector<std::string> allowedKeys;
    } policy;
    
    // Virtualization
    struct VirtualizedResources {
        std::map<std::string, std::string> mountPoints;
        std::map<std::string, std::string> registryRedirects;
        std::vector<std::string> networkRules;
    } virtualization;
    
    // Helper functions
    bool createSandboxedProcess(const std::string& filePath);
    void monitorProcess();
    void enforceResourceLimits();
    bool isOperationAllowed(const std::string& operation, const std::string& target);
    void logActivity(const std::string& type, const std::string& details, bool blocked);
};
