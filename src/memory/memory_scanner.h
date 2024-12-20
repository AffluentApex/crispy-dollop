#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <tlhelp32.h>

struct ProcessInfo {
    DWORD processId;
    std::string name;
    std::string path;
    std::vector<std::string> modules;
    bool isProtected;
    bool isSuspicious;
};

struct MemoryRegion {
    void* baseAddress;
    size_t size;
    DWORD protection;
    bool isSuspicious;
    std::string suspiciousReason;
};

class MemoryScanner {
public:
    MemoryScanner();
    ~MemoryScanner();

    // Process scanning
    bool scanProcess(DWORD processId);
    bool scanAllProcesses();
    bool protectProcess(DWORD processId);

    // Memory analysis
    std::vector<MemoryRegion> findSuspiciousRegions(DWORD processId);
    bool detectCodeInjection(DWORD processId);
    bool detectHooks(DWORD processId);
    bool detectHiddenThreads(DWORD processId);

    // DLL monitoring
    bool monitorDllLoads(DWORD processId);
    bool validateDllSignature(const std::string& dllPath);
    std::vector<std::string> getLoadedModules(DWORD processId);

    // Process protection
    bool preventDllInjection(DWORD processId);
    bool preventThreadInjection(DWORD processId);
    bool preventCodeModification(DWORD processId);

    // Memory patterns
    bool findShellcode(DWORD processId);
    bool detectHeapSpray(DWORD processId);
    bool detectStackPivot(DWORD processId);

    // Reporting
    std::vector<ProcessInfo> getProcessList();
    ProcessInfo getProcessInfo(DWORD processId);
    std::vector<MemoryRegion> getMemoryMap(DWORD processId);

private:
    // Internal helpers
    bool isProcessValid(HANDLE process);
    bool isAddressReadable(HANDLE process, void* address);
    bool isCodeSection(const MEMORY_BASIC_INFORMATION& mbi);
    
    // Pattern matching
    bool matchPattern(const std::vector<uint8_t>& memory, const std::vector<uint8_t>& pattern);
    std::vector<void*> findPattern(HANDLE process, const std::vector<uint8_t>& pattern);

    // Process monitoring
    std::unordered_map<DWORD, ProcessInfo> monitoredProcesses;
    std::vector<HANDLE> protectedProcesses;

    // Hook detection
    struct HookInfo {
        void* originalAddress;
        void* currentAddress;
        std::string functionName;
        bool isModified;
    };
    std::unordered_map<std::string, std::vector<HookInfo>> hookDatabase;

    // Thread monitoring
    struct ThreadInfo {
        DWORD threadId;
        void* startAddress;
        bool isSuspicious;
    };
    std::unordered_map<DWORD, std::vector<ThreadInfo>> threadDatabase;
};
