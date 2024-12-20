#pragma once
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <filesystem>
#include <chrono>
#include <windows.h>

namespace fs = std::filesystem;

enum class ThreatLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct ThreatInfo {
    std::string name;
    ThreatLevel level;
    std::string description;
    std::chrono::system_clock::time_point detectionTime;
};

class Scanner {
public:
    Scanner();
    
    // Add known malware signatures
    void addMalwareSignature(const std::string& signature);
    
    // Scan functions
    bool scanFile(const fs::path& filePath);
    void scanDirectory(const fs::path& dirPath);
    void scanMemory();  // New: Scan running processes
    void quarantineFile(const fs::path& filePath);  // New: Quarantine infected files
    
    // Whitelist functions
    void addToWhitelist(const std::string& hash);
    bool isWhitelisted(const std::string& hash);
    
    // Get scan statistics
    size_t getTotalScanned() const { return totalScanned; }
    size_t getTotalThreats() const { return totalThreats; }
    const std::vector<fs::path>& getInfectedFiles() const { return infectedFiles; }
    const std::vector<ThreatInfo>& getThreatHistory() const { return threatHistory; }

private:
    // Database of known malware signatures
    std::unordered_set<std::string> malwareSignatures;
    std::unordered_set<std::string> whitelist;
    
    // Statistics
    size_t totalScanned;
    size_t totalThreats;
    std::vector<fs::path> infectedFiles;
    std::vector<ThreatInfo> threatHistory;
    
    // Helper functions
    std::string calculateFileHash(const fs::path& filePath);
    bool checkFilePatterns(const fs::path& filePath);
    bool isFileInfected(const fs::path& filePath);
    bool checkProcessMemory(DWORD processId);
    void logThreat(const fs::path& filePath, const std::string& threatName, ThreatLevel level);
};
