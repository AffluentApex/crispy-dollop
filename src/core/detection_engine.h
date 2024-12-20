#pragma once
#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <unordered_map>
#include <thread>
#include <mutex>

namespace fs = std::filesystem;

// Forward declarations
class SandboxEnvironment;
class HeuristicAnalyzer;
class MLModel;
class PatternMatcher;

struct ThreatInfo {
    enum class ThreatType {
        MALWARE,
        SUSPICIOUS_BEHAVIOR,
        NETWORK_THREAT,
        REGISTRY_THREAT,
        MEMORY_THREAT,
        UNKNOWN
    };

    std::string name;
    ThreatType type;
    double confidence;
    std::string description;
    fs::path location;
    std::chrono::system_clock::time_point detectionTime;
};

class DetectionEngine {
public:
    DetectionEngine();
    ~DetectionEngine();

    // Core scanning functions
    bool scanFile(const fs::path& path, ThreatInfo& threatInfo);
    bool scanMemory(uint32_t processId, ThreatInfo& threatInfo);
    bool scanRegistry(const std::string& keyPath, ThreatInfo& threatInfo);
    bool scanNetwork(const std::vector<uint8_t>& packet, ThreatInfo& threatInfo);

    // Configuration
    void setHeuristicLevel(int level);
    void enableMachineLearning(bool enable);
    void setSandboxTimeout(std::chrono::seconds timeout);
    void updateSignatures(const std::string& signaturePath);

    // Statistics and reporting
    size_t getTotalScanned() const;
    size_t getTotalThreats() const;
    const std::vector<ThreatInfo>& getThreatHistory() const;
    void generateReport(const fs::path& outputPath) const;

private:
    // Detection components
    std::unique_ptr<SandboxEnvironment> sandbox;
    std::unique_ptr<HeuristicAnalyzer> heuristics;
    std::unique_ptr<MLModel> mlModel;
    std::unique_ptr<PatternMatcher> patterns;

    // Signature database
    struct Signature {
        std::string hash;
        std::string name;
        ThreatInfo::ThreatType type;
        std::vector<uint8_t> pattern;
    };
    std::unordered_map<std::string, Signature> signatures;

    // Statistics
    size_t totalScanned;
    size_t totalThreats;
    std::vector<ThreatInfo> threatHistory;
    
    // Thread safety
    mutable std::mutex mutex;

    // Helper functions
    bool runSandboxAnalysis(const fs::path& path);
    double calculateThreatScore(const fs::path& path);
    bool matchSignatures(const std::vector<uint8_t>& data);
    void updateThreatHistory(const ThreatInfo& threat);
};
