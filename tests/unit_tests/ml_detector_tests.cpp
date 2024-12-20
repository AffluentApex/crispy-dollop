#include <gtest/gtest.h>
#include "../../src/ml_engine/ml_detector.h"
#include "../test_framework.h"

class MLDetectorTest : public ::testing::Test {
protected:
    MLDetector detector;
    std::string testDir = "C:/Users/Ronit/CascadeProjects/simple_antivirus/tests/samples/";

    void SetUp() override {
        // Create test samples
        createMalwareTrainingSet();
        createCleanTrainingSet();
    }

    void createMalwareTrainingSet() {
        // Create files with known malicious patterns
        std::vector<std::string> malwarePatterns = {
            "CreateRemoteThread|VirtualAllocEx|WriteProcessMemory",
            "powershell -enc|downloadstring|iex",
            "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "WScript.Shell|WSH|ActiveXObject"
        };

        for (size_t i = 0; i < malwarePatterns.size(); i++) {
            std::ofstream file(testDir + "malware_" + std::to_string(i) + ".txt");
            file << malwarePatterns[i];
        }
    }

    void createCleanTrainingSet() {
        // Create files with benign patterns
        std::vector<std::string> cleanPatterns = {
            "print('Hello World')",
            "SELECT * FROM users WHERE id = 1",
            "const app = express()",
            "<html><body>Welcome</body></html>"
        };

        for (size_t i = 0; i < cleanPatterns.size(); i++) {
            std::ofstream file(testDir + "clean_" + std::to_string(i) + ".txt");
            file << cleanPatterns[i];
        }
    }
};

TEST_F(MLDetectorTest, ExtractsFeatures) {
    auto features = detector.extractStaticFeatures(testDir + "malware_0.txt");
    EXPECT_FALSE(features.empty());
}

TEST_F(MLDetectorTest, PredictsMaliciousness) {
    auto features = detector.extractStaticFeatures(testDir + "malware_0.txt");
    float score = detector.predictMaliciousness(features);
    EXPECT_GT(score, 0.7f); // High maliciousness score expected
}

TEST_F(MLDetectorTest, IdentifiesCleanFiles) {
    auto features = detector.extractStaticFeatures(testDir + "clean_0.txt");
    float score = detector.predictMaliciousness(features);
    EXPECT_LT(score, 0.3f); // Low maliciousness score expected
}

TEST_F(MLDetectorTest, TrainsIncremental) {
    std::vector<std::pair<std::vector<float>, bool>> samples;
    
    // Add malware samples
    for (int i = 0; i < 4; i++) {
        auto features = detector.extractStaticFeatures(testDir + "malware_" + std::to_string(i) + ".txt");
        samples.push_back({features, true});
    }
    
    // Add clean samples
    for (int i = 0; i < 4; i++) {
        auto features = detector.extractStaticFeatures(testDir + "clean_" + std::to_string(i) + ".txt");
        samples.push_back({features, false});
    }
    
    detector.trainIncremental(samples);
    
    // Test prediction after training
    auto malwareFeatures = detector.extractStaticFeatures(testDir + "malware_0.txt");
    float malwareScore = detector.predictMaliciousness(malwareFeatures);
    EXPECT_GT(malwareScore, 0.7f);
    
    auto cleanFeatures = detector.extractStaticFeatures(testDir + "clean_0.txt");
    float cleanScore = detector.predictMaliciousness(cleanFeatures);
    EXPECT_LT(cleanScore, 0.3f);
}
