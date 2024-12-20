#pragma once
#include <vector>
#include <string>
#include <memory>
#include <tensorflow/core/public/session.h>
#include <torch/torch.h>

class MLDetector {
public:
    MLDetector();
    ~MLDetector();

    // Feature extraction
    std::vector<float> extractStaticFeatures(const std::string& filePath);
    std::vector<float> extractDynamicFeatures(const std::string& filePath);
    std::vector<float> extractBehavioralFeatures(const std::string& filePath);
    
    // Model operations
    bool loadModel(const std::string& modelPath);
    bool updateModel(const std::string& newModelPath);
    void trainIncremental(const std::vector<std::pair<std::vector<float>, bool>>& samples);
    
    // Detection
    float predictMaliciousness(const std::vector<float>& features);
    std::pair<bool, float> analyzeFile(const std::string& filePath);
    
    // Advanced analysis
    std::vector<std::string> explainDecision(const std::vector<float>& features);
    void adjustThresholds(float falsePositiveRate);
    
private:
    // ML Models
    std::unique_ptr<tensorflow::Session> tfSession;
    torch::jit::Module torchModule;
    
    // Feature extraction
    std::vector<float> extractPEFeatures(const std::string& filePath);
    std::vector<float> extractAPIFeatures(const std::string& filePath);
    std::vector<float> extractStringFeatures(const std::string& filePath);
    
    // Model parameters
    float detectionThreshold;
    std::vector<std::string> featureNames;
    
    // Preprocessing
    std::vector<float> normalizeFeatures(const std::vector<float>& features);
    std::vector<float> selectTopFeatures(const std::vector<float>& features);
    
    // Performance tracking
    struct ModelMetrics {
        float accuracy;
        float precision;
        float recall;
        float f1Score;
        float falsePositiveRate;
    } metrics;
    
    void updateMetrics(const std::vector<std::pair<bool, bool>>& predictions);
};
