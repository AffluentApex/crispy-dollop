#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include "scanner.h"

class RealtimeMonitor {
public:
    RealtimeMonitor(Scanner& scanner);
    ~RealtimeMonitor();

    // Start monitoring
    void start(const std::string& directoryToWatch);
    
    // Stop monitoring
    void stop();

private:
    Scanner& scanner;
    std::atomic<bool> running;
    std::thread monitorThread;
    
    // Monitor function that runs in a separate thread
    void monitorDirectory(const std::string& directory);
    
    // Process file changes
    void handleFileChange(const std::string& filePath);
};
