#include "scanner.h"
#include "realtime_monitor.h"
#include <iostream>
#include <string>
#include <chrono>
#include <iomanip>
#include <windows.h>

// Color codes for Windows console
void setColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void clearScreen() {
    system("cls");
}

void printBanner() {
    clearScreen();
    setColor(11);  // Cyan
    std::cout << R"(
   SimpleAV - Lightweight Antivirus
   ===============================
    )"<< std::endl;
    setColor(7);   // Reset color
}

void printHelp() {
    setColor(14);  // Yellow
    std::cout << "\nCommands:\n";
    setColor(7);   // Reset
    std::cout << "  scan <path>    : Scan file or directory\n"
              << "  monitor <path> : Start real-time protection\n"
              << "  stats         : Show statistics\n"
              << "  clear         : Clear screen\n"
              << "  help          : Show this help\n"
              << "  exit          : Exit program\n\n";
}

void printStats(const Scanner& scanner) {
    setColor(11);  // Cyan
    std::cout << "\nScan Results:\n";
    std::cout << "------------\n";
    setColor(7);   // Reset

    std::cout << "Files scanned : " << scanner.getTotalScanned() << "\n";
    
    if (scanner.getTotalThreats() > 0) {
        setColor(12);  // Red
        std::cout << "Threats found : " << scanner.getTotalThreats() << "\n\n";
        std::cout << "Infected Files:\n";
        for (const auto& file : scanner.getInfectedFiles()) {
            std::cout << "- " << file.filename().string() << "\n";
        }
    } else {
        setColor(10);  // Green
        std::cout << "Threats found : 0 (System Clean)\n";
    }
    setColor(7);  // Reset
    std::cout << std::endl;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    printBanner();
    printHelp();
    
    Scanner scanner;
    RealtimeMonitor monitor(scanner);
    std::string command, path;

    while (true) {
        setColor(10);  // Green
        std::cout << "> ";
        setColor(7);   // Reset
        std::cin >> command;

        if (command == "exit") {
            std::cout << "Shutting down...\n";
            break;
        }
        else if (command == "help") {
            printHelp();
        }
        else if (command == "clear") {
            printBanner();
            printHelp();
        }
        else if (command == "stats") {
            printStats(scanner);
        }
        else if (command == "scan") {
            std::cin >> path;
            setColor(14);  // Yellow
            std::cout << "\nScanning: " << path << "\n";
            
            auto start = std::chrono::high_resolution_clock::now();
            
            if (fs::is_directory(path)) {
                scanner.scanDirectory(path);
            } else {
                scanner.scanFile(path);
            }
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
            
            setColor(10);  // Green
            std::cout << "\nScan completed in " 
                     << std::fixed << std::setprecision(2) 
                     << duration.count() / 1000.0 << " seconds\n";
            
            printStats(scanner);
        }
        else if (command == "monitor") {
            std::cin >> path;
            if (!fs::is_directory(path)) {
                setColor(12);  // Red
                std::cout << "Error: Invalid directory path\n";
                setColor(7);   // Reset
                continue;
            }
            
            setColor(14);  // Yellow
            std::cout << "\nStarting real-time protection for: " << path << "\n";
            std::cout << "Press Enter to stop monitoring\n";
            
            monitor.start(path);
            std::string input;
            std::getline(std::cin, input);
            monitor.stop();
            
            setColor(10);  // Green
            std::cout << "Monitoring stopped\n";
            setColor(7);   // Reset
        }
        else {
            setColor(12);  // Red
            std::cout << "Unknown command. Type 'help' for available commands.\n";
            setColor(7);   // Reset
        }
    }

    return 0;
}
