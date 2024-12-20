#include "scanner.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/md5.h>
#include <algorithm>

Scanner::Scanner() : totalScanned(0), totalThreats(0) {
    // Add some example malware signatures (MD5 hashes)
    addMalwareSignature("44d88612fea8a8f36de82e1278abb02f"); // Example malware signature
    addMalwareSignature("b026324c6904b2a9cb4b88d6d61c81d1"); // Example malware signature
}

void Scanner::addMalwareSignature(const std::string& signature) {
    malwareSignatures.insert(signature);
}

bool Scanner::scanFile(const fs::path& filePath) {
    try {
        if (!fs::exists(filePath) || !fs::is_regular_file(filePath)) {
            return false;
        }

        totalScanned++;
        
        if (isFileInfected(filePath)) {
            totalThreats++;
            infectedFiles.push_back(filePath);
            std::cout << "\033[31m[THREAT DETECTED]\033[0m " << filePath << std::endl;
            return true;
        }
        
        return false;
    }
    catch (const std::exception& e) {
        std::cerr << "Error scanning file " << filePath << ": " << e.what() << std::endl;
        return false;
    }
}

void Scanner::scanDirectory(const fs::path& dirPath) {
    try {
        for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
            if (fs::is_regular_file(entry)) {
                scanFile(entry.path());
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error scanning directory " << dirPath << ": " << e.what() << std::endl;
    }
}

std::string Scanner::calculateFileHash(const fs::path& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return "";
    }

    MD5_CTX md5Context;
    MD5_Init(&md5Context);

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        MD5_Update(&md5Context, buffer, file.gcount());
    }
    
    unsigned char result[MD5_DIGEST_LENGTH];
    MD5_Final(result, &md5Context);

    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(result[i]);
    }

    return ss.str();
}

bool Scanner::checkFilePatterns(const fs::path& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return false;
    }

    // Read file content
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    std::string lowerContent = content;
    std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);

    // Suspicious patterns
    std::vector<std::pair<std::string, std::string>> patterns = {
        // EICAR test virus signature
        {"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "EICAR Test Signature"},
        
        // Suspicious Windows API calls
        {"createremotethread", "Process Injection Attempt"},
        {"virtualalloc", "Suspicious Memory Allocation"},
        {"writeprocessmemory", "Process Memory Modification"},
        {"openprocess", "Process Access Attempt"},
        
        // Suspicious PowerShell patterns
        {"powershell", "PowerShell Command"},
        {"-enc", "Encoded PowerShell"},
        {"-nop", "PowerShell No Profile"},
        {"-w hidden", "Hidden Window"},
        {"iex", "PowerShell Invoke Expression"},
        {"downloadstring", "Network Download Attempt"},
        
        // Suspicious registry operations
        {"software\\microsoft\\windows\\currentversion\\run", "Registry Autorun"},
        {"hkey_local_machine", "Registry System Modification"},
        
        // File system operations
        {"deletefile", "File Deletion Attempt"},
        {"wscript.shell", "Script Shell Access"},
        {"scripting.filesystemobject", "File System Access"},
        
        // Network operations
        {"http://", "Network Access"},
        {"https://", "Network Access"},
        {"webclient", "Network Client Access"},
        
        // Common malware patterns
        {"cmd.exe", "Command Shell Access"},
        {".downloadstring(", "Network Download"},
        {"hidden", "Hidden Process/Window"},
        {"system32", "System Directory Access"},
        {"page_execute", "Executable Memory"},
        {"mem_commit", "Memory Allocation"}
    };

    // Check each pattern
    for (const auto& pattern : patterns) {
        if (lowerContent.find(pattern.first) != std::string::npos) {
            std::cout << "\033[31m[DETECTED]\033[0m " << pattern.second << " in " << filePath.filename().string() << std::endl;
            return true;
        }
    }

    // Check file extension for suspicious types
    std::string ext = filePath.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    std::vector<std::string> suspiciousExts = {
        ".exe", ".dll", ".bat", ".cmd", ".vbs", 
        ".ps1", ".js", ".reg", ".scr", ".hta"
    };

    for (const auto& suspExt : suspiciousExts) {
        if (ext == suspExt) {
            // For executable files, do additional checks
            if (content.find("MZ") == 0 || content.find("ZM") == 0) {
                std::cout << "\033[33m[WARNING]\033[0m Executable file detected: " << filePath.filename().string() << std::endl;
                return true;
            }
        }
    }

    return false;
}

bool Scanner::isFileInfected(const fs::path& filePath) {
    // Check file hash against known malware signatures
    std::string fileHash = calculateFileHash(filePath);
    if (!fileHash.empty() && malwareSignatures.find(fileHash) != malwareSignatures.end()) {
        return true;
    }

    // Check for suspicious patterns
    return checkFilePatterns(filePath);
}
