#include "realtime_monitor.h"
#include <iostream>
#include <chrono>
#include <thread>
#include <windows.h>

RealtimeMonitor::RealtimeMonitor(Scanner& s) : scanner(s), running(false) {}

RealtimeMonitor::~RealtimeMonitor() {
    stop();
}

void RealtimeMonitor::start(const std::string& directoryToWatch) {
    if (running) {
        return;
    }

    running = true;
    monitorThread = std::thread(&RealtimeMonitor::monitorDirectory, this, directoryToWatch);
}

void RealtimeMonitor::stop() {
    running = false;
    if (monitorThread.joinable()) {
        monitorThread.join();
    }
}

void RealtimeMonitor::monitorDirectory(const std::string& directory) {
    HANDLE hDir = CreateFileA(
        directory.c_str(),
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        std::cerr << "Error monitoring directory: " << GetLastError() << std::endl;
        return;
    }

    char buffer[4096];
    DWORD bytesReturned;
    OVERLAPPED overlapped = {0};
    overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

    while (running) {
        if (ReadDirectoryChangesW(
            hDir,
            buffer,
            sizeof(buffer),
            TRUE,
            FILE_NOTIFY_CHANGE_FILE_NAME |
            FILE_NOTIFY_CHANGE_DIR_NAME |
            FILE_NOTIFY_CHANGE_LAST_WRITE,
            &bytesReturned,
            &overlapped,
            NULL))
        {
            WaitForSingleObject(overlapped.hEvent, INFINITE);

            FILE_NOTIFY_INFORMATION* event = (FILE_NOTIFY_INFORMATION*)buffer;
            do {
                std::wstring fileName(event->FileName, event->FileNameLength / sizeof(WCHAR));
                std::string filePath = directory + "\\" + std::string(fileName.begin(), fileName.end());
                
                handleFileChange(filePath);

                if (event->NextEntryOffset == 0) {
                    break;
                }
                event = (FILE_NOTIFY_INFORMATION*)((BYTE*)event + event->NextEntryOffset);
            } while (true);

            ResetEvent(overlapped.hEvent);
        }
    }

    CloseHandle(overlapped.hEvent);
    CloseHandle(hDir);
}

void RealtimeMonitor::handleFileChange(const std::string& filePath) {
    // Add a small delay to ensure the file is fully written
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    if (scanner.scanFile(filePath)) {
        std::cout << "\033[33m[ALERT]\033[0m Suspicious activity detected in: " << filePath << std::endl;
    }
}
