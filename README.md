# Simple Antivirus

A lightweight antivirus program written in C++ for Windows systems. Detects malware and suspicious patterns through signature matching and behavioral analysis.

## Features

- File scanning with MD5 signature matching
- Real-time directory monitoring
- Suspicious pattern detection
- Process memory scanning
- Detailed threat reporting
- Command-line interface

## Dependencies

### Required
1. **C++ Compiler**
   - MinGW-w64 with GCC 8.1.0 or later (recommended)
   - Visual Studio 2019 or later
   - Must support C++17

2. **OpenSSL**
   ```bash
   # Using MSYS2/MinGW64
   pacman -S mingw-w64-x86_64-openssl
   ```

3. **Build Tools**
   ```bash
   # Using MSYS2/MinGW64
   pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja
   ```

### Optional
- **Google Test** (for unit testing)
   ```bash
   # Using MSYS2/MinGW64
   pacman -S mingw-w64-x86_64-gtest
   ```

## Building

1. **Clone the repository**
   ```bash
   git clone https://github.com/AffluentApex/crispy-dollop.git
   cd crispy-dollop
   ```

2. **Build using CMake**
   ```bash
   mkdir build
   cd build
   cmake ..
   cmake --build .
   ```

## Usage

Run the antivirus with administrator privileges:
```bash
./simple_av.exe
```

Available commands:
- `scan <path>` - Scan a file or directory
- `monitor <path>` - Start real-time monitoring
- `stats` - Show scan statistics
- `help` - Show available commands
- `clear` - Clear screen
- `exit` - Exit program

## Development

### Project Structure
```
simple_antivirus/
├── src/
│   ├── main.cpp            # Main program entry
│   ├── scanner.cpp/h       # File scanning engine
│   └── realtime_monitor.cpp/h  # Real-time monitoring
├── tests/
│   └── unit_tests/         # Unit test files
└── CMakeLists.txt         # Build configuration
```

### Running Tests
```bash
# In the build directory
./run_tests.exe
