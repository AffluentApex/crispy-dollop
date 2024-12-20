# Simple Antivirus

A basic command-line antivirus program that implements signature-based detection for identifying known threats.

## Features

- Signature-based virus detection
- File and directory scanning
- Command-line interface
- Basic reporting functionality

## Usage

Run the program:
```
python antivirus.py
```

Available commands:
- `scan <file/directory>`: Scan a specific file or directory for threats
- `report`: Show the last scan report
- `help`: Display help message
- `exit`: Exit the program

## How it Works

1. The program maintains a database of known virus signatures (SHA-1 hashes)
2. When scanning, it calculates the hash of each file
3. If a file's hash matches any known virus signature, it's flagged as infected
4. Results are displayed in the command line interface

## Technical Details

- Written in Python 3
- Uses SHA-1 hashing for signature comparison
- No external dependencies required
- Stores virus signatures in JSON format

## Dependencies

### Required Dependencies
1. **OpenSSL**
   ```bash
   # Using MSYS2/MinGW64
   pacman -S mingw-w64-x86_64-openssl
   ```

2. **C++ Compiler**
   - MinGW-w64 with GCC 8.1.0 or later
   - Visual Studio 2019 or later with C++17 support

3. **Build Tools**
   ```bash
   # Using MSYS2/MinGW64
   pacman -S mingw-w64-x86_64-cmake mingw-w64-x86_64-ninja
   ```

### Optional Dependencies
1. **Google Test** (for running tests)
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

3. **Run the antivirus**
   ```bash
   ./simple_av.exe
   ```

## Running Tests
```bash
# In the build directory
./run_tests.exe
```
