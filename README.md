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
