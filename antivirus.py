import hashlib
import os
import json
import sys
from datetime import datetime

class SimpleAntivirus:
    def __init__(self):
        self.signatures_file = "virus_signatures.json"
        self.signatures = self.load_signatures()
        
    def load_signatures(self):
        """Load virus signatures from JSON file."""
        try:
            with open(self.signatures_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Return default empty signatures if file doesn't exist
            return {
                "signatures": {
                    "malware1": "e9d71f5ee7c92d6dc9e92ffdad17b8bd49418f98",
                    "malware2": "84d5f7bb18b1b2c8b021647bb1c1f4b4c2f9853a"
                }
            }

    def calculate_file_hash(self, filepath):
        """Calculate SHA-1 hash of a file."""
        sha1 = hashlib.sha1()
        try:
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(65536)  # Read in 64kb chunks
                    if not data:
                        break
                    sha1.update(data)
            return sha1.hexdigest()
        except Exception as e:
            print(f"Error reading file {filepath}: {str(e)}")
            return None

    def scan_file(self, filepath):
        """Scan a single file for virus signatures."""
        if not os.path.exists(filepath):
            return f"File not found: {filepath}"
        
        file_hash = self.calculate_file_hash(filepath)
        if not file_hash:
            return f"Could not scan file: {filepath}"

        # Check if file hash matches any known virus signatures
        for virus_name, virus_hash in self.signatures["signatures"].items():
            if file_hash == virus_hash:
                return f"THREAT DETECTED! File {filepath} matches signature of {virus_name}"
        
        return f"File is clean: {filepath}"

    def scan_directory(self, directory):
        """Recursively scan a directory for virus signatures."""
        if not os.path.exists(directory):
            return f"Directory not found: {directory}"

        results = []
        for root, _, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                results.append(self.scan_file(filepath))
        return results

def print_help():
    """Print help message with available commands."""
    print("""
Simple Antivirus - Command Line Interface
Available commands:
    scan <file/directory>  : Scan a specific file or directory
    report                 : Show the last scan report
    help                   : Show this help message
    exit                   : Exit the program
    """)

def main():
    antivirus = SimpleAntivirus()
    print("Simple Antivirus Started")
    print_help()

    while True:
        try:
            command = input("\nEnter command: ").strip().split()
            
            if not command:
                continue

            if command[0] == "exit":
                print("Exiting...")
                break
            
            elif command[0] == "help":
                print_help()
            
            elif command[0] == "scan":
                if len(command) < 2:
                    print("Please specify a file or directory to scan")
                    continue
                
                target = " ".join(command[1:])
                if os.path.isfile(target):
                    result = antivirus.scan_file(target)
                    print(result)
                elif os.path.isdir(target):
                    results = antivirus.scan_directory(target)
                    print("\nScan Results:")
                    for result in results:
                        print(result)
                else:
                    print(f"Invalid path: {target}")
            
            else:
                print(f"Unknown command: {command[0]}")
                print_help()

        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {str(e)}")

if __name__ == "__main__":
    main()
