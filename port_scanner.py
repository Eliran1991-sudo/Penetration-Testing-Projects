import subprocess
import sys
from datetime import datetime

def scan(target):
    print(f"\nScanning target {target} at {datetime.now()}")
    try:
        result = subprocess.run(['nmap', '-sV', '-T4', target], capture_output=True, text=True)
        with open('scan_report.txt', 'w') as report:
            report.write(f"Nmap Scan Report for {target} ({datetime.now()}):\n")
            report.write(result.stdout)
        print(f"\nScan completed. Report saved to scan_report.txt.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <IP-Address>")
        sys.exit(1)
    
    scan(sys.argv[1])
