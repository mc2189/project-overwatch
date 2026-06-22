import subprocess
import os

def parse_nmap_problems(scan_text):
    """Identifies 'Critical' findings in raw text output."""
    red_flags = ["vulnerable", "exploitable", "expired", "weak", "anonymous", "denial of service"]
    findings = []
    
    if not scan_text:
        return findings

    # Split text into lines and check for flags
    for line in scan_text.split('\n'):
        if any(flag in line.lower() for flag in red_flags):
            findings.append(line.strip())
            
    return findings

def run_nmap_scan(target_ip, flags):
    """
    Executes Nmap using the subprocess module to allow for 
    complex flag stacking (e.g., -sV --script vuln).
    """
    # Ensure flags is a list; if it's a string, we wrap it
    if isinstance(flags, str):
        flags = [flags]
        
    # Construct the command: ['nmap', '-sV', '192.168.1.1']
    command = ["nmap"] + flags + [target_ip]
    
    try:
        # Run the command
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        scan_result = process.stdout
        
        # Run the automated problem identification
        problems = parse_nmap_problems(scan_result)
        
        return scan_result, problems
    
    except subprocess.CalledProcessError as e:
        return f"Error executing Nmap: {e.stderr}", []
    except FileNotFoundError:
        return "Error: Nmap is not installed or not in your PATH.", []

# Quick test if run directly
if __name__ == "__main__":
    # Test with a simple port scan
    output, issues = run_nmap_scan("8.8.8.8", ["-p", "53"])
    print(output)