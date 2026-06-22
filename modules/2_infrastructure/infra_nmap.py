import os
import subprocess
import tempfile


def parse_nmap_problems(scan_text):
    """Identifies 'Critical' findings in raw text output."""
    red_flags = ["vulnerable", "exploitable", "expired", "weak", "anonymous", "denial of service"]
    findings = []

    if not scan_text:
        return findings

    for line in scan_text.split("\n"):
        if any(flag in line.lower() for flag in red_flags):
            findings.append(line.strip())

    return findings


def run_nmap_scan(target_ip, flags):
    """
    Execute Nmap with guided flags and capture human-readable and XML output.
    Returns a dictionary with raw_output, xml_output, and findings.
    """
    if isinstance(flags, str):
        flags = [flags]

    xml_file = tempfile.NamedTemporaryFile(suffix=".xml", delete=False)
    xml_path = xml_file.name
    xml_file.close()

    command = ["nmap"] + flags + ["-oX", xml_path, target_ip]

    try:
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        scan_result = process.stdout
        problems = parse_nmap_problems(scan_result)

        xml_output = ""
        try:
            with open(xml_path, encoding="utf-8") as xml_handle:
                xml_output = xml_handle.read()
        except OSError:
            xml_output = ""

        return {
            "raw_output": scan_result,
            "xml_output": xml_output,
            "findings": problems,
        }

    except subprocess.CalledProcessError as error:
        return {
            "raw_output": f"Error executing Nmap: {error.stderr}",
            "xml_output": "",
            "findings": [],
        }
    except FileNotFoundError:
        return {
            "raw_output": "Error: Nmap is not installed or not in your PATH.",
            "xml_output": "",
            "findings": [],
        }
    finally:
        if os.path.exists(xml_path):
            os.unlink(xml_path)
