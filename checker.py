import csv
import ipaddress
from datetime import datetime


def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def check_gateway(ip, mask, gateway):
    try:
        network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        return ipaddress.ip_address(gateway) in network
    except ValueError:
        return False


def check_case(case):
    findings = []

    ip = case["ip"]
    mask = case["mask"]
    gateway = case["gateway"]
    interface = case["interface"]

    # Check IP address
    if valid_ip(ip):
        findings.append("IP address is valid.")
    else:
        findings.append("Invalid IP address.")

    # Check gateway
    if check_gateway(ip, mask, gateway):
        findings.append("Gateway is in the correct network.")
    else:
        findings.append("Gateway does not match the network.")

    # Check interface
    if interface.lower() == "up":
        findings.append("Interface is UP.")
    else:
        findings.append("Interface is DOWN.")

    return findings


print("========================================")
print("       NetSage AI Network Diagnostic")
print("========================================")

with open("cases.csv", "r") as file:
    reader = csv.DictReader(file)

    with open("logs/diagnostic_log.txt", "a") as log_file:

        log_file.write("\n========================================\n")
        log_file.write(
            f"Diagnostic Run: {datetime.now()}\n"
        )
        log_file.write("========================================\n")

        for case in reader:

            print(f"\nCase {case['case_id']}")
            print(f"Issue: {case['issue']}")

            log_file.write(f"\nCase {case['case_id']}\n")
            log_file.write(f"Issue: {case['issue']}\n")

            results = check_case(case)

            for result in results:
                print("-", result)
                log_file.write(f"- {result}\n")

            print("----------------------------------------")
            log_file.write("----------------------------------------\n")

print("\nDiagnostic results saved to logs/diagnostic_log.txt")