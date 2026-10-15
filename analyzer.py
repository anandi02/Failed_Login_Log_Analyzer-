
from collections import Counter
from pathlib import Path

LOG_FILE = Path(__file__).with_name("login.log")
REPORT_FILE = Path(__file__).with_name("login_report.txt")

# Flag an IP when it has at least 3 failed login attempts.
THRESHOLD = 3


def analyze_logs():
    failed_ips = Counter()
    successful = 0
    failed_total = 0
    invalid_lines = 0

    if not LOG_FILE.exists():
        print("Error: login.log was not found.")
        return

    
    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:

            # Skip blank lines
            if not line.strip():
                continue

            parts = line.strip().split()

            if len(parts) < 5:
                print("Malformed line:", repr(line))
                invalid_lines += 1
                continue



            if len(parts) < 5:
                invalid_lines += 1
                continue

            status = parts[2]

            # Find the IP field, such as ip=203.0.113.15
            ip_field = next(
                (item for item in parts if item.startswith("ip=")),
                None
            )

            if ip_field is None:
                invalid_lines += 1
                continue

            ip_address = ip_field.split("=", 1)[1]

            if status == "FAILED":
                failed_ips[ip_address] += 1
                failed_total += 1
            elif status == "SUCCESS":
                successful += 1
            else:
                invalid_lines += 1

    report = []
    report.append("===== FAILED LOGIN ANALYSIS =====")
    report.append(f"Total failed logins: {failed_total}")
    report.append(f"Total successful logins: {successful}")
    report.append(f"Invalid or unrecognized lines: {invalid_lines}")
    report.append("\nFailed attempts by IP:")

    if not failed_ips:
        report.append("No failed login attempts found.")

    for ip, count in failed_ips.most_common():
        report.append(f"{ip}: {count} failed attempts")

    report.append("\nIPs flagged for repeated failures:")

    flagged = [
        (ip, count)
        for ip, count in failed_ips.most_common()
        if count >= THRESHOLD
    ]

    if flagged:
        for ip, count in flagged:
            report.append(
                f"REVIEW: {ip} had {count} failed login attempts."
            )
    else:
        report.append("No IPs reached the configured threshold.")

    report.append(
        "\nNote: Repeated failures are suspicious indicators, "
        "not proof of an attack."
    )

    output = "\n".join(report)

    print("\n" + output)

    REPORT_FILE.write_text(output, encoding="utf-8")
    print(f"\nReport saved to: {REPORT_FILE}")


if __name__ == "__main__":
    analyze_logs()
