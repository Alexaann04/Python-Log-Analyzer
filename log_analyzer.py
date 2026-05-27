import pandas as pd
import numpy as np
import re

print("\n========== CYBERSECURITY LOG ANALYZER ==========\n")

# -----------------------------------
# STEP 1 — READ LOG FILE
# -----------------------------------

log_file = "sample_logs.txt"

with open(log_file, "r") as file:
    logs = file.readlines()

print("[+] Log file loaded successfully.")

# -----------------------------------
# STEP 2 — PARSE LOGS USING REGEX
# -----------------------------------

data = []

pattern = r'(\S+ \S+) (\S+) user=(\S+) ip=(\S+) country=(\S+)'

for log in logs:

    match = re.search(pattern, log)

    if match:

        timestamp = match.group(1)
        action = match.group(2)
        user = match.group(3)
        ip = match.group(4)
        country = match.group(5)

        data.append([
            timestamp,
            action,
            user,
            ip,
            country
        ])

print("[+] Logs parsed successfully.")

# -----------------------------------
# STEP 3 — CREATE DATAFRAME
# -----------------------------------

df = pd.DataFrame(
    data,
    columns=[
        "timestamp",
        "action",
        "user",
        "ip",
        "country"
    ]
)

print("\n========== PARSED LOGS ==========\n")
print(df)

# -----------------------------------
# STEP 4 — FILTER FAILED LOGINS
# -----------------------------------

failed_df = df[df["action"] == "LOGIN_FAILED"]

print("\n========== FAILED LOGINS ==========\n")
print(failed_df)

# -----------------------------------
# STEP 5 — COUNT FAILED ATTEMPTS
# -----------------------------------

attack_counts = failed_df["ip"].value_counts()

print("\n========== FAILED LOGIN COUNTS ==========\n")
print(attack_counts)

# -----------------------------------
# STEP 6 — STATISTICAL ANALYSIS
# -----------------------------------

mean = attack_counts.mean()
std = attack_counts.std()

print("\n========== STATISTICAL ANALYSIS ==========\n")

print(f"Mean Failed Attempts: {mean}")
print(f"Standard Deviation: {std}")

# -----------------------------------
# STEP 7 — Z-SCORE DETECTION
# -----------------------------------

suspicious = []

print("\n========== Z-SCORE ANALYSIS ==========\n")

for ip, count in attack_counts.items():

    # Avoid divide-by-zero error
    if std != 0:
        z_score = (count - mean) / std
    else:
        z_score = 0

    print(f"IP Address      : {ip}")
    print(f"Failed Attempts : {count}")
    print(f"Z-Score         : {round(z_score, 2)}")
    print("-----------------------------------")

    # LOWERED THRESHOLD FOR TESTING
    if z_score >= 0:

        suspicious.append({
            "ip": ip,
            "failed_attempts": count,
            "z_score": round(z_score, 2)
        })

# -----------------------------------
# STEP 8 — CREATE SUSPICIOUS DATAFRAME
# -----------------------------------

suspicious_df = pd.DataFrame(suspicious)

print("\n========== SUSPICIOUS ACTIVITY ==========\n")
print(suspicious_df)

# -----------------------------------
# STEP 9 — EXPORT CSV
# -----------------------------------

output_file = "suspicious_activity.csv"

suspicious_df.to_csv(
    output_file,
    index=False
)

print("\n[+] Suspicious activity exported successfully.")
print(f"[+] File saved as: {output_file}")

print("\n========== ANALYSIS COMPLETED ==========\n")