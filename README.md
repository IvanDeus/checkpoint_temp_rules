# 🔍 Check Point Temporary Rule Finder

A Python script to help identify **temporary access rules** in your Check Point firewall policy that are set to expire within a specified time window. This is especially useful for security teams or administrators who need to audit, track, or clean up temporary rules before they expire or cause unnecessary risk.

You can run this script in interactive mode or from a task scheduler.

## 📄 Script: `cp_find_temp_rules.py`

### ✅ Purpose:
This script connects to a **Check Point R8x management server**, retrieves **time objects** used in access rules, and identifies **access rules** tied to those time objects that will expire within a defined number of days (default is 31 days).

It outputs:
- A list of matching rules to the console
- A CSV file (`Temp-rules.csv`) with rule details
- A log file (`find_temp_rules.log`) for debugging and auditing

---

## ⚙️ Features

- Connects to Check Point Management via API
- Identifies access rules using time-based restrictions
- Filters rules based on future expiration (configurable)
- Outputs results to both screen and CSV
- Logs all activity for troubleshooting
- Supports read-only login for safe operation

---

## 🛠 Requirements

Before running this script, ensure you have:

- **Python 3.x**
- The `cpapi` library installed (part of the Check Point SDK)
- Proper permissions on the Check Point management server
- Network connectivity to the management server

Install dependencies if needed:
```bash
pip install cpapi
```

---

## ⚙️ Usage Example

### Command Line:
```bash
python cp_find_temp_rules.py -s <server_ip> [-u <username>] [-p <password>] [-d <days_in_future>]
```

### Example:
```bash
python cp_find_temp_rules.py -s 192.168.1.10 -u admin -p securepass -d 14
```

Where:
- `-s` or `--server`: IP address of the Check Point Management Server (required)
- `-u` or `--username`: Username (defaults to `Admin`)
- `-p` or `--password`: Password (will prompt securely if not provided)
- `-d` or `--days_in_future`: Number of days to look ahead for expiring rules (default: 31)

---

## 📁 Output Files

### 1. `Temp-rules.csv`
A comma-separated values file containing:
| Position | Rule Name | Time Objects | Comment | Package Name |
|----------|-----------|--------------|---------|---------------|

Example:
```
Rule 1 ; Temp_Access ; temp_rule_time ; Temporary access for dev team ; Security_Policy
```

### 2. `find_temp_rules.log`
Logs all script actions and API interactions for review and troubleshooting.

---

## 🧾 What the Script Does:

1. Logs into the Check Point Management Server in **read-only mode**.
2. Retrieves all **time objects** defined in the system.
3. Determines which time objects fall within the configured expiration window.
4. For each relevant time object, finds all associated **access rules**.
5. Gathers rule comments, package name, and other metadata.
6. Writes the output to the console and a CSV file.
7. Logs out and closes files safely.

---

## 🛡️ Security Notes

- The script uses **secure password input** (doesn't echo to the terminal).
- It logs in with **read-only access** by default to prevent accidental changes.
- All API communication is logged for audit purposes.

---

## 🧩 Customization Tips

- Modify the script to export data to Excel or JSON instead of CSV.
- Add filters to exclude specific packages or layers.
- Integrate with email or ticketing systems to notify owners of upcoming rule expirations.

---

[ivan deus] 
