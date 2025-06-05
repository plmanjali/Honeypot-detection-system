import sqlite3
import json
from datetime import datetime, timedelta

# Connect to the database
conn = sqlite3.connect('instance/honeypot.db')
cursor = conn.cursor()

# Generate a report for the past 30 days
now = datetime.now()
start_date = (now - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')
end_date = now.strftime('%Y-%m-%d %H:%M:%S')

# Get attack counts by type
cursor.execute("""
SELECT attack_type, COUNT(*) as count 
FROM attack_log 
WHERE timestamp BETWEEN ? AND ? 
GROUP BY attack_type 
ORDER BY count DESC
""", (start_date, end_date))
attack_types = cursor.fetchall()

# Get attack counts by source IP
cursor.execute("""
SELECT source_ip, COUNT(*) as count 
FROM attack_log 
WHERE timestamp BETWEEN ? AND ? 
GROUP BY source_ip 
ORDER BY count DESC 
LIMIT 5
""", (start_date, end_date))
source_ips = cursor.fetchall()

# Get attack count
cursor.execute("SELECT COUNT(*) FROM attack_log WHERE timestamp BETWEEN ? AND ?", (start_date, end_date))
attack_count = cursor.fetchone()[0]

# Create a summary
summary = f"This report covers the period from {start_date} to {end_date}. "
summary += f"Total of {attack_count} attacks were detected. "
summary += f"Most common attack type was {attack_types[0][0]} with {attack_types[0][1]} occurrences. "
summary += f"Most active source IP was {source_ips[0][0]} with {source_ips[0][1]} attacks."

# Serialize the top attack types and source IPs for storage
top_attack_types_json = json.dumps(dict(attack_types))
top_source_ips_json = json.dumps(dict(source_ips))

# Generate a report title
title = f"Security Report - {datetime.now().strftime('%Y-%m-%d')}"

# Insert the report into the database
cursor.execute("""
INSERT INTO report 
(title, created_at, report_type, start_date, end_date, summary, attack_count, top_attack_types, top_source_ips)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
""", (title, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'monthly', start_date, end_date, 
      summary, attack_count, top_attack_types_json, top_source_ips_json))

report_id = cursor.lastrowid
conn.commit()

# Get the report back to confirm it was created
cursor.execute("SELECT * FROM report WHERE id = ?", (report_id,))
report = cursor.fetchone()

print(f"Generated report with ID: {report_id}")
print(f"Title: {title}")
print(f"Summary: {summary}")
print(f"Time period: {start_date} to {end_date}")
print(f"Attack count: {attack_count}")
print("\nTop attack types:")
for attack_type, count in attack_types:
    print(f"  - {attack_type}: {count}")
print("\nTop source IPs:")
for ip, count in source_ips:
    print(f"  - {ip}: {count}")

conn.close()