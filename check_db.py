import sqlite3

# Connect to the database
conn = sqlite3.connect('instance/honeypot.db')
cursor = conn.cursor()

# Check attack logs
print("=" * 50)
print("ATTACK LOGS")
print("=" * 50)
cursor.execute("SELECT COUNT(*) FROM attack_log")
print(f"Total attacks: {cursor.fetchone()[0]}")

cursor.execute("SELECT attack_type, COUNT(*) FROM attack_log GROUP BY attack_type")
print("\nAttack types:")
for attack_type, count in cursor.fetchall():
    print(f"  - {attack_type}: {count}")

cursor.execute("SELECT severity, COUNT(*) FROM attack_log GROUP BY severity")
print("\nSeverities:")
for severity, count in cursor.fetchall():
    print(f"  - {severity}: {count}")

# Check alerts
print("\n" + "=" * 50)
print("ALERTS")
print("=" * 50)
cursor.execute("SELECT COUNT(*) FROM alert")
print(f"Total alerts: {cursor.fetchone()[0]}")

cursor.execute("""
SELECT id, timestamp, title, severity, source_ip, attack_type, is_read 
FROM alert 
ORDER BY timestamp DESC
LIMIT 5
""")
alerts = cursor.fetchall()
print("\nLatest alerts:")
for alert in alerts:
    print(f"  - {alert[0]}: {alert[2]} (Severity: {alert[3]}, Type: {alert[5]})")

# Close the connection
conn.close()