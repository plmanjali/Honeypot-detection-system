import pandas as pd
import sqlite3
import random
import re
import json
import os
from datetime import datetime, timedelta

# Database connection
conn = sqlite3.connect('instance/honeypot.db')
cursor = conn.cursor()

# Sample YouTube comments data for demo purposes
# In a real scenario, you would load from the actual dataset file
SAMPLE_COMMENTS = [
    "I love this video! Great content as always.",
    "SELECT * FROM users WHERE username = 'admin' AND password = ''; DROP TABLE users;--",
    "Check out my page www.phishing-example.com/login?redirect=mypage",
    "This song is <script>alert('XSS Attack!');</script> awesome!",
    "I tried pwd; cat /etc/passwd to see if it works",
    "Anyone know how to hack Netflix? I want free premium",
    "rm -rf / would delete everything right?",
    "../../../../../../etc/shadow",
    "Has anyone tried a DDoS attack on this site?",
    "admin:admin123 credentials didn't work for me",
    "This video is trash unsubscribe now",
    "Hey guys, visit my website! Free gift cards www.totallylegit.com/free",
    "I want to inject some code into this page document.cookie",
    "' UNION SELECT username, password FROM users --",
    "I found a vulnerability in your website's login page",
    "My wifi keeps dropping when I run nmap -sS -p- 192.168.1.1",
    "This is a harmless comment about the video",
    "<img src=x onerror='javascript:alert(1)'>",
    "Let's test if system('ls -la') works here",
    "I'm trying to brute force the login but it's not working"
]

# Analyze comment to determine attack type and severity
def analyze_comment(comment):
    # Convert to lowercase for easier matching
    text = str(comment).lower()
    
    # Define patterns for different attack types
    patterns = {
        'SQL Injection': ['select ', 'union', 'insert', 'drop table', 'delete from', '--', '1=1', 'or 1=1'],
        'XSS Attack': ['<script>', 'javascript:', 'alert(', 'onerror=', '<img src=', 'document.cookie'],
        'Command Injection': ['system(', 'exec(', ';ls -la', '|cat', '/etc/passwd', 'rm -rf'],
        'Path Traversal': ['../../../', 'etc/shadow', 'wp-config.php', '.htaccess'],
        'Brute Force': ['password', 'admin', 'login failed', 'bruteforce', 'crack'],
        'DDoS': ['ddos', 'flood', 'attack', 'down'],
        'CSRF Attack': ['csrf', 'forged', 'request forgery'],
        'Phishing': ['click here', 'free', 'verify', 'login', 'www.']
    }
    
    # Check for matches
    matches = {}
    for attack_type, keywords in patterns.items():
        count = sum(1 for keyword in keywords if keyword in text)
        if count > 0:
            matches[attack_type] = count
    
    # If no matches, return random reconnaissance
    if not matches:
        return "Port Scan", "low"
    
    # Determine the attack type with the most matches
    attack_type = max(matches, key=matches.get)
    
    # Determine severity based on content and length
    if len(text) > 100 and matches[attack_type] >= 3:
        severity = "critical"
    elif len(text) > 50 and matches[attack_type] >= 2:
        severity = "high"
    elif matches[attack_type] >= 1:
        severity = "medium"
    else:
        severity = "low"
        
    return attack_type, severity

# Generate a random IP address
def random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

# Generate timestamp within the last 30 days
def random_date():
    now = datetime.now()
    days_ago = random.randint(0, 30)
    return now - timedelta(days=days_ago, 
                          hours=random.randint(0, 23), 
                          minutes=random.randint(0, 59),
                          seconds=random.randint(0, 59))

def main():
    try:
        print("Importing YouTube comments as attack data...")
        
        # Clear existing data (optional)
        cursor.execute("DELETE FROM attack_log")
        cursor.execute("DELETE FROM alert")
        conn.commit()
        
        # Process each comment
        for i, comment in enumerate(SAMPLE_COMMENTS):
            # Analyze comment to determine attack type and severity
            attack_type, severity = analyze_comment(comment)
            
            # Generate attack details
            timestamp = random_date().strftime('%Y-%m-%d %H:%M:%S')
            source_ip = random_ip()
            dest_ip = "192.168.1.101"  # Honeypot IP
            source_port = random.randint(1024, 65535)
            dest_port = random.choice([22, 23, 80, 443, 8080, 3306, 5432])  # Common ports
            protocol = random.choice(["TCP", "UDP", "HTTP", "HTTPS", "SSH"])
            
            # Use the comment as the payload
            payload = comment
            
            # Insert into AttackLog table
            cursor.execute('''
            INSERT INTO attack_log 
            (timestamp, source_ip, destination_ip, source_port, destination_port, 
             protocol, attack_type, severity, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, source_ip, dest_ip, source_port, dest_port, 
                  protocol, attack_type, severity, payload))
            
            # Also create alerts for high/critical attacks
            if severity in ["high", "critical"]:
                cursor.execute('''
                INSERT INTO alert
                (timestamp, title, message, severity, source_ip, attack_type, is_read)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (timestamp, f"{attack_type} detected", 
                      f"Potential {attack_type} attack from {source_ip}:{source_port}. Content analysis indicates malicious intent.",
                      severity, source_ip, attack_type, 0))  # 0 = unread
            
            print(f"Processed comment {i+1}: {attack_type} ({severity})")
        
        conn.commit()
        print(f"Successfully imported {len(SAMPLE_COMMENTS)} comments as attack data")
        
        # Get summary of imported data
        cursor.execute("SELECT COUNT(*) FROM attack_log")
        total_attacks = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alert")
        total_alerts = cursor.fetchone()[0]
        
        cursor.execute("SELECT attack_type, COUNT(*) FROM attack_log GROUP BY attack_type")
        attack_types = cursor.fetchall()
        
        cursor.execute("SELECT severity, COUNT(*) FROM attack_log GROUP BY severity")
        severities = cursor.fetchall()
        
        print(f"\nSummary of imported data:")
        print(f"Total attacks: {total_attacks}")
        print(f"Total alerts: {total_alerts}")
        print(f"Attack types:")
        for attack_type, count in attack_types:
            print(f"  - {attack_type}: {count}")
        print(f"Severities:")
        for severity, count in severities:
            print(f"  - {severity}: {count}")
        
    except Exception as e:
        print(f"Error importing data: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()