# How to Import YouTube Comments as Attack Data

This guide explains how to import YouTube comments dataset from Kaggle and transform them into simulated attack data for the Honeypot Detection System.

## Step 1: Download the Dataset

1. Download the YouTube comments dataset from Kaggle:
   https://www.kaggle.com/datasets/atifaliak/youtube-comments-dataset

2. Extract the CSV file to your project folder

## Step 2: Import Using Python Script

The system includes two Python scripts for importing data:

1. `import_youtube_comments.py` - Uses a pre-loaded set of sample comments for quick testing
2. For the full Kaggle dataset, you would modify the script as shown below

### For the Full Kaggle Dataset

```python
import pandas as pd
import sqlite3
import random
from datetime import datetime, timedelta

# Database connection
conn = sqlite3.connect('instance/honeypot.db')
cursor = conn.cursor()

# Path to your YouTube comments dataset
DATASET_PATH = 'your_dataset_filename.csv'  # Update this to your CSV file path

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
        print("Loading YouTube comments dataset...")
        df = pd.read_csv(DATASET_PATH)
        
        # Clear existing data (optional)
        cursor.execute("DELETE FROM attack_log")
        cursor.execute("DELETE FROM alert")
        conn.commit()
        
        # Limit to prevent overwhelming the database
        max_records = min(1000, len(df))
        
        print(f"Processing {max_records} comments...")
        for i, row in df.head(max_records).iterrows():
            # Get comment text - adjust column name based on your dataset
            comment = row.get('Comment', row.get('comment', row.get('text', '')))
            
            # Skip empty comments
            if not isinstance(comment, str) or not comment.strip():
                continue
                
            # Analyze comment to determine attack type and severity
            attack_type, severity = analyze_comment(comment)
            
            # Generate attack details
            timestamp = random_date().strftime('%Y-%m-%d %H:%M:%S')
            source_ip = random_ip()
            dest_ip = "192.168.1.101"  # Honeypot IP
            source_port = random.randint(1024, 65535)
            dest_port = random.choice([22, 23, 80, 443, 8080, 3306, 5432])  # Common ports
            protocol = random.choice(["TCP", "UDP", "HTTP", "HTTPS", "SSH"])
            
            # Use the comment as the payload (truncate if too long)
            payload = comment[:500] if comment else "Empty comment"
            
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
            
            # Print progress
            if (i + 1) % 100 == 0:
                print(f"Processed {i + 1} comments")
        
        conn.commit()
        print(f"Successfully imported {max_records} YouTube comments as attack data")
        
    except Exception as e:
        print(f"Error importing data: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
```

## Step 3: Run the Import Script

1. Make sure you have the required packages:
   ```
   pip install pandas
   ```

2. Run the script:
   ```
   python import_youtube_comments.py
   ```

## Step 4: View the Results

1. After importing, restart your application.
2. Open the dashboard in your browser to see:
   - Attack counts with severity levels
   - Alerts for high/critical attacks 
   - Timeline showing attack distribution
   - Attack severity breakdown

3. Click on "View Alerts" to see detailed alerts based on the YouTube comments
4. Click on "View Logs" to see all the processed comments as attack logs

## Step 5: Generate a Report

1. Go to the Reports page
2. Click "Generate Report" 
3. Select a time range and create a report
4. View the report to see statistics and trends

## How It Works

The import script:
1. Reads YouTube comments from the dataset
2. Analyzes each comment for patterns that could represent cyber attacks
3. Classifies comments as specific attack types with severity levels
4. Creates attack log entries in the database
5. Generates alerts for high and critical severity attacks

This approach transforms social media comments into a realistic cybersecurity dataset by using natural language processing techniques to identify potentially malicious content patterns.