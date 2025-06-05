import json
import logging
import os

logger = logging.getLogger(__name__)

# Default attack patterns in case the patterns file doesn't exist
DEFAULT_ATTACK_PATTERNS = [
    {
        "name": "SQL Injection",
        "protocol": "TCP",
        "port": 80,
        "signature": "' OR 1=1",
        "severity": "high",
        "description": "SQL injection attempt trying to bypass authentication"
    },
    {
        "name": "SQL Injection",
        "protocol": "TCP",
        "port": 80,
        "signature": "UNION SELECT",
        "severity": "high",
        "description": "SQL injection attempt using UNION"
    },
    {
        "name": "XSS Attack",
        "protocol": "TCP",
        "port": 80,
        "signature": "<script>",
        "severity": "medium",
        "description": "Cross-site scripting attempt"
    },
    {
        "name": "Command Injection",
        "protocol": "TCP",
        "port": 80,
        "signature": "; cat /etc/passwd",
        "severity": "high",
        "description": "Command injection attempt to read passwd file"
    },
    {
        "name": "Path Traversal",
        "protocol": "TCP",
        "port": 80,
        "signature": "../../../",
        "severity": "medium",
        "description": "Directory traversal attempt"
    },
    {
        "name": "SSH Brute Force",
        "protocol": "TCP",
        "port": 22,
        "signature": "SSH-",
        "severity": "medium", 
        "description": "SSH brute force attempt"
    },
    {
        "name": "FTP Brute Force",
        "protocol": "TCP",
        "port": 21,
        "signature": "USER",
        "severity": "medium",
        "description": "FTP brute force attempt"
    },
    {
        "name": "NMAP Scan",
        "protocol": "*",
        "port": "*",
        "signature": "Nmap",
        "severity": "low",
        "description": "Port scanning with Nmap"
    },
    {
        "name": "HTTP Directory Scan",
        "protocol": "TCP",
        "port": 80,
        "signature": "gobuster",
        "severity": "low",
        "description": "Web directory scanning"
    },
    {
        "name": "HTTP Directory Scan",
        "protocol": "TCP",
        "port": 80,
        "signature": "dirbuster",
        "severity": "low",
        "description": "Web directory scanning"
    },
    {
        "name": "Log4j Exploitation",
        "protocol": "TCP",
        "port": "*",
        "signature": "${jndi:ldap",
        "severity": "critical",
        "description": "Log4j vulnerability exploitation attempt"
    },
    {
        "name": "ShellShock Attack",
        "protocol": "TCP",
        "port": 80,
        "signature": "() {",
        "severity": "high",
        "description": "ShellShock vulnerability exploitation attempt"
    }
]

def load_attack_patterns():
    """
    Load attack patterns from a JSON file or use defaults.
    In a real-world scenario, this could be regularly updated from a threat intel feed.
    """
    patterns_file = os.path.join(os.path.dirname(__file__), "attack_patterns.json")
    
    # Check if patterns file exists
    if os.path.exists(patterns_file):
        try:
            with open(patterns_file, 'r') as f:
                patterns = json.load(f)
                logger.info(f"Loaded {len(patterns)} attack patterns from {patterns_file}")
                return patterns
        except Exception as e:
            logger.error(f"Error loading attack patterns from file: {e}")
            logger.info("Using default attack patterns")
            return DEFAULT_ATTACK_PATTERNS
    else:
        # Create the file with default patterns
        try:
            with open(patterns_file, 'w') as f:
                json.dump(DEFAULT_ATTACK_PATTERNS, f, indent=2)
                logger.info(f"Created attack patterns file with default patterns at {patterns_file}")
        except Exception as e:
            logger.error(f"Error creating attack patterns file: {e}")
        
        return DEFAULT_ATTACK_PATTERNS

def save_attack_patterns(patterns):
    """Save attack patterns to a JSON file"""
    patterns_file = os.path.join(os.path.dirname(__file__), "attack_patterns.json")
    
    try:
        with open(patterns_file, 'w') as f:
            json.dump(patterns, f, indent=2)
            logger.info(f"Saved {len(patterns)} attack patterns to {patterns_file}")
        return True
    except Exception as e:
        logger.error(f"Error saving attack patterns to file: {e}")
        return False

def add_attack_pattern(name, protocol, port, signature, severity, description):
    """Add a new attack pattern to the database"""
    patterns = load_attack_patterns()
    
    new_pattern = {
        "name": name,
        "protocol": protocol,
        "port": port,
        "signature": signature,
        "severity": severity,
        "description": description
    }
    
    patterns.append(new_pattern)
    save_attack_patterns(patterns)
    return True

def remove_attack_pattern(index):
    """Remove an attack pattern by index"""
    patterns = load_attack_patterns()
    
    if 0 <= index < len(patterns):
        patterns.pop(index)
        save_attack_patterns(patterns)
        return True
    
    return False
