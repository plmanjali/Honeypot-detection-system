from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
import logging
from datetime import datetime
from models import AttackLog, Alert, db
from alert_system import AlertSystem
import re

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create blueprint for decoy website
decoy_bp = Blueprint('decoy', __name__, url_prefix='/bank')

# Initialize alert system
alert_system = AlertSystem()

def detect_attack(content, source_ip):
    """
    Analyzes request content to detect potential attack patterns.
    Returns attack_type, severity, and payload if attack detected.
    """
    # SQL Injection patterns
    sql_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b.*(\bFROM\b|\bTABLE\b|\bDATABASE\b))",
        r"('|\")(;|\s*--|\s*\|\s*|\s*\|\|\s*|\s*&\s*|\s*&&\s*|\s*\|\s*)",
        r"('|\")\s*OR\s*('|\")?\s*[0-9]+(=|>|<)",
        r"\b(OR|AND)\s+[0-9]+=\s*[0-9]+",
        r";\s*(SELECT|INSERT|UPDATE|DELETE|DROP)"
    ]
    
    # XSS patterns
    xss_patterns = [
        r"<script.*?>.*?</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"eval\s*\(",
        r"document\.cookie"
    ]
    
    # Command injection patterns
    cmd_patterns = [
        r";\s*(ls|cat|rm|pwd|echo|bash|sh)\s",
        r"\|\s*(ls|cat|rm|pwd|echo|bash|sh)\s",
        r"`.*?`",
        r"\$\(.*?\)"
    ]
    
    # Path traversal patterns
    path_patterns = [
        r"\.\.(/|\\){1,}",
        r"/etc/(passwd|shadow|hosts)",
        r"C:\\Windows\\system32"
    ]
    
    # Analyze request content
    if isinstance(content, str):
        # Check SQL Injection
        for pattern in sql_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return "SQL Injection", "high", content
        
        # Check XSS
        for pattern in xss_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return "XSS Attack", "high", content
        
        # Check Command Injection
        for pattern in cmd_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return "Command Injection", "critical", content
        
        # Check Path Traversal
        for pattern in path_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return "Path Traversal", "medium", content
    
    # Username/password guessing detection
    if "/login" in request.path and request.method == "POST":
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        common_admin_usernames = ['admin', 'administrator', 'root', 'superuser', 'sysadmin']
        if username.lower() in common_admin_usernames:
            return "Brute Force", "medium", f"Attempted login with common admin username: {username}"
    
    # CSRF detection for forms
    if request.method == "POST" and not request.headers.get('Referer'):
        return "CSRF Attack", "medium", "Missing referer header in form submission"
    
    # No attack detected
    return None, None, None

def log_attack(attack_type, severity, payload, source_ip):
    """
    Log detected attack to database and generate alert
    """
    try:
        now = datetime.utcnow()
        
        # Create attack log entry
        attack_log = AttackLog(
            timestamp=now,
            source_ip=source_ip,
            destination_ip=request.host,
            source_port=0,  # HTTP port info may not be available
            destination_port=80 if not request.is_secure else 443,
            protocol="HTTP",
            attack_type=attack_type,
            severity=severity,
            payload=payload[:1000]  # Limit payload size
        )
        db.session.add(attack_log)
        db.session.commit()
        
        # Generate alert for high and critical severity attacks
        if severity in ["high", "critical"]:
            message = f"Potential {attack_type} attack detected from {source_ip}. Request contained suspicious patterns."
            alert_system.generate_alert(
                title=f"{attack_type} detected",
                message=message,
                severity=severity,
                source_ip=source_ip,
                attack_type=attack_type,
                log_id=attack_log.id
            )
        
        logger.info(f"Attack logged: {attack_type} from {source_ip}")
        return True
    except Exception as e:
        logger.error(f"Error logging attack: {e}")
        return False

@decoy_bp.before_request
def before_request():
    """
    Intercept every request to check for potential attacks
    """
    source_ip = request.remote_addr
    
    # Check query parameters
    if request.args:
        query_string = request.query_string.decode('utf-8', errors='ignore')
        attack_type, severity, payload = detect_attack(query_string, source_ip)
        if attack_type:
            log_attack(attack_type, severity, payload, source_ip)
    
    # Check form data
    if request.form:
        form_data = str(request.form)
        attack_type, severity, payload = detect_attack(form_data, source_ip)
        if attack_type:
            log_attack(attack_type, severity, payload, source_ip)
    
    # Check JSON data
    if request.is_json:
        try:
            json_data = str(request.get_json())
            attack_type, severity, payload = detect_attack(json_data, source_ip)
            if attack_type:
                log_attack(attack_type, severity, payload, source_ip)
        except Exception as e:
            logger.error(f"Error processing JSON data: {e}")
    
    # Check cookies
    if request.cookies:
        cookies_data = str(request.cookies)
        attack_type, severity, payload = detect_attack(cookies_data, source_ip)
        if attack_type:
            log_attack(attack_type, severity, payload, source_ip)
    
    # Check headers for malicious content
    headers = str(dict(request.headers))
    attack_type, severity, payload = detect_attack(headers, source_ip)
    if attack_type:
        log_attack(attack_type, severity, payload, source_ip)

# Decoy website routes
@decoy_bp.route('/')
def home():
    return render_template('decoy/home.html')

@decoy_bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Log all login attempts
        login_attempt = f"Login attempt: Username={username}, Password={password}"
        logger.info(login_attempt)
        
        # Deliberately vulnerable to SQL injection but we're logging the attempt
        if username and password:
            # Check for SQL injection patterns in the username
            sql_injection = False
            sql_patterns = [
                "'", "--", "OR 1=1", "OR '1'='1", "UNION", "SELECT", "DROP", 
                "1=1", "admin'--", ";", "/*", "*/"
            ]
            
            for pattern in sql_patterns:
                if pattern.lower() in username.lower() or pattern.lower() in password.lower():
                    sql_injection = True
                    break
            
            # Fake authentication failure
            error = "Invalid username or password"
            
            if sql_injection:
                # Log as SQL Injection - high severity
                attack_log = AttackLog(
                    timestamp=datetime.utcnow(),
                    source_ip=request.remote_addr,
                    destination_ip=request.host,
                    source_port=0,
                    destination_port=80 if not request.is_secure else 443,
                    protocol="HTTP",
                    attack_type="SQL Injection",
                    severity="high",
                    payload=login_attempt
                )
                
                # Also generate an alert with detailed credentials
                alert_system.generate_alert(
                    title="SQL Injection attempt",
                    message=f"SQL Injection attempt detected from {request.remote_addr}. Login credentials: Username='{username}', Password='{password}'",
                    severity="high",
                    source_ip=request.remote_addr,
                    attack_type="SQL Injection",
                    log_id=attack_log.id
                )
            else:
                # Log as "Unauthorized Access" - low severity
                attack_log = AttackLog(
                    timestamp=datetime.utcnow(),
                    source_ip=request.remote_addr,
                    destination_ip=request.host,
                    source_port=0,
                    destination_port=80 if not request.is_secure else 443,
                    protocol="HTTP",
                    attack_type="Unauthorized Access",
                    severity="low",
                    payload=login_attempt
                )
            
            db.session.add(attack_log)
            db.session.commit()
            
    return render_template('decoy/login.html', error=error)

@decoy_bp.route('/admin')
def admin():
    # Log attempted access to admin area
    attack_log = AttackLog(
        timestamp=datetime.utcnow(),
        source_ip=request.remote_addr,
        destination_ip=request.host,
        source_port=0,
        destination_port=80 if not request.is_secure else 443,
        protocol="HTTP",
        attack_type="Unauthorized Access",
        severity="medium",
        payload="Attempted access to admin area without authentication"
    )
    db.session.add(attack_log)
    db.session.commit()
    
    # Generate alert
    alert_system.generate_alert(
        title="Admin access attempt",
        message=f"Unauthorized access attempt to admin area from {request.remote_addr}",
        severity="medium",
        source_ip=request.remote_addr,
        attack_type="Unauthorized Access",
        log_id=attack_log.id
    )
    
    # Redirect to login
    flash("Please login to access the admin area", "danger")
    return redirect(url_for('decoy.login'))

@decoy_bp.route('/api/accounts', methods=['GET'])
def get_accounts():
    # Log API access attempt
    attack_log = AttackLog(
        timestamp=datetime.utcnow(),
        source_ip=request.remote_addr,
        destination_ip=request.host,
        source_port=0,
        destination_port=80 if not request.is_secure else 443,
        protocol="HTTP",
        attack_type="API Access",
        severity="medium",
        payload="Attempted access to accounts API without authentication"
    )
    db.session.add(attack_log)
    db.session.commit()
    
    # Return "unauthorized" response
    return jsonify({"error": "Unauthorized access"}), 401

@decoy_bp.route('/search')
def search():
    query = request.args.get('q', '')
    
    # Check for XSS attempts
    xss_detected = False
    if query:
        xss_patterns = [
            '<script', 'javascript:', 'onerror=', 'onload=', 'onclick=', 
            'alert(', 'document.cookie', '<img', '<iframe', 'eval('
        ]
        
        for pattern in xss_patterns:
            if pattern.lower() in query.lower():
                xss_detected = True
                break
                
        # Check for path traversal
        path_traversal = False
        path_patterns = ['../', '..\\', '/etc/', 'passwd', 'shadow', 'boot.ini', 'windows\\']
        
        for pattern in path_patterns:
            if pattern.lower() in query.lower():
                path_traversal = True
                break
        
        # Log the attack if detected
        if xss_detected:
            # Log as XSS Attack
            attack_log = AttackLog(
                timestamp=datetime.utcnow(),
                source_ip=request.remote_addr,
                destination_ip=request.host,
                source_port=0,
                destination_port=80 if not request.is_secure else 443,
                protocol="HTTP",
                attack_type="XSS Attack",
                severity="high",
                payload=f"XSS attempt in search: {query}"
            )
            db.session.add(attack_log)
            
            # Generate alert
            alert_system.generate_alert(
                title="XSS Attack detected",
                message=f"XSS Attack detected from {request.remote_addr}. Search query: {query}",
                severity="high",
                source_ip=request.remote_addr,
                attack_type="XSS Attack",
                log_id=attack_log.id
            )
            
            db.session.commit()
            
        elif path_traversal:
            # Log as Path Traversal
            attack_log = AttackLog(
                timestamp=datetime.utcnow(),
                source_ip=request.remote_addr,
                destination_ip=request.host,
                source_port=0,
                destination_port=80 if not request.is_secure else 443,
                protocol="HTTP",
                attack_type="Path Traversal",
                severity="medium",
                payload=f"Path Traversal attempt in search: {query}"
            )
            db.session.add(attack_log)
            
            # Generate alert
            alert_system.generate_alert(
                title="Path Traversal detected",
                message=f"Path Traversal detected from {request.remote_addr}. Search query: {query}",
                severity="medium",
                source_ip=request.remote_addr,
                attack_type="Path Traversal",
                log_id=attack_log.id
            )
            
            db.session.commit()
    
    # Return fake search results - deliberately vulnerable to XSS
    results = []
    if query:
        results = [
            {"title": "Account Services", "url": "/bank/accounts"}, 
            {"title": "Customer Support", "url": "/bank/support"},
            {"title": "Loan Information", "url": "/bank/loans"}
        ]
    
    return render_template('decoy/search.html', query=query, results=results)

@decoy_bp.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        message = request.form.get('message', '')
        
        # Log the contact form submission
        payload = f"Contact form: Name={name}, Email={email}, Message={message}"
        
        # Check for command injection patterns
        cmd_injection = False
        if message:
            cmd_patterns = [
                ';', '|', '`', '$(',  # Command separators
                'ls', 'cat', 'rm', 'pwd', 'echo', 'bash', 'sh',  # Common commands
                '/bin/', '/etc/', '/usr/',  # Common directories
                '&&', '||', '>', '>>'  # Command operators
            ]
            
            for pattern in cmd_patterns:
                if pattern in message:
                    cmd_injection = True
                    break
        
        # Check for phishing content
        phishing = False
        if message:
            phishing_patterns = [
                'password', 'account', 'login', 'verify', 'click here',
                'urgent', 'update your', 'security alert', 'unusual activity',
                'http://', 'https://', 'www.', '.com', '.net', '.org'
            ]
            
            matched_patterns = 0
            for pattern in phishing_patterns:
                if pattern.lower() in message.lower():
                    matched_patterns += 1
            
            # If multiple phishing patterns are found, flag as phishing
            if matched_patterns >= 3:
                phishing = True
        
        if cmd_injection:
            # Log as Command Injection - critical severity
            attack_log = AttackLog(
                timestamp=datetime.utcnow(),
                source_ip=request.remote_addr,
                destination_ip=request.host,
                source_port=0,
                destination_port=80 if not request.is_secure else 443,
                protocol="HTTP",
                attack_type="Command Injection",
                severity="critical",
                payload=payload[:1000]  # Limit payload size
            )
            db.session.add(attack_log)
            
            # Generate alert with detailed command
            alert_system.generate_alert(
                title="Command Injection detected",
                message=f"Command Injection detected from {request.remote_addr} in contact form.\nName: '{name}'\nEmail: '{email}'\nMessage: '{message}'",
                severity="critical",
                source_ip=request.remote_addr,
                attack_type="Command Injection",
                log_id=attack_log.id
            )
        elif phishing:
            # Log as Phishing Attempt - medium severity
            attack_log = AttackLog(
                timestamp=datetime.utcnow(),
                source_ip=request.remote_addr,
                destination_ip=request.host,
                source_port=0,
                destination_port=80 if not request.is_secure else 443,
                protocol="HTTP",
                attack_type="Phishing Attempt",
                severity="medium",
                payload=payload[:1000]  # Limit payload size
            )
            db.session.add(attack_log)
            
            # Generate alert with phishing content details
            alert_system.generate_alert(
                title="Phishing content detected",
                message=f"Potential phishing content detected from {request.remote_addr} in contact form.\nName: '{name}'\nEmail: '{email}'\nMessage: '{message}'",
                severity="medium",
                source_ip=request.remote_addr,
                attack_type="Phishing Attempt",
                log_id=attack_log.id
            )
        else:
            # Log as normal form submission - low severity
            attack_log = AttackLog(
                timestamp=datetime.utcnow(),
                source_ip=request.remote_addr,
                destination_ip=request.host,
                source_port=0,
                destination_port=80 if not request.is_secure else 443,
                protocol="HTTP",
                attack_type="Form Submission",
                severity="low",
                payload=payload[:1000]  # Limit payload size
            )
            db.session.add(attack_log)
        
        db.session.commit()
        
        flash("Thank you for your message. We'll get back to you soon!", "success")
        return redirect(url_for('decoy.contact'))
        
    return render_template('decoy/contact.html')

def register_decoy_routes(app):
    """Register decoy website blueprint with the Flask app"""
    app.register_blueprint(decoy_bp)