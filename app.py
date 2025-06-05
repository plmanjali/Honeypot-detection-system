import os
import logging
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
import threading

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize SQLAlchemy
db = SQLAlchemy(model_class=Base)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev_secret_key")

# Configure database (SQLite for simplicity)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///honeypot.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the database with the app
db.init_app(app)

# Import models to ensure they're registered
from models import AttackLog, Alert, Report

# Create database tables
with app.app_context():
    db.create_all()
    logger.info("Database tables created")

# Import routes after models to avoid circular imports
from routes import register_routes

# Register all route blueprints
register_routes(app)

# Import honeypot monitoring system
from honeypot import HoneypotMonitor

# Create and initialize the honeypot monitor
honeypot_monitor = None

# Start the honeypot monitor in a separate thread when the app starts
def start_honeypot_monitor():
    global honeypot_monitor
    from attack_patterns import load_attack_patterns
    from alert_system import AlertSystem
    
    # Initialize components
    attack_patterns = load_attack_patterns()
    alert_system = AlertSystem()
    
    # Create honeypot monitor
    honeypot_monitor = HoneypotMonitor(attack_patterns, alert_system, app)
    
    # Start monitoring in a separate thread
    monitor_thread = threading.Thread(target=honeypot_monitor.start_monitoring)
    monitor_thread.daemon = True
    monitor_thread.start()
    logger.info("Honeypot monitor started in background")

# Initialize the honeypot monitor with Flask app context
with app.app_context():
    start_honeypot_monitor()

# Error handlers
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500
