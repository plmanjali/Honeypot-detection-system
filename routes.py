from flask import Blueprint, render_template, jsonify, request, redirect, url_for, flash
from datetime import datetime, timedelta
import json
from models import AttackLog, Alert, Report
from app import db
from log_manager import get_logs, get_log_stats
from report_generator import generate_report

# Create blueprints
dashboard_bp = Blueprint('dashboard', __name__)
alerts_bp = Blueprint('alerts', __name__)
logs_bp = Blueprint('logs', __name__)
reports_bp = Blueprint('reports', __name__)
settings_bp = Blueprint('settings', __name__)

# Dashboard routes
@dashboard_bp.route('/')
def index():
    return render_template('dashboard.html')

@dashboard_bp.route('/api/dashboard/stats')
def dashboard_stats():
    # Get time range from request
    time_range = request.args.get('range', 'day')
    
    # Calculate time period based on range
    now = datetime.utcnow()
    if time_range == 'day':
        start_time = now - timedelta(days=1)
    elif time_range == 'week':
        start_time = now - timedelta(weeks=1)
    elif time_range == 'month':
        start_time = now - timedelta(days=30)
    else:
        start_time = now - timedelta(days=1)  # Default to 1 day
    
    # Get attack stats
    stats = get_log_stats(start_time)
    
    # Get recent alerts
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(5).all()
    alerts_data = [alert.to_dict() for alert in recent_alerts]
    
    return jsonify({
        'stats': stats,
        'recent_alerts': alerts_data
    })

# Alerts routes
@alerts_bp.route('/alerts')
def alerts_page():
    return render_template('alerts.html')

@alerts_bp.route('/api/alerts')
def get_alerts():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # Get alerts with pagination
    pagination = Alert.query.order_by(Alert.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    alerts = pagination.items
    alerts_data = [alert.to_dict() for alert in alerts]
    
    return jsonify({
        'alerts': alerts_data,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })

@alerts_bp.route('/api/alerts/<int:alert_id>/mark-read', methods=['POST'])
def mark_alert_read(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.is_read = True
    db.session.commit()
    return jsonify({'success': True})

# Logs routes
@logs_bp.route('/logs')
def logs_page():
    return render_template('logs.html')

@logs_bp.route('/api/logs')
def get_attack_logs():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    # Filtering parameters
    source_ip = request.args.get('source_ip')
    attack_type = request.args.get('attack_type')
    severity = request.args.get('severity')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    # Base query
    query = AttackLog.query
    
    # Apply filters
    if source_ip:
        query = query.filter(AttackLog.source_ip == source_ip)
    if attack_type:
        query = query.filter(AttackLog.attack_type == attack_type)
    if severity:
        query = query.filter(AttackLog.severity == severity)
    if start_date:
        start_datetime = datetime.strptime(start_date, '%Y-%m-%d')
        query = query.filter(AttackLog.timestamp >= start_datetime)
    if end_date:
        end_datetime = datetime.strptime(end_date, '%Y-%m-%d')
        end_datetime = end_datetime + timedelta(days=1)  # Include the end date
        query = query.filter(AttackLog.timestamp < end_datetime)
    
    # Execute query with pagination
    pagination = query.order_by(AttackLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    logs = pagination.items
    logs_data = [log.to_dict() for log in logs]
    
    return jsonify({
        'logs': logs_data,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })

# Reports routes
@reports_bp.route('/reports')
def reports_page():
    return render_template('reports.html')

@reports_bp.route('/api/reports')
def get_reports():
    reports = Report.query.order_by(Report.created_at.desc()).all()
    reports_data = [report.to_dict() for report in reports]
    return jsonify({'reports': reports_data})

@reports_bp.route('/api/reports/generate', methods=['POST'])
def create_report():
    data = request.json
    report_type = data.get('report_type', 'daily')
    title = data.get('title', f'{report_type.capitalize()} Report')
    
    # Get date range
    if report_type == 'daily':
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow()
    elif report_type == 'weekly':
        start_date = datetime.utcnow() - timedelta(weeks=1)
        end_date = datetime.utcnow()
    elif report_type == 'monthly':
        start_date = datetime.utcnow() - timedelta(days=30)
        end_date = datetime.utcnow()
    else:  # Custom range
        start_date = datetime.strptime(data.get('start_date'), '%Y-%m-%d')
        end_date = datetime.strptime(data.get('end_date'), '%Y-%m-%d') + timedelta(days=1)
    
    # Generate report
    report = generate_report(title, report_type, start_date, end_date)
    
    return jsonify({'success': True, 'report': report.to_dict()})

@reports_bp.route('/api/reports/<int:report_id>')
def get_report(report_id):
    report = Report.query.get_or_404(report_id)
    return jsonify({'report': report.to_dict()})

# Settings routes
@settings_bp.route('/settings')
def settings_page():
    return render_template('settings.html')

def register_routes(app):
    """Register all route blueprints with the Flask app"""
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(settings_bp)
