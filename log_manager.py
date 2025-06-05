import logging
import json
from datetime import datetime, timedelta
from models import AttackLog, Alert
from app import db
from sqlalchemy import func, desc, and_

logger = logging.getLogger(__name__)

def get_logs(start_time=None, end_time=None, source_ip=None, attack_type=None, severity=None, page=1, per_page=50):
    """
    Get attack logs with optional filtering
    
    Args:
        start_time (datetime): Start time for filtering
        end_time (datetime): End time for filtering
        source_ip (str): Filter by source IP
        attack_type (str): Filter by attack type
        severity (str): Filter by severity
        page (int): Page number for pagination
        per_page (int): Items per page
        
    Returns:
        dict: Dictionary with logs and pagination info
    """
    try:
        # Base query
        query = AttackLog.query
        
        # Apply filters
        if start_time:
            query = query.filter(AttackLog.timestamp >= start_time)
        if end_time:
            query = query.filter(AttackLog.timestamp <= end_time)
        if source_ip:
            query = query.filter(AttackLog.source_ip == source_ip)
        if attack_type:
            query = query.filter(AttackLog.attack_type == attack_type)
        if severity:
            query = query.filter(AttackLog.severity == severity)
        
        # Execute query with pagination
        pagination = query.order_by(AttackLog.timestamp.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        logs = pagination.items
        logs_data = [log.to_dict() for log in logs]
        
        return {
            'logs': logs_data,
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page
        }
    
    except Exception as e:
        logger.error(f"Error retrieving logs: {e}")
        return {'logs': [], 'total': 0, 'pages': 0, 'current_page': page}

def get_log_stats(start_time=None, end_time=None):
    """
    Get statistics about attack logs
    
    Args:
        start_time (datetime): Start time for filtering
        end_time (datetime): End time for filtering
        
    Returns:
        dict: Dictionary with statistics
    """
    try:
        # Set default end time to now if not provided
        if not end_time:
            end_time = datetime.utcnow()
        
        # Set default start time to 24 hours ago if not provided
        if not start_time:
            start_time = end_time - timedelta(days=1)
        
        # Base query filter for time range
        time_filter = and_(
            AttackLog.timestamp >= start_time,
            AttackLog.timestamp <= end_time
        )
        
        # Total attacks count
        total_attacks = db.session.query(func.count(AttackLog.id)).filter(time_filter).scalar() or 0
        
        # Attacks by severity
        severity_counts = db.session.query(
            AttackLog.severity, func.count(AttackLog.id)
        ).filter(time_filter).group_by(AttackLog.severity).all()
        
        severity_data = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for severity, count in severity_counts:
            if severity in severity_data:
                severity_data[severity] = count
        
        # Top attack types
        attack_types = db.session.query(
            AttackLog.attack_type, func.count(AttackLog.id).label('count')
        ).filter(time_filter).group_by(AttackLog.attack_type).order_by(desc('count')).limit(5).all()
        
        attack_types_data = [{'name': attack_type, 'count': count} for attack_type, count in attack_types]
        
        # Top source IPs
        source_ips = db.session.query(
            AttackLog.source_ip, func.count(AttackLog.id).label('count')
        ).filter(time_filter).group_by(AttackLog.source_ip).order_by(desc('count')).limit(5).all()
        
        source_ips_data = [{'ip': ip, 'count': count} for ip, count in source_ips]
        
        # Attacks by protocol
        protocols = db.session.query(
            AttackLog.protocol, func.count(AttackLog.id).label('count')
        ).filter(time_filter).group_by(AttackLog.protocol).all()
        
        protocols_data = [{'protocol': protocol, 'count': count} for protocol, count in protocols]
        
        # Attacks by time (hourly for last 24 hours)
        if (end_time - start_time).total_seconds() <= 86400:  # 24 hours
            time_series = []
            current = start_time
            interval = timedelta(hours=1)
            
            while current <= end_time:
                next_hour = current + interval
                count = db.session.query(func.count(AttackLog.id)).filter(
                    AttackLog.timestamp >= current,
                    AttackLog.timestamp < next_hour
                ).scalar() or 0
                
                time_series.append({
                    'time': current.strftime('%Y-%m-%d %H:%M'),
                    'count': count
                })
                
                current = next_hour
        else:
            # Daily data for longer periods
            time_series = []
            current = start_time
            interval = timedelta(days=1)
            
            while current <= end_time:
                next_day = current + interval
                count = db.session.query(func.count(AttackLog.id)).filter(
                    AttackLog.timestamp >= current,
                    AttackLog.timestamp < next_day
                ).scalar() or 0
                
                time_series.append({
                    'time': current.strftime('%Y-%m-%d'),
                    'count': count
                })
                
                current = next_day
        
        # Recent alerts count
        recent_alerts_count = db.session.query(func.count(Alert.id)).filter(
            Alert.timestamp >= start_time,
            Alert.timestamp <= end_time
        ).scalar() or 0
        
        return {
            'total_attacks': total_attacks,
            'severity': severity_data,
            'attack_types': attack_types_data,
            'source_ips': source_ips_data,
            'protocols': protocols_data,
            'time_series': time_series,
            'alerts_count': recent_alerts_count
        }
    
    except Exception as e:
        logger.error(f"Error getting log stats: {e}")
        return {
            'total_attacks': 0,
            'severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'attack_types': [],
            'source_ips': [],
            'protocols': [],
            'time_series': [],
            'alerts_count': 0
        }

def export_logs(start_time, end_time, format='json'):
    """
    Export logs for a specific time period
    
    Args:
        start_time (datetime): Start time for filtering
        end_time (datetime): End time for filtering
        format (str): Export format ('json' or 'csv')
        
    Returns:
        str: Exported data in the specified format
    """
    try:
        # Get logs for the specified time period
        logs = AttackLog.query.filter(
            AttackLog.timestamp >= start_time,
            AttackLog.timestamp <= end_time
        ).order_by(AttackLog.timestamp).all()
        
        logs_data = [log.to_dict() for log in logs]
        
        if format == 'json':
            return json.dumps(logs_data, indent=2)
        elif format == 'csv':
            # Simple CSV export
            if not logs_data:
                return "No data available"
            
            headers = logs_data[0].keys()
            csv_data = ','.join(headers) + '\n'
            
            for log in logs_data:
                row = ','.join([str(log[h]) for h in headers])
                csv_data += row + '\n'
            
            return csv_data
        else:
            return "Unsupported format"
    
    except Exception as e:
        logger.error(f"Error exporting logs: {e}")
        return "Error exporting logs"

def delete_old_logs(days=30):
    """
    Delete logs older than the specified number of days
    
    Args:
        days (int): Number of days to keep logs
        
    Returns:
        int: Number of deleted logs
    """
    try:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        deleted = AttackLog.query.filter(AttackLog.timestamp < cutoff_date).delete()
        db.session.commit()
        return deleted
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting old logs: {e}")
        return 0
