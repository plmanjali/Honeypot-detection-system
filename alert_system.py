import logging
from datetime import datetime
from models import Alert
from app import db

logger = logging.getLogger(__name__)

class AlertSystem:
    """
    Alert system for the honeypot detection system.
    Generates and manages alerts based on detected attacks.
    """
    
    def __init__(self):
        self.severity_levels = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0
        }
    
    def generate_alert(self, title, message, severity="medium", source_ip=None, attack_type=None, log_id=None):
        """
        Generate a new alert and save it to the database.
        
        Args:
            title (str): Alert title
            message (str): Detailed alert message
            severity (str): Alert severity (critical, high, medium, low, info)
            source_ip (str): Source IP of the attack
            attack_type (str): Type of the detected attack
            log_id (int): ID of the associated attack log
            
        Returns:
            int: ID of the created alert, or None if failed
        """
        try:
            # Validate severity
            if severity not in self.severity_levels:
                severity = "medium"
            
            # Create new alert
            alert = Alert(
                timestamp=datetime.utcnow(),
                title=title,
                message=message,
                severity=severity,
                source_ip=source_ip,
                attack_type=attack_type,
                log_id=log_id
            )
            
            # Save to database
            db.session.add(alert)
            db.session.commit()
            
            logger.info(f"Generated alert: {title} (ID: {alert.id})")
            
            # In a real system, here you might also:
            # - Send email notifications
            # - Send SMS alerts
            # - Integrate with external systems (SIEM, etc.)
            
            return alert.id
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error generating alert: {e}")
            return None
    
    def get_unread_alerts_count(self):
        """Get count of unread alerts"""
        try:
            return Alert.query.filter_by(is_read=False).count()
        except Exception as e:
            logger.error(f"Error getting unread alerts count: {e}")
            return 0
    
    def get_recent_alerts(self, limit=10):
        """Get most recent alerts"""
        try:
            alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(limit).all()
            return [alert.to_dict() for alert in alerts]
        except Exception as e:
            logger.error(f"Error getting recent alerts: {e}")
            return []
    
    def mark_alert_as_read(self, alert_id):
        """Mark an alert as read"""
        try:
            alert = Alert.query.get(alert_id)
            if alert:
                alert.is_read = True
                db.session.commit()
                return True
            return False
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error marking alert as read: {e}")
            return False
    
    def delete_alert(self, alert_id):
        """Delete an alert"""
        try:
            alert = Alert.query.get(alert_id)
            if alert:
                db.session.delete(alert)
                db.session.commit()
                return True
            return False
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error deleting alert: {e}")
            return False
