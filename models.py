from datetime import datetime
from app import db

class AttackLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(50), nullable=False)
    destination_ip = db.Column(db.String(50), nullable=False)
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    attack_type = db.Column(db.String(100))
    severity = db.Column(db.String(20))
    payload = db.Column(db.Text)
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'source_port': self.source_port,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'attack_type': self.attack_type,
            'severity': self.severity,
            'payload': self.payload
        }

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    title = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # high, medium, low
    source_ip = db.Column(db.String(50))
    attack_type = db.Column(db.String(100))
    is_read = db.Column(db.Boolean, default=False)
    log_id = db.Column(db.Integer, db.ForeignKey('attack_log.id'))
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'title': self.title,
            'message': self.message,
            'severity': self.severity,
            'source_ip': self.source_ip,
            'attack_type': self.attack_type,
            'is_read': self.is_read,
            'log_id': self.log_id
        }

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    report_type = db.Column(db.String(50))  # daily, weekly, custom
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    summary = db.Column(db.Text)
    attack_count = db.Column(db.Integer)
    top_attack_types = db.Column(db.Text)  # JSON serialized
    top_source_ips = db.Column(db.Text)    # JSON serialized
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'report_type': self.report_type,
            'start_date': self.start_date.strftime('%Y-%m-%d %H:%M:%S') if self.start_date else None,
            'end_date': self.end_date.strftime('%Y-%m-%d %H:%M:%S') if self.end_date else None,
            'summary': self.summary,
            'attack_count': self.attack_count,
            'top_attack_types': self.top_attack_types,
            'top_source_ips': self.top_source_ips
        }
