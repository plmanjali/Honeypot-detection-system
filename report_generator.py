import logging
import json
from datetime import datetime
from models import Report, AttackLog
from app import db
from sqlalchemy import func, desc, and_

logger = logging.getLogger(__name__)

def generate_report(title, report_type, start_date, end_date):
    """
    Generate a report for a specific time period
    
    Args:
        title (str): Report title
        report_type (str): Type of report (daily, weekly, monthly, custom)
        start_date (datetime): Start date for the report
        end_date (datetime): End date for the report
        
    Returns:
        Report: Generated report object
    """
    try:
        # Check if a report with the same parameters already exists
        existing_report = Report.query.filter(
            Report.report_type == report_type,
            Report.start_date == start_date,
            Report.end_date == end_date
        ).first()
        
        if existing_report:
            # Update existing report
            logger.info(f"Updating existing report: {existing_report.id}")
            report = existing_report
            report.created_at = datetime.utcnow()
        else:
            # Create new report
            report = Report(
                title=title,
                report_type=report_type,
                start_date=start_date,
                end_date=end_date
            )
        
        # Get attack count for the time period
        attack_count = db.session.query(func.count(AttackLog.id)).filter(
            AttackLog.timestamp >= start_date,
            AttackLog.timestamp <= end_date
        ).scalar() or 0
        
        # Get top attack types
        top_attack_types = db.session.query(
            AttackLog.attack_type, func.count(AttackLog.id).label('count')
        ).filter(
            AttackLog.timestamp >= start_date,
            AttackLog.timestamp <= end_date
        ).group_by(AttackLog.attack_type).order_by(desc('count')).limit(10).all()
        
        # Get top source IPs
        top_source_ips = db.session.query(
            AttackLog.source_ip, func.count(AttackLog.id).label('count')
        ).filter(
            AttackLog.timestamp >= start_date,
            AttackLog.timestamp <= end_date
        ).group_by(AttackLog.source_ip).order_by(desc('count')).limit(10).all()
        
        # Convert to serializable format
        attack_types_data = [{'name': attack_type, 'count': count} for attack_type, count in top_attack_types]
        source_ips_data = [{'ip': ip, 'count': count} for ip, count in top_source_ips]
        
        # Generate summary
        summary = f"This report covers the period from {start_date} to {end_date}. "
        summary += f"During this period, {attack_count} attack attempts were detected. "
        
        if top_attack_types:
            top_attack = top_attack_types[0]
            summary += f"The most common attack type was '{top_attack[0]}' with {top_attack[1]} occurrences. "
        
        if top_source_ips:
            top_ip = top_source_ips[0]
            summary += f"The most active source IP was {top_ip[0]} with {top_ip[1]} attack attempts."
        
        # Update report data
        report.summary = summary
        report.attack_count = attack_count
        report.top_attack_types = json.dumps(attack_types_data)
        report.top_source_ips = json.dumps(source_ips_data)
        
        # Save to database
        if not existing_report:
            db.session.add(report)
        db.session.commit()
        
        logger.info(f"Generated report: {report.id} - {report.title}")
        
        return report
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error generating report: {e}")
        return None

def get_report(report_id):
    """
    Get a report by ID
    
    Args:
        report_id (int): Report ID
        
    Returns:
        dict: Report data
    """
    try:
        report = Report.query.get(report_id)
        if not report:
            return None
        
        return report.to_dict()
    
    except Exception as e:
        logger.error(f"Error getting report: {e}")
        return None

def delete_report(report_id):
    """
    Delete a report
    
    Args:
        report_id (int): Report ID
        
    Returns:
        bool: Success status
    """
    try:
        report = Report.query.get(report_id)
        if not report:
            return False
        
        db.session.delete(report)
        db.session.commit()
        return True
    
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting report: {e}")
        return False
