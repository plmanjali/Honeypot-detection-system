import logging
import time
import threading
import socket

# Mock scapy classes for environments where scapy might not work properly
# In a production environment, you would use the actual scapy library
class MockPacket(dict):
    def __contains__(self, item):
        return False

# Create mock versions of all needed scapy components
def sniff(prn=None, store=None, filter=None, iface=None):
    logging.info(f"Mock sniffing on interface {iface} with filter: {filter}")
    # In a real environment, this would actually capture packets
    # For now, we'll just log that it was called
    return []

# Mock packet classes
class IP:
    pass

class TCP:
    pass

class UDP:
    pass

class ICMP:
    pass

class Raw:
    pass

# Try to import actual scapy if available
try:
    from scapy.all import sniff as real_sniff
    from scapy.all import IP as real_IP
    from scapy.all import TCP as real_TCP
    from scapy.all import UDP as real_UDP
    from scapy.all import ICMP as real_ICMP
    from scapy.all import Raw as real_Raw
    
    # Replace our mocks with the real thing
    sniff = real_sniff
    IP = real_IP
    TCP = real_TCP
    UDP = real_UDP
    ICMP = real_ICMP
    Raw = real_Raw
    
    logging.info("Successfully imported Scapy modules")
except ImportError:
    logging.warning("Using mock packet capture - Scapy not available")
    # Continue with our mock classes
from datetime import datetime
from models import AttackLog
from app import db

logger = logging.getLogger(__name__)

class HoneypotMonitor:
    """Main honeypot monitoring class that captures and analyzes network traffic"""
    
    def __init__(self, attack_patterns, alert_system, app):
        self.attack_patterns = attack_patterns
        self.alert_system = alert_system
        self.app = app
        self.running = False
        self.interfaces = self._get_available_interfaces()
        self.honeypot_ips = ["127.0.0.1"]  # Default to localhost for testing
        
        # In a real deployment, you'd have specific honeypot IPs to monitor
        # self.honeypot_ips = ["192.168.1.100", "192.168.1.101"]
    
    def _get_available_interfaces(self):
        """Get available network interfaces"""
        try:
            return socket.if_nameindex()
        except (AttributeError, OSError):
            # Fallback for systems where if_nameindex is not available
            return [("lo", "lo")]
    
    def _process_packet(self, packet):
        """Process a captured packet and check for attack patterns"""
        with self.app.app_context():
            try:
                # Only process IP packets
                if IP not in packet:
                    return
                
                # Extract basic packet information
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Skip packets not directed to our honeypot IPs
                if dst_ip not in self.honeypot_ips:
                    return
                
                protocol = None
                src_port = None
                dst_port = None
                payload = None
                
                # Extract protocol-specific information
                if TCP in packet:
                    protocol = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    if Raw in packet:
                        payload = str(packet[Raw].load)
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    if Raw in packet:
                        payload = str(packet[UDP].load)
                elif ICMP in packet:
                    protocol = "ICMP"
                    if Raw in packet:
                        payload = str(packet[Raw].load)
                
                # Check for attack patterns
                attack_type, severity = self._check_attack_patterns(packet, protocol, payload)
                
                # Log the packet if it matches an attack pattern or is suspicious
                if attack_type:
                    logger.info(f"Detected attack: {attack_type} from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
                    self._log_attack(src_ip, dst_ip, src_port, dst_port, protocol, attack_type, severity, payload)
                    
                    # Generate alert for the attack
                    self.alert_system.generate_alert(
                        title=f"{attack_type} attack detected",
                        message=f"Attack from {src_ip}:{src_port} to {dst_ip}:{dst_port}",
                        severity=severity,
                        source_ip=src_ip,
                        attack_type=attack_type
                    )
            
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
    
    def _check_attack_patterns(self, packet, protocol, payload):
        """Check packet against known attack patterns"""
        attack_type = None
        severity = "low"
        
        if not protocol:
            return None, None
        
        # Process payload-based attacks if we have a payload
        if payload:
            # Check against all attack patterns
            for pattern in self.attack_patterns:
                if pattern['protocol'] == protocol or pattern['protocol'] == '*':
                    # Check if pattern signature is in payload
                    if pattern['signature'] in payload:
                        attack_type = pattern['name']
                        severity = pattern['severity']
                        break
        
        # Process TCP-specific attacks
        if protocol == "TCP" and TCP in packet:
            # Check for SYN flood (many SYN packets)
            if packet[TCP].flags & 0x02:  # SYN flag
                # In a real implementation, you'd track SYN counts from IPs
                # This is simplified for demonstration
                pass
            
            # Check for port scanning patterns
            # Again, in real implementation, you'd track this behavior over time
        
        # Return detected attack type and severity
        return attack_type, severity
    
    def _log_attack(self, src_ip, dst_ip, src_port, dst_port, protocol, attack_type, severity, payload):
        """Log attack to database"""
        try:
            attack_log = AttackLog(
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol=protocol,
                attack_type=attack_type,
                severity=severity,
                payload=str(payload)[:1000] if payload else None  # Limit payload size
            )
            
            db.session.add(attack_log)
            db.session.commit()
            logger.debug(f"Attack logged: ID={attack_log.id}")
            
            return attack_log.id
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error logging attack: {e}")
            return None
    
    def start_monitoring(self):
        """Start packet sniffing and monitoring"""
        self.running = True
        logger.info("Starting honeypot monitoring...")
        
        try:
            # Start packet capturing
            # Note: In a real deployment, you'd need to specify the interface
            # and possibly use a more sophisticated approach
            sniff(prn=self._process_packet, store=0, filter="ip", iface="lo")
        except Exception as e:
            logger.error(f"Error in packet sniffing: {e}")
        finally:
            self.running = False
    
    def stop_monitoring(self):
        """Stop the monitoring"""
        self.running = False
        logger.info("Stopping honeypot monitoring...")
