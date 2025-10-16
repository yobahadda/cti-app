"""
CTI Log Correlation System
Kafka Consumer + MITRE ATT&CK Mapping + Neo4j Profiling
"""

from kafka import KafkaConsumer
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from neo4j import GraphDatabase
from datetime import datetime
import json
import re
import threading
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ====================================
# Configuration
# ====================================

KAFKA_BOOTSTRAP_SERVERS = ['localhost:9092']
KAFKA_TOPICS = ['security-logs', 'network-logs', 'edr-logs']
KAFKA_GROUP_ID = 'cti-consumer-group'

NEO4J_URI = "neo4j+s://4df7529c.databases.neo4j.io"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "AD0Cr_vK2k1Sdm25wxj5sHPaf26YE7KZsGBe7aBUL0U"

# ====================================
# Database Connection
# ====================================

class Database:
    def __init__(self):
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    
    def query(self, cypher: str, params: dict = None):
        with self.driver.session() as session:
            result = session.run(cypher, params or {})
            return [record.data() for record in result]
    
    def close(self):
        self.driver.close()

db = Database()

# ====================================
# IOC Extractor
# ====================================

class IOCExtractor:
    """Extract indicators of compromise from logs"""
    
    # Regex patterns
    IP_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    MD5_PATTERN = r'\b[a-fA-F0-9]{32}\b'
    SHA256_PATTERN = r'\b[a-fA-F0-9]{64}\b'
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    @staticmethod
    def extract_ips(text: str) -> List[str]:
        """Extract IP addresses"""
        ips = re.findall(IOCExtractor.IP_PATTERN, text)
        return list(set(ips))
    
    @staticmethod
    def extract_domains(text: str) -> List[str]:
        """Extract domain names"""
        domains = re.findall(IOCExtractor.DOMAIN_PATTERN, text)
        return list(set(domains))
    
    @staticmethod
    def extract_hashes(text: str) -> Dict[str, List[str]]:
        """Extract file hashes"""
        md5_hashes = re.findall(IOCExtractor.MD5_PATTERN, text)
        sha256_hashes = re.findall(IOCExtractor.SHA256_PATTERN, text)
        return {
            'md5': list(set(md5_hashes)),
            'sha256': list(set(sha256_hashes))
        }
    
    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """Extract email addresses"""
        emails = re.findall(IOCExtractor.EMAIL_PATTERN, text)
        return list(set(emails))
    
    @staticmethod
    def extract_all(log_text: str) -> Dict[str, List[str]]:
        """Extract all IOCs from log"""
        return {
            'ips': IOCExtractor.extract_ips(log_text),
            'domains': IOCExtractor.extract_domains(log_text),
            'hashes': IOCExtractor.extract_hashes(log_text),
            'emails': IOCExtractor.extract_emails(log_text)
        }

# ====================================
# MITRE Mapper
# ====================================

class MITREMapper:
    """Map security events to MITRE ATT&CK techniques"""
    
    # Technique mapping keywords
    TECHNIQUE_KEYWORDS = {
        'T1566': ['phishing', 'spearphishing', 'malicious email', 'attachment'],
        'T1059': ['command line', 'powershell', 'cmd.exe', 'bash', 'script execution'],
        'T1071': ['http', 'https', 'dns', 'application layer protocol'],
        'T1055': ['process injection', 'dll injection', 'code injection'],
        'T1486': ['ransomware', 'file encryption', 'encrypted files'],
        'T1083': ['file discovery', 'directory listing', 'reconnaissance'],
        'T1090': ['proxy', 'c2', 'command and control'],
        'T1078': ['valid accounts', 'compromised credentials', 'brute force'],
        'T1021': ['remote services', 'rdp', 'ssh', 'smb'],
        'T1070': ['log clearing', 'indicator removal', 'cover tracks']
    }
    
    @staticmethod
    def detect_techniques(log_data: Dict[str, Any]) -> List[str]:
        """Detect MITRE techniques from log data"""
        detected_techniques = []
        log_text = json.dumps(log_data).lower()
        
        for technique_id, keywords in MITREMapper.TECHNIQUE_KEYWORDS.items():
            if any(keyword in log_text for keyword in keywords):
                detected_techniques.append(technique_id)
        
        return detected_techniques
    
    @staticmethod
    def get_technique_details(technique_id: str) -> Optional[Dict]:
        """Get technique details from Neo4j"""
        query = """
        MATCH (tech:Technique {id: $technique_id})
        OPTIONAL MATCH (tech)-[:PART_OF_TACTIC]->(tac:Tactic)
        RETURN tech.id as id, tech.name as name, 
               tech.description as description,
               collect(tac.name) as tactics
        """
        results = db.query(query, {"technique_id": technique_id})
        return results[0] if results else None

# ====================================
# Event Processor
# ====================================

class EventProcessor:
    """Process and enrich security events"""
    
    @staticmethod
    def parse_log(raw_log: str) -> Dict[str, Any]:
        """Parse raw log to structured format"""
        try:
            return json.loads(raw_log)
        except:
            parsed = {}
            for pair in raw_log.split():
                if '=' in pair:
                    key, value = pair.split('=', 1)
                    parsed[key] = value
            return parsed
    
    @staticmethod
    def enrich_event(log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with IOCs and MITRE mapping"""
        log_text = json.dumps(log_data)
        
        # Extract IOCs
        iocs = IOCExtractor.extract_all(log_text)
        
        # Detect MITRE techniques
        techniques = MITREMapper.detect_techniques(log_data)
        
        # Build enriched event
        enriched = {
            'original_log': log_data,
            'timestamp': log_data.get('timestamp', datetime.utcnow().isoformat()),
            'source_ip': log_data.get('src_ip') or log_data.get('source_ip'),
            'destination_ip': log_data.get('dst_ip') or log_data.get('dest_ip'),
            'event_type': log_data.get('event_type') or log_data.get('action'),
            'iocs': iocs,
            'mitre_techniques': techniques,
            'severity': EventProcessor.calculate_severity(log_data, techniques)
        }
        
        return enriched
    
    @staticmethod
    def calculate_severity(log_data: Dict, techniques: List[str]) -> str:
        """Calculate event severity"""
        if len(techniques) >= 3:
            return 'critical'
        elif len(techniques) >= 1:
            return 'high'
        elif any(k in json.dumps(log_data).lower() for k in ['failed', 'denied', 'blocked']):
            return 'medium'
        else:
            return 'low'
    
    @staticmethod
    def store_event(enriched_event: Dict[str, Any]) -> str:
        """Store enriched event in Neo4j"""
        query = """
        CREATE (e:SecurityEvent {
            id: randomUUID(),
            timestamp: datetime($timestamp),
            source_ip: $source_ip,
            destination_ip: $destination_ip,
            event_type: $event_type,
            severity: $severity,
            raw_data: $raw_data
        })
        RETURN e.id as event_id
        """
        
        result = db.query(query, {
            'timestamp': enriched_event['timestamp'],
            'source_ip': enriched_event.get('source_ip'),
            'destination_ip': enriched_event.get('destination_ip'),
            'event_type': enriched_event.get('event_type'),
            'severity': enriched_event['severity'],
            'raw_data': json.dumps(enriched_event['original_log'])
        })
        
        event_id = result[0]['event_id']
        
        # Link IOCs
        EventProcessor.link_iocs(event_id, enriched_event['iocs'])
        
        # Link techniques
        EventProcessor.link_techniques(event_id, enriched_event['mitre_techniques'])
        
        return event_id
    
    @staticmethod
    def link_iocs(event_id: str, iocs: Dict[str, List[str]]):
        """Link IOCs to event"""
        for ip in iocs.get('ips', []):
            query = """
            MATCH (e:SecurityEvent {id: $event_id})
            MERGE (ioc:IOC {value: $ip, type: 'ip-address'})
            MERGE (e)-[:CONTAINS_IOC]->(ioc)
            """
            db.query(query, {'event_id': event_id, 'ip': ip})
        
        for domain in iocs.get('domains', []):
            query = """
            MATCH (e:SecurityEvent {id: $event_id})
            MERGE (ioc:IOC {value: $domain, type: 'domain'})
            MERGE (e)-[:CONTAINS_IOC]->(ioc)
            """
            db.query(query, {'event_id': event_id, 'domain': domain})
    
    @staticmethod
    def link_techniques(event_id: str, techniques: List[str]):
        """Link MITRE techniques to event"""
        for tech_id in techniques:
            query = """
            MATCH (e:SecurityEvent {id: $event_id})
            MATCH (tech:Technique {id: $tech_id})
            MERGE (e)-[:MAPPED_TO_TECHNIQUE]->(tech)
            """
            db.query(query, {'event_id': event_id, 'tech_id': tech_id})

# ====================================
# Profile Builder
# ====================================

class ProfileBuilder:
    """Build threat profiles from correlated events"""
    
    @staticmethod
    def build_ip_profile(ip_address: str) -> Dict[str, Any]:
        """Build profile for an IP address"""
        query = """
        MATCH (e:SecurityEvent)-[:CONTAINS_IOC]->(ioc:IOC {value: $ip})
        OPTIONAL MATCH (e)-[:MAPPED_TO_TECHNIQUE]->(tech:Technique)
        OPTIONAL MATCH (tech)-[:PART_OF_TACTIC]->(tac:Tactic)
        RETURN count(DISTINCT e) as event_count,
               collect(DISTINCT e.severity) as severities,
               collect(DISTINCT tech.name) as techniques,
               collect(DISTINCT tac.name) as tactics,
               min(e.timestamp) as first_seen,
               max(e.timestamp) as last_seen
        """
        
        result = db.query(query, {'ip': ip_address})
        
        if not result or result[0]['event_count'] == 0:
            return None
        
        data = result[0]
        
        threat_intel = ProfileBuilder.check_threat_intelligence(ip_address)
        
        return {
            'ip_address': ip_address,
            'event_count': data['event_count'],
            'severities': data['severities'],
            'techniques_used': [t for t in data['techniques'] if t],
            'tactics_used': [t for t in data['tactics'] if t],
            'first_seen': str(data['first_seen']),
            'last_seen': str(data['last_seen']),
            'threat_intelligence': threat_intel,
            'risk_score': ProfileBuilder.calculate_risk_score(data)
        }
    
    @staticmethod
    def check_threat_intelligence(ioc_value: str) -> Dict[str, Any]:
        """Check if IOC is associated with known threats"""
        query = """
        MATCH (ioc:IOC {value: $value})-[:ATTRIBUTED_TO]->(g:ThreatGroup)
        RETURN g.name as group_name, g.aliases as aliases
        """
        results = db.query(query, {'value': ioc_value})
        return results if results else []
    
    @staticmethod
    def calculate_risk_score(data: Dict) -> int:
        """Calculate risk score (0-100)"""
        score = 0
        score += min(data['event_count'] * 5, 30)
        
        if 'critical' in data['severities']:
            score += 40
        elif 'high' in data['severities']:
            score += 25
        elif 'medium' in data['severities']:
            score += 15
        
        score += min(len([t for t in data['techniques'] if t]) * 3, 30)
        
        return min(score, 100)
    
    @staticmethod
    def correlate_campaign() -> List[Dict]:
        """Find correlated events that may indicate a campaign"""
        query = """
        MATCH (e1:SecurityEvent)-[:CONTAINS_IOC]->(ioc)<-[:CONTAINS_IOC]-(e2:SecurityEvent)
        WHERE e1.id < e2.id
        AND duration.between(e1.timestamp, e2.timestamp).minutes < 60
        MATCH (e1)-[:MAPPED_TO_TECHNIQUE]->(tech:Technique)
        MATCH (e2)-[:MAPPED_TO_TECHNIQUE]->(tech)
        RETURN ioc.value as common_ioc,
               count(DISTINCT e1) + count(DISTINCT e2) as event_count,
               collect(DISTINCT tech.name) as common_techniques
        ORDER BY event_count DESC
        LIMIT 10
        """
        return db.query(query)

# ====================================
# Kafka Consumer
# ====================================

class CTIKafkaConsumer:
    """Kafka consumer for security logs"""
    
    def __init__(self):
        self.consumer = None
        self.running = False
    
    def start(self):
        """Start consuming messages"""
        try:
            self.consumer = KafkaConsumer(
                *KAFKA_TOPICS,
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                group_id=KAFKA_GROUP_ID,
                value_deserializer=lambda m: m.decode('utf-8'),
                auto_offset_reset='latest',
                enable_auto_commit=True
            )
            
            self.running = True
            logger.info(f"Kafka consumer started. Listening to topics: {KAFKA_TOPICS}")
            
            for message in self.consumer:
                if not self.running:
                    break
                
                try:
                    log_data = EventProcessor.parse_log(message.value)
                    enriched = EventProcessor.enrich_event(log_data)
                    event_id = EventProcessor.store_event(enriched)
                    
                    logger.info(f"Processed event {event_id} - Severity: {enriched['severity']}")
                    
                    if enriched['mitre_techniques']:
                        logger.info(f"  Techniques: {', '.join(enriched['mitre_techniques'])}")
                
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
        
        except Exception as e:
            logger.error(f"Kafka consumer error: {e}")
        finally:
            if self.consumer:
                self.consumer.close()
    
    def stop(self):
        """Stop consuming messages"""
        self.running = False
        logger.info("Kafka consumer stopped")

kafka_consumer = CTIKafkaConsumer()

# ====================================
# FastAPI Application
# ====================================

app = FastAPI(title="CTI Log Correlation API", version="1.0.0")

class LogSubmit(BaseModel):
    raw_log: str
    source: Optional[str] = "manual"

class IPProfileRequest(BaseModel):
    ip_address: str

# ====================================
# API Endpoints
# ====================================

@app.get("/health")
def health_check():
    """Health check"""
    return {
        "status": "healthy",
        "kafka_running": kafka_consumer.running,
        "database": "connected" if db.query("RETURN 1") else "disconnected",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.post("/logs/submit")
def submit_log(log: LogSubmit):
    """Manually submit a log for processing"""
    try:
        log_data = EventProcessor.parse_log(log.raw_log)
        enriched = EventProcessor.enrich_event(log_data)
        event_id = EventProcessor.store_event(enriched)
        
        return {
            "event_id": event_id,
            "severity": enriched['severity'],
            "techniques_detected": enriched['mitre_techniques'],
            "iocs_found": {
                'ips': len(enriched['iocs']['ips']),
                'domains': len(enriched['iocs']['domains'])
            }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/profile/ip")
def get_ip_profile(request: IPProfileRequest):
    """Get threat profile for an IP address"""
    profile = ProfileBuilder.build_ip_profile(request.ip_address)
    
    if not profile:
        raise HTTPException(status_code=404, detail="No data found for this IP")
    
    return profile

@app.get("/profile/campaigns")
def get_campaigns():
    """Get correlated campaigns"""
    campaigns = ProfileBuilder.correlate_campaign()
    return {
        "total_campaigns": len(campaigns),
        "campaigns": campaigns
    }

@app.get("/events/recent")
def get_recent_events(limit: int = 50):
    """Get recent security events"""
    query = """
    MATCH (e:SecurityEvent)
    OPTIONAL MATCH (e)-[:MAPPED_TO_TECHNIQUE]->(tech:Technique)
    RETURN e.id as id, e.timestamp as timestamp, e.source_ip as source_ip,
           e.destination_ip as destination_ip, e.severity as severity,
           collect(tech.name) as techniques
    ORDER BY e.timestamp DESC
    LIMIT $limit
    """
    events = db.query(query, {'limit': limit})
    return {"events": events, "total": len(events)}

@app.get("/events/by-technique/{technique_id}")
def get_events_by_technique(technique_id: str):
    """Get events mapped to a specific technique"""
    query = """
    MATCH (e:SecurityEvent)-[:MAPPED_TO_TECHNIQUE]->(tech:Technique {id: $tech_id})
    RETURN e.id as id, e.timestamp as timestamp, e.source_ip as source_ip,
           e.severity as severity
    ORDER BY e.timestamp DESC
    LIMIT 100
    """
    events = db.query(query, {'tech_id': technique_id})
    return {"technique": technique_id, "events": events, "count": len(events)}

@app.get("/statistics/dashboard")
def get_dashboard_stats():
    """Get dashboard statistics"""
    stats_query = """
    MATCH (e:SecurityEvent)
    RETURN count(e) as total_events,
           count(DISTINCT e.source_ip) as unique_ips,
           collect(DISTINCT e.severity) as severities
    """
    
    technique_query = """
    MATCH (e:SecurityEvent)-[:MAPPED_TO_TECHNIQUE]->(tech:Technique)
    RETURN tech.name as technique, count(e) as event_count
    ORDER BY event_count DESC
    LIMIT 10
    """
    
    stats = db.query(stats_query)[0]
    top_techniques = db.query(technique_query)
    
    return {
        "total_events": stats['total_events'],
        "unique_ips": stats['unique_ips'],
        "severities": stats['severities'],
        "top_techniques": top_techniques
    }

@app.on_event("startup")
def startup_event():
    """Start Kafka consumer in background"""
    def run_consumer():
        kafka_consumer.start()
    
    consumer_thread = threading.Thread(target=run_consumer, daemon=True)
    consumer_thread.start()
    logger.info("Application started. Kafka consumer running in background.")

@app.on_event("shutdown")
def shutdown_event():
    """Stop Kafka consumer"""
    kafka_consumer.stop()
    db.close()
    logger.info("Application shutdown complete")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)