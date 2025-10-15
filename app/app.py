
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional
from neo4j import GraphDatabase
from datetime import datetime
import os
from dotenv import load_dotenv
load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USER = os.getenv("NEO4J_USER")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
class Database:
    def __init__(self):
        self.driver = GraphDatabase.driver(
            NEO4J_URI,
            auth=(NEO4J_USER,NEO4J_PASSWORD)
        )
    
    def query(self,cypher: str,params:dict=None):
        with self.driver.session() as session:
            result = session.run(cypher,params or {})
            return [record.data() for record in result]
    
    def close(self):
        self.drive.close()



db  = Database()
## models 

class HealthResponse(BaseModel):
    status: str
    database: str
    timestamp: str

class Tactic(BaseModel):
    id: str
    name: str
    description: Optional[str] = None

class Technique(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    platforms: List[str] = []

class ThreatGroup(BaseModel):
    id: str
    name: str
    aliases: List[str] = []

class Software(BaseModel):
    id: str
    name: str
    type: Optional[str] = None

class IOC(BaseModel):
    id: str
    type: str
    value: str
    confidence: Optional[str] = None

class IOCCreate(BaseModel):
    type: str = Field(..., description="Type: ip-address, domain, file-hash, email, url")
    value: str
    confidence: str = "medium"
    tlp: str = "AMBER"


app = FastAPI(
    title="MITRE ATT&CK CTI API",
    description="Simple CTI database API with filters",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health", response_model=HealthResponse)
def health_check():
    """Health check endpoint"""
    try:
        db.query("RETURN 1")
        db_status = "connected"
    except:
        db_status = "disconnected"
    
    return {
        "status": "healthy" if db_status == "connected" else "unhealthy",
        "database": db_status,
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/")
def root():
    """API information"""
    return {
        "name": "MITRE ATT&CK CTI API",
        "version": "1.0.0",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "tactics": "/tactics",
            "techniques": "/techniques",
            "groups": "/groups",
            "software": "/software",
            "iocs": "/iocs"
        }
    }

# ====================================
# Tactics Endpoints
# ====================================

@app.get("/tactics", response_model=List[Tactic])
def get_tactics():
    """Get all tactics"""
    query = """
    MATCH (t:Tactic)
    RETURN t.id as id, t.name as name, t.description as description
    ORDER BY t.id
    """
    results = db.query(query)
    return results

@app.get("/tactics/{tactic_id}/techniques", response_model=List[Technique])
def get_tactic_techniques(tactic_id: str):
    """Get techniques for a specific tactic"""
    query = """
    MATCH (tech:Technique)-[:PART_OF_TACTIC]->(tac:Tactic {id: $tactic_id})
    RETURN tech.id as id, tech.name as name, 
           tech.description as description, tech.platforms as platforms
    ORDER BY tech.id
    """
    results = db.query(query, {"tactic_id": tactic_id})
    if not results:
        raise HTTPException(status_code=404, detail="Tactic not found")
    return results

# ====================================
# Techniques Endpoints with Filters
# ====================================

@app.get("/techniques", response_model=List[Technique])
def get_techniques(
    platform: Optional[str] = Query(None, description="Filter by platform (Windows, Linux, macOS)"),
    tactic: Optional[str] = Query(None, description="Filter by tactic name"),
    search: Optional[str] = Query(None, description="Search in name or description"),
    limit: int = Query(50, ge=1, le=500)
):
    """
    Get techniques with optional filters
    
    - **platform**: Filter by platform (e.g., Windows, Linux, macOS)
    - **tactic**: Filter by tactic name
    - **search**: Search in technique name or description
    - **limit**: Maximum number of results
    """
    # Base query
    query = "MATCH (tech:Technique) "
    
    # Add tactic filter
    if tactic:
        query += "MATCH (tech)-[:PART_OF_TACTIC]->(tac:Tactic) WHERE toLower(tac.name) CONTAINS toLower($tactic) "
    
    # Add platform filter
    conditions = []
    if platform:
        conditions.append("$platform IN tech.platforms")
    
    # Add search filter
    if search:
        conditions.append("(toLower(tech.name) CONTAINS toLower($search) OR toLower(tech.description) CONTAINS toLower($search))")
    
    if conditions:
        query += ("WHERE " if "WHERE" not in query else "AND ") + " AND ".join(conditions) + " "
    
    query += """
    RETURN DISTINCT tech.id as id, tech.name as name, 
           tech.description as description, tech.platforms as platforms
    ORDER BY tech.id
    LIMIT $limit
    """
    
    params = {"limit": limit}
    if platform:
        params["platform"] = platform
    if tactic:
        params["tactic"] = tactic
    if search:
        params["search"] = search
    
    results = db.query(query, params)
    return results

@app.get("/techniques/{technique_id}", response_model=Technique)
def get_technique(technique_id: str):
    """Get a specific technique by ID"""
    query = """
    MATCH (tech:Technique {id: $technique_id})
    RETURN tech.id as id, tech.name as name,
           tech.description as description, tech.platforms as platforms
    """
    results = db.query(query, {"technique_id": technique_id})
    if not results:
        raise HTTPException(status_code=404, detail="Technique not found")
    return results[0]

# ====================================
# Threat Groups Endpoints with Filters
# ====================================

@app.get("/groups", response_model=List[ThreatGroup])
def get_groups(
    search: Optional[str] = Query(None, description="Search in group name or aliases"),
    technique: Optional[str] = Query(None, description="Filter by technique ID they use"),
    limit: int = Query(50, ge=1, le=500)
):
    """
    Get threat groups with optional filters
    
    - **search**: Search in group name or aliases
    - **technique**: Filter groups that use specific technique
    - **limit**: Maximum number of results
    """
    query = "MATCH (g:ThreatGroup) "
    
    # Add technique filter
    if technique:
        query += "MATCH (g)-[:USES]->(tech:Technique {id: $technique}) "
    
    # Add search filter
    if search:
        query += """
        WHERE toLower(g.name) CONTAINS toLower($search) 
           OR ANY(alias IN g.aliases WHERE toLower(alias) CONTAINS toLower($search)) 
        """
    
    query += """
    RETURN DISTINCT g.id as id, g.name as name, g.aliases as aliases
    ORDER BY g.name
    LIMIT $limit
    """
    
    params = {"limit": limit}
    if search:
        params["search"] = search
    if technique:
        params["technique"] = technique
    
    results = db.query(query, params)
    return results

@app.get("/groups/{group_id}", response_model=ThreatGroup)
def get_group(group_id: str):
    """Get a specific threat group by ID"""
    query = """
    MATCH (g:ThreatGroup {id: $group_id})
    RETURN g.id as id, g.name as name, g.aliases as aliases
    """
    results = db.query(query, {"group_id": group_id})
    if not results:
        raise HTTPException(status_code=404, detail="Threat group not found")
    return results[0]

@app.get("/groups/{group_id}/techniques", response_model=List[Technique])
def get_group_techniques(group_id: str):
    """Get techniques used by a threat group"""
    query = """
    MATCH (g:ThreatGroup {id: $group_id})-[:USES]->(tech)
    WHERE tech:Technique OR tech:SubTechnique
    RETURN tech.id as id, tech.name as name,
           tech.description as description, tech.platforms as platforms
    ORDER BY tech.id
    """
    results = db.query(query, {"group_id": group_id})
    if not results:
        raise HTTPException(status_code=404, detail="Threat group not found or no techniques")
    return results

# ====================================
# Software Endpoints with Filters
# ====================================

@app.get("/software", response_model=List[Software])
def get_software(
    type: Optional[str] = Query(None, description="Filter by type (Malware or Tool)"),
    platform: Optional[str] = Query(None, description="Filter by platform"),
    search: Optional[str] = Query(None, description="Search in software name"),
    limit: int = Query(50, ge=1, le=500)
):
    """
    Get software/malware/tools with optional filters
    
    - **type**: Filter by type (Malware or Tool)
    - **platform**: Filter by platform
    - **search**: Search in software name
    - **limit**: Maximum number of results
    """
    query = "MATCH (s:Software) "
    
    conditions = []
    if type:
        conditions.append("s.type = $type")
    if platform:
        conditions.append("$platform IN s.platforms")
    if search:
        conditions.append("toLower(s.name) CONTAINS toLower($search)")
    
    if conditions:
        query += "WHERE " + " AND ".join(conditions) + " "
    
    query += """
    RETURN s.id as id, s.name as name, s.type as type
    ORDER BY s.name
    LIMIT $limit
    """
    
    params = {"limit": limit}
    if type:
        params["type"] = type
    if platform:
        params["platform"] = platform
    if search:
        params["search"] = search
    
    results = db.query(query, params)
    return results

# ====================================
# IOCs Endpoints with Filters
# ====================================

@app.get("/iocs", response_model=List[IOC])
def get_iocs(
    type: Optional[str] = Query(None, description="Filter by IOC type"),
    confidence: Optional[str] = Query(None, description="Filter by confidence level"),
    limit: int = Query(100, ge=1, le=1000)
):
    """
    Get IOCs with optional filters
    
    - **type**: Filter by IOC type (ip-address, domain, file-hash, etc.)
    - **confidence**: Filter by confidence level (low, medium, high)
    - **limit**: Maximum number of results
    """
    query = "MATCH (ioc:IOC) "
    
    conditions = []
    if type:
        conditions.append("ioc.type = $type")
    if confidence:
        conditions.append("ioc.confidence = $confidence")
    
    if conditions:
        query += "WHERE " + " AND ".join(conditions) + " "
    
    query += """
    RETURN ioc.id as id, ioc.type as type, ioc.value as value, ioc.confidence as confidence
    ORDER BY ioc.first_seen DESC
    LIMIT $limit
    """
    
    params = {"limit": limit}
    if type:
        params["type"] = type
    if confidence:
        params["confidence"] = confidence
    
    results = db.query(query, params)
    return results

@app.post("/iocs", response_model=IOC)
def create_ioc(ioc: IOCCreate):
    """Create a new IOC"""
    query = """
    CREATE (ioc:IOC {
        id: randomUUID(),
        type: $type,
        value: $value,
        confidence: $confidence,
        tlp: $tlp,
        first_seen: datetime()
    })
    RETURN ioc.id as id, ioc.type as type, ioc.value as value, ioc.confidence as confidence
    """
    
    results = db.query(query, {
        "type": ioc.type,
        "value": ioc.value,
        "confidence": ioc.confidence,
        "tlp": ioc.tlp
    })
    
    return results[0]

# ====================================
# Search Endpoint
# ====================================

@app.get("/search")
def search(q: str = Query(..., min_length=2, description="Search query")):
    """
    Global search across techniques, groups, and software
    
    - **q**: Search query (minimum 2 characters)
    """
    query = """
    CALL {
        MATCH (tech:Technique)
        WHERE toLower(tech.name) CONTAINS toLower($q) 
           OR toLower(tech.description) CONTAINS toLower($q)
        RETURN 'Technique' as type, tech.id as id, tech.name as name
        LIMIT 10
        UNION
        MATCH (g:ThreatGroup)
        WHERE toLower(g.name) CONTAINS toLower($q)
        RETURN 'ThreatGroup' as type, g.id as id, g.name as name
        LIMIT 10
        UNION
        MATCH (s:Software)
        WHERE toLower(s.name) CONTAINS toLower($q)
        RETURN 'Software' as type, s.id as id, s.name as name
        LIMIT 10
    }
    RETURN type, id, name
    ORDER BY type, name
    LIMIT 30
    """
    
    results = db.query(query, {"q": q})
    return {"query": q, "results": results, "total": len(results)}

# ====================================
# Statistics Endpoint
# ====================================

@app.get("/stats")
def get_stats():
    """Get database statistics"""
    stats_query = """
    MATCH (n)
    RETURN labels(n)[0] as label, count(*) as count
    ORDER BY count DESC
    """
    
    results = db.query(stats_query)
    
    return {
        "total_nodes": sum(r["count"] for r in results),
        "breakdown": results
    }

# ====================================
# Shutdown Event
# ====================================

@app.on_event("shutdown")
def shutdown_event():
    db.close()

# ====================================
# Run Server
# ====================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)