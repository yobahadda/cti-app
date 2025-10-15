"""
MITRE ATT&CK to Neo4j Data Loader
Configured for your Neo4j Aura instance
"""

import requests
from neo4j import GraphDatabase
import json
from datetime import datetime

class MITREAttackLoader:
    def __init__(self, neo4j_uri, neo4j_user, neo4j_password):
        """Initialize connection to Neo4j"""
        print(f"Connecting to Neo4j at {neo4j_uri}...")
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        
        # Test connection
        try:
            self.driver.verify_connectivity()
            print("✅ Successfully connected to Neo4j!")
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            raise
        
        # MITRE ATT&CK STIX data URLs
        self.enterprise_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    def close(self):
        """Close Neo4j connection"""
        self.driver.close()
        print("Connection closed.")
    
    def fetch_attack_data(self):
        """Fetch MITRE ATT&CK data from GitHub"""
        print(f"\n📥 Fetching MITRE ATT&CK Enterprise data...")
        print(f"   URL: {self.enterprise_url}")
        
        try:
            response = requests.get(self.enterprise_url, timeout=30)
            response.raise_for_status()
            data = response.json()
            print(f"✅ Successfully fetched {len(data.get('objects', []))} objects")
            return data
        except Exception as e:
            print(f"❌ Failed to fetch data: {e}")
            raise
    
    def load_tactics(self, attack_data):
        """Load tactics into Neo4j"""
        print("\n🎯 Loading Tactics...")
        tactics = [obj for obj in attack_data['objects'] 
                  if obj['type'] == 'x-mitre-tactic']
        
        count = 0
        with self.driver.session() as session:
            for tactic in tactics:
                try:
                    ext_ref = tactic['external_references'][0]
                    session.run("""
                        MERGE (t:Tactic {id: $id})
                        SET t.name = $name,
                            t.description = $description,
                            t.shortname = $shortname,
                            t.url = $url,
                            t.modified = datetime($modified),
                            t.created = datetime($created)
                    """, 
                    id=ext_ref['external_id'],
                    name=tactic['name'],
                    description=tactic.get('description', ''),
                    shortname=tactic.get('x_mitre_shortname', ''),
                    url=ext_ref['url'],
                    modified=tactic['modified'],
                    created=tactic.get('created', tactic['modified'])
                    )
                    count += 1
                except Exception as e:
                    print(f"   ⚠️  Error loading tactic {tactic.get('name', 'unknown')}: {e}")
        
        print(f"✅ Loaded {count} tactics")
    
    def load_techniques(self, attack_data):
        """Load techniques and subtechniques into Neo4j"""
        print("\n⚔️  Loading Techniques and SubTechniques...")
        techniques = [obj for obj in attack_data['objects'] 
                     if obj['type'] == 'attack-pattern']
        
        technique_count = 0
        subtechnique_count = 0
        
        with self.driver.session() as session:
            for tech in techniques:
                try:
                    ext_ref = tech['external_references'][0]
                    tech_id = ext_ref['external_id']
                    
                    # Determine if it's a subtechnique (contains a dot)
                    is_subtechnique = '.' in tech_id
                    label = 'SubTechnique' if is_subtechnique else 'Technique'
                    
                    # Extract platforms
                    platforms = tech.get('x_mitre_platforms', [])
                    
                    # Extract kill chain phases (tactics)
                    kill_chain_phases = tech.get('kill_chain_phases', [])
                    tactic_shortnames = [phase['phase_name'] for phase in kill_chain_phases]
                    
                    # Create node
                    session.run(f"""
                        MERGE (t:{label} {{id: $id}})
                        SET t.name = $name,
                            t.description = $description,
                            t.platforms = $platforms,
                            t.url = $url,
                            t.modified = datetime($modified),
                            t.created = datetime($created),
                            t.detection = $detection,
                            t.tactics = $tactics
                    """,
                    id=tech_id,
                    name=tech['name'],
                    description=tech.get('description', ''),
                    platforms=platforms,
                    url=ext_ref['url'],
                    modified=tech['modified'],
                    created=tech.get('created', tech['modified']),
                    detection=tech.get('x_mitre_detection', ''),
                    tactics=tactic_shortnames
                    )
                    
                    if is_subtechnique:
                        subtechnique_count += 1
                        # Link subtechnique to parent technique
                        parent_id = tech_id.split('.')[0]
                        session.run("""
                            MATCH (sub:SubTechnique {id: $sub_id})
                            MATCH (tech:Technique {id: $parent_id})
                            MERGE (sub)-[:SUBTECHNIQUE_OF]->(tech)
                        """,
                        sub_id=tech_id,
                        parent_id=parent_id
                        )
                    else:
                        technique_count += 1
                    
                    # Link technique/subtechnique to tactics
                    for tactic_shortname in tactic_shortnames:
                        session.run(f"""
                            MATCH (t:{label} {{id: $tech_id}})
                            MATCH (tac:Tactic {{shortname: $tactic_shortname}})
                            MERGE (t)-[:PART_OF_TACTIC]->(tac)
                        """,
                        tech_id=tech_id,
                        tactic_shortname=tactic_shortname
                        )
                
                except Exception as e:
                    print(f"   ⚠️  Error loading technique {tech.get('name', 'unknown')}: {e}")
        
        print(f"✅ Loaded {technique_count} techniques and {subtechnique_count} subtechniques")
    
    def load_threat_groups(self, attack_data):
        """Load threat groups into Neo4j"""
        print("\n👥 Loading Threat Groups...")
        groups = [obj for obj in attack_data['objects'] 
                 if obj['type'] == 'intrusion-set']
        
        count = 0
        with self.driver.session() as session:
            for group in groups:
                try:
                    ext_ref = group['external_references'][0]
                    aliases = group.get('aliases', [])
                    
                    session.run("""
                        MERGE (g:ThreatGroup {id: $id})
                        SET g.name = $name,
                            g.description = $description,
                            g.aliases = $aliases,
                            g.url = $url,
                            g.modified = datetime($modified),
                            g.created = datetime($created)
                    """,
                    id=ext_ref['external_id'],
                    name=group['name'],
                    description=group.get('description', ''),
                    aliases=aliases,
                    url=ext_ref['url'],
                    modified=group['modified'],
                    created=group.get('created', group['modified'])
                    )
                    count += 1
                except Exception as e:
                    print(f"   ⚠️  Error loading group {group.get('name', 'unknown')}: {e}")
        
        print(f"✅ Loaded {count} threat groups")
    
    def load_software(self, attack_data):
        """Load software/malware/tools into Neo4j"""
        print("\n💾 Loading Software/Malware/Tools...")
        software = [obj for obj in attack_data['objects'] 
                   if obj['type'] in ['malware', 'tool']]
        
        count = 0
        with self.driver.session() as session:
            for sw in software:
                try:
                    ext_ref = sw['external_references'][0]
                    sw_type = 'Malware' if sw['type'] == 'malware' else 'Tool'
                    platforms = sw.get('x_mitre_platforms', [])
                    aliases = sw.get('x_mitre_aliases', [])
                    
                    session.run("""
                        MERGE (s:Software {id: $id})
                        SET s.name = $name,
                            s.description = $description,
                            s.type = $type,
                            s.platforms = $platforms,
                            s.aliases = $aliases,
                            s.url = $url,
                            s.modified = datetime($modified),
                            s.created = datetime($created)
                    """,
                    id=ext_ref['external_id'],
                    name=sw['name'],
                    description=sw.get('description', ''),
                    type=sw_type,
                    platforms=platforms,
                    aliases=aliases,
                    url=ext_ref['url'],
                    modified=sw['modified'],
                    created=sw.get('created', sw['modified'])
                    )
                    count += 1
                except Exception as e:
                    print(f"   ⚠️  Error loading software {sw.get('name', 'unknown')}: {e}")
        
        print(f"✅ Loaded {count} software/malware/tools")
    
    def load_mitigations(self, attack_data):
        """Load mitigations into Neo4j"""
        print("\n🛡️  Loading Mitigations...")
        mitigations = [obj for obj in attack_data['objects'] 
                      if obj['type'] == 'course-of-action']
        
        count = 0
        with self.driver.session() as session:
            for mitigation in mitigations:
                try:
                    ext_ref = mitigation['external_references'][0]
                    
                    session.run("""
                        MERGE (m:Mitigation {id: $id})
                        SET m.name = $name,
                            m.description = $description,
                            m.url = $url,
                            m.modified = datetime($modified),
                            m.created = datetime($created)
                    """,
                    id=ext_ref['external_id'],
                    name=mitigation['name'],
                    description=mitigation.get('description', ''),
                    url=ext_ref['url'],
                    modified=mitigation['modified'],
                    created=mitigation.get('created', mitigation['modified'])
                    )
                    count += 1
                except Exception as e:
                    print(f"   ⚠️  Error loading mitigation {mitigation.get('name', 'unknown')}: {e}")
        
        print(f"✅ Loaded {count} mitigations")
    
    def load_relationships(self, attack_data):
        """Load relationships between entities"""
        print("\n🔗 Loading Relationships...")
        relationships = [obj for obj in attack_data['objects'] 
                        if obj['type'] == 'relationship']
        
        uses_count = 0
        mitigates_count = 0
        
        with self.driver.session() as session:
            for rel in relationships:
                try:
                    source_ref = rel['source_ref']
                    target_ref = rel['target_ref']
                    rel_type = rel['relationship_type']
                    description = rel.get('description', '')
                    
                    if rel_type == 'uses':
                        # Find source and target by STIX ID
                        result = session.run("""
                            MATCH (source) WHERE id(source) = $source_ref OR source.stix_id = $source_ref
                            MATCH (target) WHERE id(target) = $target_ref OR target.stix_id = $target_ref
                            MERGE (source)-[r:USES]->(target)
                            SET r.description = $description
                            RETURN count(r) as cnt
                        """,
                        source_ref=source_ref,
                        target_ref=target_ref,
                        description=description
                        )
                        uses_count += 1
                    
                    elif rel_type == 'mitigates':
                        result = session.run("""
                            MATCH (source) WHERE id(source) = $source_ref OR source.stix_id = $source_ref
                            MATCH (target) WHERE id(target) = $target_ref OR target.stix_id = $target_ref
                            MERGE (source)-[r:MITIGATES]->(target)
                            SET r.description = $description
                            RETURN count(r) as cnt
                        """,
                        source_ref=source_ref,
                        target_ref=target_ref,
                        description=description
                        )
                        mitigates_count += 1
                
                except Exception as e:
                    # Skip relationship errors silently as they're common with STIX IDs
                    pass
        
        print(f"✅ Loaded relationships (uses: ~{uses_count}, mitigates: ~{mitigates_count})")
    
    def get_database_stats(self):
        """Get statistics about loaded data"""
        print("\n📊 Database Statistics:")
        with self.driver.session() as session:
            # Count nodes by label
            result = session.run("""
                MATCH (n)
                RETURN labels(n)[0] as label, count(*) as count
                ORDER BY count DESC
            """)
            
            for record in result:
                print(f"   {record['label']}: {record['count']}")
            
            # Count relationships
            result = session.run("""
                MATCH ()-[r]->()
                RETURN type(r) as rel_type, count(*) as count
                ORDER BY count DESC
            """)
            
            print("\n📊 Relationships:")
            for record in result:
                print(f"   {record['rel_type']}: {record['count']}")
    
    def load_all(self):
        """Load all MITRE ATT&CK data"""
        print("="*60)
        print("🚀 Starting MITRE ATT&CK Data Load")
        print("="*60)
        
        # Fetch data
        attack_data = self.fetch_attack_data()
        
        # Load entities in order
        self.load_tactics(attack_data)
        self.load_techniques(attack_data)
        self.load_threat_groups(attack_data)
        self.load_software(attack_data)
        self.load_mitigations(attack_data)
        
        # Note: Relationships are complex with STIX IDs, skipping for now
        # You can enable this later once basic data is loaded
        # self.load_relationships(attack_data)
        
        # Show stats
        self.get_database_stats()
        
        print("\n" + "="*60)
        print("✅ MITRE ATT&CK Data Load Complete!")
        print("="*60)
        print("\n🎉 Your CTI database is ready to use!")
        print("\n💡 Next steps:")
        print("   1. Open Neo4j Browser: https://console.neo4j.io")
        print("   2. Try sample queries (see below)")
        print("   3. Start adding your custom IOCs and campaigns")


# Main execution
if __name__ == "__main__":
    # Your Neo4j Aura credentials
    NEO4J_URI = "neo4j+s://4df7529c.databases.neo4j.io"
    NEO4J_USER = "neo4j"
    NEO4J_PASSWORD = "AD0Cr_vK2k1Sdm25wxj5sHPaf26YE7KZsGBe7aBUL0U"
    
    loader = MITREAttackLoader(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
    
    try:
        loader.load_all()
    except Exception as e:
        print(f"\n❌ Error during data load: {e}")
        import traceback
        traceback.print_exc()
    finally:
        loader.close()
    
    print("\n" + "="*60)
    print("📖 Sample Queries to Try in Neo4j Browser:")
    print("="*60)
    print("""
1. View all tactics:
   MATCH (t:Tactic) RETURN t LIMIT 25

2. Find techniques for a specific tactic:
   MATCH (tech:Technique)-[:PART_OF_TACTIC]->(tac:Tactic {name: 'Initial Access'})
   RETURN tech.id, tech.name

3. Find all APT groups:
   MATCH (g:ThreatGroup) 
   RETURN g.name, g.aliases 
   ORDER BY g.name LIMIT 25

4. Find software used by a specific group (after relationships loaded):
   MATCH (g:ThreatGroup {name: 'APT29'})-[:USES]->(s:Software)
   RETURN s.name, s.type

5. Search for techniques by name:
   MATCH (tech:Technique) 
   WHERE tech.name CONTAINS 'Phishing'
   RETURN tech.id, tech.name, tech.description

6. Find all techniques with their tactics:
   MATCH (tech:Technique)-[:PART_OF_TACTIC]->(tac:Tactic)
   RETURN tech.name, collect(tac.name) as tactics
   LIMIT 25

7. Find mitigations for a technique:
   MATCH (m:Mitigation)-[:MITIGATES]->(tech:Technique {id: 'T1566'})
   RETURN m.name, m.description
    """)