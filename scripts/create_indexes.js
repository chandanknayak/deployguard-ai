/**
 * scripts/create_indexes.js — MongoDB Index Provisioning Script.
 *
 * Run with mongosh:
 *   mongosh "$MONGODB_URI" --file scripts/create_indexes.js
 */

const dbName = process.env.MONGODB_DB_NAME || "deployguard";
const db = db.getSiblingDB(dbName);

print(`🛡️  Provisioning DeployGuard AI MongoDB indexes on database: ${dbName}...`);

// ------------------------------------------------------------------
// 1. code_graph Collection Indexes (for $graphLookup speed)
// ------------------------------------------------------------------
print("Creating indexes on 'code_graph'...");
db.code_graph.createIndex({ "service_name": 1 }, { unique: true, name: "idx_service_name_unique" });
db.code_graph.createIndex({ "downstream_services": 1 }, { name: "idx_downstream_services" });
db.code_graph.createIndex({ "sla_tier": 1 }, { name: "idx_sla_tier" });
db.code_graph.createIndex({ "status": 1 }, { name: "idx_status" });

// ------------------------------------------------------------------
// 2. risk_assessments Collection Indexes (for audit log & lookup)
// ------------------------------------------------------------------
print("Creating indexes on 'risk_assessments'...");
db.risk_assessments.createIndex({ "assessment_id": 1 }, { unique: true, name: "idx_assessment_id_unique" });
db.risk_assessments.createIndex({ "repo_full_name": 1, "pr_number": 1 }, { name: "idx_repo_pr" });
db.risk_assessments.createIndex({ "risk_level": 1 }, { name: "idx_risk_level" });
db.risk_assessments.createIndex({ "created_at": -1 }, { name: "idx_created_at" });

// ------------------------------------------------------------------
// 3. incidents Collection Indexes (for metadata + vector search)
// ------------------------------------------------------------------
print("Creating indexes on 'incidents'...");
db.incidents.createIndex({ "incident_id": 1 }, { unique: true, name: "idx_incident_id_unique" });
db.incidents.createIndex({ "affected_service": 1 }, { name: "idx_affected_service" });
db.incidents.createIndex({ "severity": 1 }, { name: "idx_severity" });

print("\n✅ Standard B-Tree indexes created successfully.");
print("\n📌 ATLAS VECTOR SEARCH INDEX REQUIREMENT:");
print(`
To enable vector search on historical incidents in MongoDB Atlas:
1. Navigate to your Atlas Cluster -> Atlas Search -> Create Search Index -> JSON Editor.
2. Select database '${dbName}' and collection 'incidents'.
3. Name the index: 'incident_embedding_index'
4. Paste the following JSON definition:

{
  "fields": [
    {
      "type": "vector",
      "path": "embedding",
      "numDimensions": 1536,
      "similarity": "cosine"
    },
    {
      "type": "filter",
      "path": "affected_service"
    }
  ]
}
`);

