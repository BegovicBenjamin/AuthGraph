// AuthGraph's high-privacy storage model deliberately uses generic labels and
// relationship types. Sensitive semantic kinds and properties are contained
// only in authenticated ciphertext produced by the trusted application layer.
//
// Relationship property uniqueness requires Neo4j 5.7 or newer. After
// applying this file, verify the exact names, types, entity types, and
// properties with SHOW CONSTRAINTS; IF NOT EXISTS can otherwise hide a
// conflicting pre-existing name. Production Enterprise deployments should
// additionally require the expected properties with existence/key constraints.

CREATE CONSTRAINT authgraph_vault_id IF NOT EXISTS
FOR (vault:AGVault)
REQUIRE vault.vault_id IS UNIQUE;

CREATE CONSTRAINT authgraph_entity_id IF NOT EXISTS
FOR (entity:AGEntity)
REQUIRE entity.entity_id IS UNIQUE;

CREATE CONSTRAINT authgraph_relationship_id IF NOT EXISTS
FOR ()-[link:AG_LINK]-()
REQUIRE link.relationship_id IS UNIQUE;

CREATE INDEX authgraph_entity_vault IF NOT EXISTS
FOR (entity:AGEntity)
ON (entity.vault_id);

CREATE INDEX authgraph_vault_owner IF NOT EXISTS
FOR (vault:AGVault)
ON (vault.principal_id);
