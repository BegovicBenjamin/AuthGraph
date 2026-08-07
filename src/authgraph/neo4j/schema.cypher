// AuthGraph's high-privacy storage model deliberately uses generic labels and
// relationship types. Sensitive semantic kinds and properties are contained
// only in authenticated ciphertext produced by the trusted application layer.
//
// Relationship property uniqueness requires Neo4j 5.7 or newer. After
// applying this file, verify the exact names, types, entity types, and
// properties with SHOW CONSTRAINTS; IF NOT EXISTS can otherwise hide a
// conflicting pre-existing name. Production Enterprise deployments should
// additionally require the expected properties with existence/key constraints.

CREATE CONSTRAINT authgraph_schema_metadata_name IF NOT EXISTS
FOR (metadata:AGSchemaMetadata)
REQUIRE metadata.name IS UNIQUE;

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

// Scoped-vault v2 keeps each private protection compartment under an
// independently random key. Scope IDs are opaque; semantic names remain in
// trusted application configuration. The v2 labels are separate so legacy
// readers cannot accidentally reinterpret scoped ciphertext.

CREATE CONSTRAINT authgraph_protection_scope_id IF NOT EXISTS
FOR (scope:AGProtectionScope)
REQUIRE scope.scope_id IS UNIQUE;

CREATE CONSTRAINT authgraph_scoped_entity_id IF NOT EXISTS
FOR (entity:AGScopedEntity)
REQUIRE entity.entity_id IS UNIQUE;

CREATE CONSTRAINT authgraph_scoped_relationship_id IF NOT EXISTS
FOR ()-[link:AG_SCOPED_LINK]-()
REQUIRE link.relationship_id IS UNIQUE;

CREATE INDEX authgraph_protection_scope_vault IF NOT EXISTS
FOR (scope:AGProtectionScope)
ON (scope.vault_id);

CREATE INDEX authgraph_scoped_entity_vault_scope IF NOT EXISTS
FOR (entity:AGScopedEntity)
ON (entity.vault_id, entity.scope_id);

CREATE INDEX authgraph_scoped_relationship_vault_scope IF NOT EXISTS
FOR ()-[link:AG_SCOPED_LINK]-()
ON (link.vault_id, link.scope_id);

// The layered graph API keeps intentionally public records in a physically
// separate storage shape. Their semantic kinds and properties are plaintext
// at AuthGraph's application-encryption layer. Never place confidential data
// in these labels merely because Neo4j itself uses TLS or disk encryption.

CREATE CONSTRAINT authgraph_public_graph_id IF NOT EXISTS
FOR (graph:AGPublicGraph)
REQUIRE graph.graph_id IS UNIQUE;

CREATE CONSTRAINT authgraph_public_entity_id IF NOT EXISTS
FOR (entity:AGPublicEntity)
REQUIRE entity.entity_id IS UNIQUE;

CREATE CONSTRAINT authgraph_public_relationship_id IF NOT EXISTS
FOR ()-[link:AG_PUBLIC_LINK]-()
REQUIRE link.relationship_id IS UNIQUE;

CREATE INDEX authgraph_public_entity_graph IF NOT EXISTS
FOR (entity:AGPublicEntity)
ON (entity.graph_id);
