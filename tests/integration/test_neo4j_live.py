"""Opt-in live Neo4j checks.

Run only against a disposable or explicitly approved database:

    AUTHGRAPH_RUN_NEO4J_TESTS=1 \
    AUTHGRAPH_TEST_NEO4J_URI=neo4j+ssc://... \
    AUTHGRAPH_TEST_NEO4J_USERNAME=... \
    AUTHGRAPH_TEST_NEO4J_PASSWORD_FILE=/run/secrets/neo4j-password \
    AUTHGRAPH_TEST_NEO4J_DATABASE=neo4j \
    python -m unittest discover -s tests/integration -v

Set AUTHGRAPH_TEST_APPLY_SCHEMA=1 only when the test account is allowed to
install AuthGraph's packaged schema. Otherwise the suite verifies it read-only.
"""

from __future__ import annotations

import os
import unittest
import uuid
from pathlib import Path


RUN_LIVE = os.environ.get("AUTHGRAPH_RUN_NEO4J_TESTS") == "1"


@unittest.skipUnless(
    RUN_LIVE,
    "set AUTHGRAPH_RUN_NEO4J_TESTS=1 for live Neo4j tests",
)
class LiveNeo4jTests(unittest.TestCase):
    driver: object
    database: str

    @classmethod
    def setUpClass(cls) -> None:
        required = {
            "AUTHGRAPH_TEST_NEO4J_URI": os.environ.get(
                "AUTHGRAPH_TEST_NEO4J_URI"
            ),
            "AUTHGRAPH_TEST_NEO4J_USERNAME": os.environ.get(
                "AUTHGRAPH_TEST_NEO4J_USERNAME"
            ),
            "AUTHGRAPH_TEST_NEO4J_PASSWORD_FILE": os.environ.get(
                "AUTHGRAPH_TEST_NEO4J_PASSWORD_FILE"
            ),
            "AUTHGRAPH_TEST_NEO4J_DATABASE": os.environ.get(
                "AUTHGRAPH_TEST_NEO4J_DATABASE"
            ),
        }
        missing = tuple(name for name, value in required.items() if not value)
        if missing:
            raise RuntimeError(
                "Missing live Neo4j test configuration: "
                + ", ".join(missing)
            )

        from neo4j import GraphDatabase

        from authgraph.cli import _validated_uri
        from authgraph.neo4j_schema import apply_schema, verify_schema

        uri = _validated_uri(required["AUTHGRAPH_TEST_NEO4J_URI"])
        username = required["AUTHGRAPH_TEST_NEO4J_USERNAME"]
        password_path = Path(
            required["AUTHGRAPH_TEST_NEO4J_PASSWORD_FILE"] or ""
        )
        if not password_path.is_file() or password_path.stat().st_size > 65536:
            raise RuntimeError(
                "Live Neo4j password file must be a small regular file."
            )
        password = password_path.read_text(encoding="utf-8")
        if password.endswith("\r\n"):
            password = password[:-2]
        elif password.endswith("\n"):
            password = password[:-1]
        if not password:
            raise RuntimeError("Live Neo4j password file is empty.")

        cls.database = required["AUTHGRAPH_TEST_NEO4J_DATABASE"] or ""
        cls.driver = GraphDatabase.driver(
            uri,
            auth=(username, password),
        )
        password = ""
        try:
            cls.driver.verify_connectivity()
            if os.environ.get("AUTHGRAPH_TEST_APPLY_SCHEMA") == "1":
                apply_schema(cls.driver, database=cls.database)
                apply_schema(cls.driver, database=cls.database)
            else:
                verify_schema(cls.driver, database=cls.database)
        except Exception:
            cls.driver.close()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        cls.driver.close()

    def setUp(self) -> None:
        self.created_vaults: list[tuple[str, str]] = []
        self.sessions: list[object] = []

    def tearDown(self) -> None:
        for sessions in self.sessions:
            sessions.close_all()
        for principal_id, vault_id in reversed(self.created_vaults):
            self._delete_exact_vault(principal_id, vault_id)

    def _delete_exact_vault(
        self,
        principal_id: str,
        vault_id: str,
    ) -> None:
        # Never clear a whole database. Cleanup is rooted at the exact random
        # test principal and exact service-generated vault ID.
        parameters = {
            "principal_id": principal_id,
            "vault_id": vault_id,
        }
        queries = (
            """
            MATCH (vault:AGVault {
                principal_id: $principal_id,
                vault_id: $vault_id
            })-[:AG_HAS_SCOPE]->(:AGProtectionScope)
              -[:AG_PROTECTS]->(entity:AGScopedEntity)
            DETACH DELETE entity
            """,
            """
            MATCH (vault:AGVault {
                principal_id: $principal_id,
                vault_id: $vault_id
            })-[:AG_HAS_SCOPE]->(scope:AGProtectionScope)
            DETACH DELETE scope
            """,
            """
            MATCH (vault:AGVault {
                principal_id: $principal_id,
                vault_id: $vault_id
            })
            DETACH DELETE vault
            """,
        )
        for query in queries:
            self.driver.execute_query(
                query,
                parameters_=parameters,
                database_=self.database,
            )

    def test_scoped_round_trip_is_ciphertext_only_and_owner_scoped(
        self,
    ) -> None:
        from authgraph.crypto import CryptoEngine
        from authgraph.errors import ConflictError, RecordNotFound
        from authgraph.models import KdfParameters
        from authgraph.neo4j_scoped_repository import (
            Neo4jScopedGraphRepository,
        )
        from authgraph.scoped_service import ScopedAuthGraphService
        from authgraph.scoped_sessions import ScopedSessionBroker

        repository = Neo4jScopedGraphRepository(
            self.driver,
            database=self.database,
        )
        crypto = CryptoEngine(
            KdfParameters.insecure_for_testing(),
            allow_insecure_kdf_for_testing=True,
        )
        sessions = ScopedSessionBroker(
            default_ttl_seconds=30,
            max_ttl_seconds=30,
            sweep_interval_seconds=None,
        )
        self.sessions.append(sessions)
        service = ScopedAuthGraphService(repository, crypto, sessions)

        run_id = uuid.uuid4().hex
        principal = f"idp|authgraph-live|{run_id}|owner"
        other_principal = f"idp|authgraph-live|{run_id}|other"
        passphrase = bytearray(b"synthetic-live-passphrase-owner")
        other_passphrase = bytearray(b"synthetic-live-passphrase-other")

        vault_id = service.create_vault(principal, passphrase)
        self.created_vaults.append((principal, vault_id))
        scope_id = service.create_protection_scope(
            principal,
            vault_id,
            passphrase,
        )
        context = service.unlock(
            principal,
            vault_id,
            passphrase,
            (scope_id,),
        )
        sentinel = f"must-stay-encrypted-{run_id}"
        first_entity = service.create_entity(
            context,
            scope_id,
            "CustomerProfile",
            {"private_value": sentinel},
            idempotency_key=f"entity-profile-{run_id}",
        )
        self.assertEqual(
            service.create_entity(
                context,
                scope_id,
                "CustomerProfile",
                {"private_value": sentinel},
                idempotency_key=f"entity-profile-{run_id}",
            ),
            first_entity,
        )
        second_entity = service.create_entity(
            context,
            scope_id,
            "Order",
            {"order_number": f"ORDER-{run_id}"},
            idempotency_key=f"entity-order-{run_id}",
        )
        relationship_id = service.connect(
            context,
            scope_id,
            first_entity,
            second_entity,
            "PLACED",
            {"private_note": sentinel},
            idempotency_key=f"relationship-placed-{run_id}",
        )
        self.assertEqual(
            service.connect(
                context,
                scope_id,
                first_entity,
                second_entity,
                "PLACED",
                {"private_note": sentinel},
                idempotency_key=f"relationship-placed-{run_id}",
            ),
            relationship_id,
        )
        self.assertEqual(
            service.get_entity(context, first_entity).properties[
                "private_value"
            ],
            sentinel,
        )
        with self.assertRaises(ConflictError):
            service.create_entity(
                context,
                scope_id,
                "CustomerProfile",
                {"private_value": "different"},
                idempotency_key=f"entity-profile-{run_id}",
            )

        entity_result = self.driver.execute_query(
            """
            MATCH (vault:AGVault {
                principal_id: $principal_id,
                vault_id: $vault_id
            })-[:AG_HAS_SCOPE]->(:AGProtectionScope)
              -[:AG_PROTECTS]->(entity:AGScopedEntity {
                  entity_id: $entity_id
              })
            RETURN
                labels(entity) AS labels,
                keys(entity) AS property_keys,
                entity.ciphertext AS ciphertext
            """,
            parameters_={
                "principal_id": principal,
                "vault_id": vault_id,
                "entity_id": first_entity,
            },
            database_=self.database,
        )
        entity_record = entity_result.records[0]
        self.assertEqual(set(entity_record["labels"]), {"AGScopedEntity"})
        self.assertNotIn("kind", entity_record["property_keys"])
        self.assertNotIn("properties", entity_record["property_keys"])
        self.assertNotIn("properties_json", entity_record["property_keys"])
        self.assertNotIn(
            sentinel.encode("utf-8"),
            bytes(entity_record["ciphertext"]),
        )

        relationship_result = self.driver.execute_query(
            """
            MATCH (:AGScopedEntity {entity_id: $from_entity_id})
              -[link:AG_SCOPED_LINK {
                  relationship_id: $relationship_id
              }]->
              (:AGScopedEntity {entity_id: $to_entity_id})
            RETURN
                type(link) AS relationship_type,
                keys(link) AS property_keys,
                link.ciphertext AS ciphertext
            """,
            parameters_={
                "from_entity_id": first_entity,
                "to_entity_id": second_entity,
                "relationship_id": relationship_id,
            },
            database_=self.database,
        )
        relationship_record = relationship_result.records[0]
        self.assertEqual(
            relationship_record["relationship_type"],
            "AG_SCOPED_LINK",
        )
        self.assertNotIn("kind", relationship_record["property_keys"])
        self.assertNotIn(
            sentinel.encode("utf-8"),
            bytes(relationship_record["ciphertext"]),
        )

        other_vault = service.create_vault(
            other_principal,
            other_passphrase,
        )
        self.created_vaults.append((other_principal, other_vault))
        other_scope = service.create_protection_scope(
            other_principal,
            other_vault,
            other_passphrase,
        )
        other_context = service.unlock(
            other_principal,
            other_vault,
            other_passphrase,
            (other_scope,),
        )
        with self.assertRaises(RecordNotFound):
            service.get_entity(other_context, first_entity)

        service.lock(other_context)

        updated_entity = service.update_entity(
            context,
            first_entity,
            "CustomerProfile",
            {"private_value": sentinel, "status": "updated"},
            expected_revision=1,
        )
        self.assertEqual(updated_entity.record_revision, 2)
        self.assertEqual(updated_entity.properties["status"], "updated")
        with self.assertRaises(ConflictError):
            service.update_entity(
                context,
                first_entity,
                "CustomerProfile",
                {"private_value": sentinel},
                expected_revision=1,
            )

        updated_relationship = service.update_relationship(
            context,
            relationship_id,
            "PLACED",
            {"private_note": sentinel, "status": "updated"},
            expected_revision=1,
        )
        self.assertEqual(updated_relationship.record_revision, 2)
        self.assertEqual(updated_relationship.properties["status"], "updated")
        service.delete_relationship(
            context,
            relationship_id,
            expected_revision=2,
        )
        with self.assertRaises(RecordNotFound):
            service.get_relationship(context, relationship_id)

        bundle_relationship, helper_ids = (
            service.create_relationship_bundle(
                context,
                scope_id,
                (("EncryptedAnchor", {"opaque_reference": run_id}),),
                first_entity,
                0,
                "REFERENCES",
                {"source": "live-test"},
            )
        )
        self.assertEqual(len(helper_ids), 1)
        bundled = service.get_relationship(
            context,
            bundle_relationship,
        )
        self.assertEqual(bundled.from_entity_id, first_entity)
        self.assertEqual(bundled.to_entity_id, helper_ids[0])
        service.delete_relationship(
            context,
            bundle_relationship,
            expected_revision=1,
        )
        service.delete_entity(
            context,
            helper_ids[0],
            expected_revision=1,
        )

        service.delete_entity(
            context,
            first_entity,
            expected_revision=2,
        )
        service.delete_entity(
            context,
            second_entity,
            expected_revision=1,
        )
        with self.assertRaises(RecordNotFound):
            service.get_entity(context, first_entity)
        service.lock(context)


if __name__ == "__main__":
    unittest.main()
