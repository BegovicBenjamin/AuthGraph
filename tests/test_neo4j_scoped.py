from __future__ import annotations

import unittest
from dataclasses import replace

from authgraph.errors import IntegrityViolation
from authgraph.models import (
    EncryptedPayload,
    KdfParameters,
    KeyEnvelope,
    ProtectionScopeRow,
    ScopeKeyEnvelope,
    ScopedEncryptedEntityRow,
    ScopedEncryptedRelationshipRow,
    VaultRow,
)
from authgraph.neo4j_scoped_repository import Neo4jScopedGraphRepository


class SequencedRecordingDriver:
    encrypted = True

    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute_query(self, query: str, **kwargs: object) -> object:
        self.calls.append((query, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return type("Result", (), {"records": response})()


def vault_envelope(
    *,
    version: int = 2,
    revision: int = 1,
    key_version: int = 1,
) -> KeyEnvelope:
    return KeyEnvelope(
        version=version,
        envelope_revision=revision,
        key_version=key_version,
        wrapping_algorithm="AES-256-GCM",
        kdf=KdfParameters(),
        salt=b"s" * 16,
        nonce=b"n" * 12,
        wrapped_dek=b"w" * 48,
    )


def vault_record(
    *,
    version: object = 2,
    revision: object = 1,
    key_version: object = 1,
) -> dict[str, object]:
    return {
        "envelope_version": version,
        "envelope_revision": revision,
        "key_version": key_version,
        "wrapping_algorithm": "AES-256-GCM",
        "kdf_algorithm": "argon2id",
        "kdf_memory_cost_kib": 64 * 1024,
        "kdf_iterations": 3,
        "kdf_lanes": 1,
        "kdf_output_length": 32,
        "envelope_salt": b"s" * 16,
        "envelope_nonce": b"n" * 12,
        "wrapped_dek": b"w" * 48,
    }


def scope_envelope(*, key_version: int = 1) -> ScopeKeyEnvelope:
    return ScopeKeyEnvelope(
        version=1,
        root_key_version=1,
        scope_key_version=key_version,
        algorithm="AES-256-GCM",
        nonce=b"q" * 12,
        wrapped_scope_dek=b"k" * 48,
    )


def scope_record(
    scope_id: str = "scope_orders",
    *,
    vault_id: str = "v2_vault",
    key_version: object = 1,
) -> dict[str, object]:
    return {
        "vault_id": vault_id,
        "scope_id": scope_id,
        "scope_envelope_version": 1,
        "root_key_version": 1,
        "scope_key_version": key_version,
        "scope_wrapping_algorithm": "AES-256-GCM",
        "scope_envelope_nonce": b"q" * 12,
        "wrapped_scope_dek": b"k" * 48,
    }


def payload(*, key_version: int = 1) -> EncryptedPayload:
    return EncryptedPayload(
        version=2,
        key_version=key_version,
        algorithm="AES-256-GCM",
        nonce=b"p" * 12,
        ciphertext=b"c" * 32,
    )


def entity_record(
    entity_id: str = "scoped_entity_1",
    *,
    vault_id: str = "v2_vault",
    scope_id: str = "scope_orders",
    key_version: object = 1,
    expected_key_version: object = 1,
    record_revision: object = 1,
) -> dict[str, object]:
    return {
        "vault_id": vault_id,
        "scope_id": scope_id,
        "entity_id": entity_id,
        "record_revision": record_revision,
        "protection_scope_key_version": expected_key_version,
        "payload_version": 2,
        "key_version": key_version,
        "algorithm": "AES-256-GCM",
        "nonce": b"p" * 12,
        "ciphertext": b"c" * 32,
    }


def relationship_record(
    relationship_id: str = "scoped_relationship_1",
    *,
    vault_id: str = "v2_vault",
    scope_id: str = "scope_orders",
    from_entity_id: str = "scoped_entity_1",
    from_scope_id: str = "scope_orders",
    to_entity_id: str = "scoped_entity_2",
    to_scope_id: str = "scope_profile",
    key_version: object = 1,
    expected_key_version: object = 1,
    record_revision: object = 1,
) -> dict[str, object]:
    return {
        "vault_id": vault_id,
        "scope_id": scope_id,
        "relationship_id": relationship_id,
        "record_revision": record_revision,
        "from_entity_id": from_entity_id,
        "from_scope_id": from_scope_id,
        "to_entity_id": to_entity_id,
        "to_scope_id": to_scope_id,
        "protection_scope_key_version": expected_key_version,
        "payload_version": 2,
        "key_version": key_version,
        "algorithm": "AES-256-GCM",
        "nonce": b"p" * 12,
        "ciphertext": b"c" * 32,
    }


class Neo4jScopedRepositoryTests(unittest.TestCase):
    PRINCIPAL = "idp_subject_7f83"
    VAULT = "v2_vault"
    ALLOWED = ("scope_orders", "scope_profile")

    def repository(
        self,
        responses: list[object],
    ) -> tuple[Neo4jScopedGraphRepository, SequencedRecordingDriver]:
        driver = SequencedRecordingDriver(responses)
        return (
            Neo4jScopedGraphRepository(driver, database="authgraph"),
            driver,
        )

    def test_scoped_queries_are_fixed_owner_rooted_and_revision_fenced(
        self,
    ) -> None:
        scoped_queries = (
            Neo4jScopedGraphRepository._PUT_PROTECTION_SCOPE,
            Neo4jScopedGraphRepository._GET_PROTECTION_SCOPES,
            Neo4jScopedGraphRepository._PUT_SCOPED_ENTITY,
            Neo4jScopedGraphRepository._GET_SCOPED_ENTITY,
            Neo4jScopedGraphRepository._PUT_SCOPED_RELATIONSHIP,
            Neo4jScopedGraphRepository._PUT_SCOPED_ENTITY_RELATIONSHIP_BUNDLE,
            Neo4jScopedGraphRepository._GET_SCOPED_RELATIONSHIP,
            Neo4jScopedGraphRepository._REPLACE_SCOPED_ENTITY,
            Neo4jScopedGraphRepository._REPLACE_SCOPED_RELATIONSHIP,
            Neo4jScopedGraphRepository._DELETE_SCOPED_ENTITY,
            Neo4jScopedGraphRepository._DELETE_SCOPED_RELATIONSHIP,
            Neo4jScopedGraphRepository._GET_SCOPED_VAULT_SNAPSHOT,
        )
        for query in scoped_queries:
            with self.subTest(query=query[:60]):
                self.assertTrue(query.lstrip().startswith("MATCH (vault:AGVault"))
                self.assertIn("$principal_id", query)
                self.assertIn("$vault_id", query)
                self.assertIn("$envelope_revision", query)
                self.assertNotIn("$kind", query)
                self.assertNotIn("$properties", query)

        self.assertIn(
            "AGProtectionScope",
            Neo4jScopedGraphRepository._PUT_PROTECTION_SCOPE,
        )
        self.assertIn(
            "AGScopedEntity",
            Neo4jScopedGraphRepository._PUT_SCOPED_ENTITY,
        )
        self.assertIn(
            "AG_SCOPED_LINK",
            Neo4jScopedGraphRepository._PUT_SCOPED_RELATIONSHIP,
        )
        for query in (
            Neo4jScopedGraphRepository._GET_SCOPED_ENTITY,
            Neo4jScopedGraphRepository._PUT_SCOPED_RELATIONSHIP,
            Neo4jScopedGraphRepository._GET_SCOPED_RELATIONSHIP,
            Neo4jScopedGraphRepository._GET_SCOPED_VAULT_SNAPSHOT,
        ):
            self.assertIn("$allowed_scope_ids", query)

    def test_scoped_queries_fence_scope_roots_to_current_vault_key(
        self,
    ) -> None:
        for query in (
            Neo4jScopedGraphRepository._GET_PROTECTION_SCOPES,
            Neo4jScopedGraphRepository._PUT_SCOPED_ENTITY,
            Neo4jScopedGraphRepository._GET_SCOPED_ENTITY,
        ):
            with self.subTest(query=query[:60]):
                self.assertIn(
                    "scope.root_key_version = vault.key_version",
                    query,
                )

        for query in (
            Neo4jScopedGraphRepository._PUT_SCOPED_RELATIONSHIP,
            Neo4jScopedGraphRepository._PUT_SCOPED_ENTITY_RELATIONSHIP_BUNDLE,
            Neo4jScopedGraphRepository._GET_SCOPED_RELATIONSHIP,
            Neo4jScopedGraphRepository._GET_SCOPED_VAULT_SNAPSHOT,
        ):
            with self.subTest(query=query[:60]):
                self.assertIn(
                    "relationship_scope.root_key_version = vault.key_version",
                    query,
                )
                self.assertIn(
                    "source_scope.root_key_version = vault.key_version",
                    query,
                )
                self.assertIn(
                    "target_scope.root_key_version = vault.key_version",
                    query,
                )

    def test_relationship_queries_require_relationship_and_endpoint_scopes(
        self,
    ) -> None:
        for query in (
            Neo4jScopedGraphRepository._PUT_SCOPED_RELATIONSHIP,
            Neo4jScopedGraphRepository._PUT_SCOPED_ENTITY_RELATIONSHIP_BUNDLE,
            Neo4jScopedGraphRepository._GET_SCOPED_RELATIONSHIP,
            Neo4jScopedGraphRepository._GET_SCOPED_VAULT_SNAPSHOT,
        ):
            with self.subTest(query=query[:60]):
                self.assertIn(
                    "relationship_scope.scope_id IN $allowed_scope_ids",
                    query,
                )
                self.assertIn(
                    "source_scope.scope_id IN $allowed_scope_ids",
                    query,
                )
                self.assertIn(
                    "target_scope.scope_id IN $allowed_scope_ids",
                    query,
                )

    def test_v2_vault_create_get_and_replace_use_inherited_transport(
        self,
    ) -> None:
        row = VaultRow(
            principal_id=self.PRINCIPAL,
            vault_id=self.VAULT,
            envelope=vault_envelope(),
        )
        repository, driver = self.repository([[{"created": 1}]])
        self.assertTrue(repository.create_vault(row))
        query, kwargs = driver.calls[0]
        self.assertEqual(query, Neo4jScopedGraphRepository._CREATE_VAULT)
        self.assertEqual(kwargs["parameters_"]["envelope_version"], 2)
        self.assertEqual(kwargs["database_"], "authgraph")

        repository, driver = self.repository([[vault_record()]])
        self.assertEqual(
            repository.get_vault(self.PRINCIPAL, self.VAULT),
            row,
        )
        self.assertEqual(
            driver.calls[0][0],
            Neo4jScopedGraphRepository._GET_VAULT,
        )

        next_envelope = vault_envelope(revision=2)
        repository, driver = self.repository([[{"updated": 1}]])
        self.assertTrue(
            repository.replace_envelope(
                self.PRINCIPAL,
                self.VAULT,
                1,
                next_envelope,
            )
        )
        self.assertEqual(
            driver.calls[0][0],
            Neo4jScopedGraphRepository._REPLACE_ENVELOPE,
        )
        self.assertIn(
            "vault.key_version = $key_version",
            Neo4jScopedGraphRepository._REPLACE_ENVELOPE,
        )

    def test_v2_envelope_replace_rejects_root_key_version_change(self) -> None:
        changed_root_version = vault_envelope(
            revision=2,
            key_version=2,
        )
        repository, driver = self.repository(
            [
                [{"updated": 0}],
                [vault_record(key_version=1)],
            ]
        )

        self.assertFalse(
            repository.replace_envelope(
                self.PRINCIPAL,
                self.VAULT,
                1,
                changed_root_version,
            )
        )
        self.assertEqual(
            driver.calls[0][0],
            Neo4jScopedGraphRepository._REPLACE_ENVELOPE,
        )
        self.assertEqual(
            driver.calls[0][1]["parameters_"]["key_version"],
            2,
        )
        self.assertEqual(
            driver.calls[1][0],
            Neo4jScopedGraphRepository._GET_VAULT,
        )

    def test_v1_vault_envelopes_are_rejected_by_v2_adapter(self) -> None:
        repository, driver = self.repository([])
        row = VaultRow(
            principal_id=self.PRINCIPAL,
            vault_id=self.VAULT,
            envelope=vault_envelope(version=1),
        )
        self.assertFalse(repository.create_vault(row))
        self.assertFalse(
            repository.replace_envelope(
                self.PRINCIPAL,
                self.VAULT,
                1,
                row.envelope,
            )
        )
        self.assertEqual(driver.calls, [])

        repository, _ = self.repository([[vault_record(version=1)]])
        with self.assertRaises(IntegrityViolation):
            repository.get_vault(self.PRINCIPAL, self.VAULT)

    def test_put_and_get_protection_scope_are_ciphertext_only(self) -> None:
        expected = ProtectionScopeRow(
            vault_id=self.VAULT,
            scope_id="scope_orders",
            envelope=scope_envelope(),
        )
        repository, driver = self.repository([[{"created": 1}]])
        self.assertTrue(
            repository.put_protection_scope(
                self.PRINCIPAL,
                self.VAULT,
                4,
                expected,
            )
        )
        query, kwargs = driver.calls[0]
        parameters = kwargs["parameters_"]
        self.assertEqual(
            query,
            Neo4jScopedGraphRepository._PUT_PROTECTION_SCOPE,
        )
        self.assertEqual(parameters["scope_id"], "scope_orders")
        self.assertEqual(parameters["wrapped_scope_dek"], b"k" * 48)
        self.assertNotIn("kind", parameters)
        self.assertNotIn("properties", parameters)

        repository, driver = self.repository(
            [[{"scopes": [scope_record()]}]]
        )
        self.assertEqual(
            repository.get_protection_scopes(
                self.PRINCIPAL,
                self.VAULT,
                4,
                ("scope_orders",),
            ),
            (expected,),
        )
        self.assertEqual(
            driver.calls[0][1]["parameters_"]["scope_ids"],
            ["scope_orders"],
        )

    def test_scope_get_distinguishes_missing_vault_from_empty_scope_set(
        self,
    ) -> None:
        repository, _ = self.repository([[]])
        self.assertIsNone(
            repository.get_protection_scopes(
                self.PRINCIPAL,
                self.VAULT,
                1,
                ("scope_orders",),
            )
        )

        repository, _ = self.repository([[{"scopes": []}]])
        self.assertEqual(
            repository.get_protection_scopes(
                self.PRINCIPAL,
                self.VAULT,
                1,
                ("scope_orders",),
            ),
            (),
        )

    def test_scope_decoder_rejects_malformed_or_unrequested_rows(self) -> None:
        malformed_rows = (
            {**scope_record(), "scope_key_version": True},
            {**scope_record(), "scope_envelope_nonce": "not-bytes"},
            {**scope_record(), "wrapped_scope_dek": b"short"},
            scope_record(scope_id="scope_unrequested"),
            scope_record(vault_id="other_vault"),
        )
        for malformed in malformed_rows:
            with self.subTest(malformed=malformed):
                repository, _ = self.repository(
                    [[{"scopes": [malformed]}]]
                )
                with self.assertRaises(IntegrityViolation):
                    repository.get_protection_scopes(
                        self.PRINCIPAL,
                        self.VAULT,
                        1,
                        ("scope_orders",),
                    )

    def test_scoped_entity_write_and_grant_filtered_read(self) -> None:
        expected = ScopedEncryptedEntityRow(
            vault_id=self.VAULT,
            scope_id="scope_orders",
            entity_id="scoped_entity_1",
            payload=payload(),
        )
        repository, driver = self.repository([[{"created": 1}]])
        self.assertTrue(
            repository.put_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                3,
                expected,
            )
        )
        query, kwargs = driver.calls[0]
        self.assertEqual(
            query,
            Neo4jScopedGraphRepository._PUT_SCOPED_ENTITY,
        )
        self.assertEqual(kwargs["parameters_"]["ciphertext"], b"c" * 32)
        self.assertNotIn("kind", kwargs["parameters_"])
        self.assertNotIn("properties", kwargs["parameters_"])

        repository, driver = self.repository([[entity_record()]])
        self.assertEqual(
            repository.get_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                3,
                self.ALLOWED,
                "scoped_entity_1",
            ),
            expected,
        )
        self.assertEqual(
            driver.calls[0][1]["parameters_"]["allowed_scope_ids"],
            list(self.ALLOWED),
        )

    def test_scoped_entity_decoder_rejects_malformed_storage(self) -> None:
        malformed_rows = (
            entity_record(key_version=True),
            entity_record(key_version=1, expected_key_version=2),
            {**entity_record(), "nonce": b"short"},
            entity_record(scope_id="scope_hidden"),
            entity_record(vault_id="other_vault"),
            entity_record(entity_id="other_entity"),
        )
        for malformed in malformed_rows:
            with self.subTest(malformed=malformed):
                repository, _ = self.repository([[malformed]])
                with self.assertRaises(IntegrityViolation):
                    repository.get_scoped_entity(
                        self.PRINCIPAL,
                        self.VAULT,
                        1,
                        self.ALLOWED,
                        "scoped_entity_1",
                    )

    def test_scoped_relationship_write_passes_only_server_scope_grant(
        self,
    ) -> None:
        expected = ScopedEncryptedRelationshipRow(
            vault_id=self.VAULT,
            scope_id="scope_orders",
            relationship_id="scoped_relationship_1",
            from_entity_id="scoped_entity_1",
            to_entity_id="scoped_entity_2",
            payload=payload(),
        )
        repository, driver = self.repository([[{"created": 1}]])
        self.assertTrue(
            repository.put_scoped_relationship(
                self.PRINCIPAL,
                self.VAULT,
                2,
                self.ALLOWED,
                expected,
            )
        )
        query, kwargs = driver.calls[0]
        parameters = kwargs["parameters_"]
        self.assertEqual(
            query,
            Neo4jScopedGraphRepository._PUT_SCOPED_RELATIONSHIP,
        )
        self.assertEqual(parameters["allowed_scope_ids"], list(self.ALLOWED))
        self.assertEqual(parameters["scope_id"], "scope_orders")
        self.assertEqual(parameters["ciphertext"], b"c" * 32)

    def test_scoped_anchor_bundle_is_atomic_and_ciphertext_only(self) -> None:
        helpers = (
            ScopedEncryptedEntityRow(
                vault_id=self.VAULT,
                scope_id="scope_orders",
                entity_id="scoped_anchor_1",
                payload=payload(),
            ),
            ScopedEncryptedEntityRow(
                vault_id=self.VAULT,
                scope_id="scope_orders",
                entity_id="scoped_anchor_2",
                payload=payload(),
            ),
        )
        relationship = ScopedEncryptedRelationshipRow(
            vault_id=self.VAULT,
            scope_id="scope_orders",
            relationship_id="scoped_relationship_1",
            from_entity_id="scoped_anchor_1",
            to_entity_id="scoped_anchor_2",
            payload=payload(),
        )
        repository, driver = self.repository(
            [[{"created_entities": 2, "created_relationships": 1}]]
        )
        self.assertTrue(
            repository.put_scoped_entity_relationship_bundle(
                self.PRINCIPAL,
                self.VAULT,
                2,
                self.ALLOWED,
                helpers,
                relationship,
            )
        )
        query, kwargs = driver.calls[0]
        self.assertEqual(
            query,
            Neo4jScopedGraphRepository
            ._PUT_SCOPED_ENTITY_RELATIONSHIP_BUNDLE,
        )
        parameters = kwargs["parameters_"]
        self.assertEqual(parameters["allowed_scope_ids"], list(self.ALLOWED))
        self.assertEqual(parameters["relationship_record_revision"], 1)
        self.assertEqual(
            {row["entity_id"] for row in parameters["entity_rows"]},
            {"scoped_anchor_1", "scoped_anchor_2"},
        )
        self.assertNotIn("kind", repr(parameters))
        self.assertNotIn("properties", repr(parameters))

    def test_scoped_anchor_bundle_reconciles_only_exact_complete_state(
        self,
    ) -> None:
        helpers = (
            ScopedEncryptedEntityRow(
                vault_id=self.VAULT,
                scope_id="scope_orders",
                entity_id="scoped_anchor_1",
                payload=payload(),
            ),
        )
        relationship = ScopedEncryptedRelationshipRow(
            vault_id=self.VAULT,
            scope_id="scope_orders",
            relationship_id="scoped_relationship_1",
            from_entity_id="scoped_anchor_1",
            to_entity_id="scoped_entity_2",
            payload=payload(),
        )
        stored_anchor = entity_record("scoped_anchor_1")
        repository, _ = self.repository(
            [
                [{"created_entities": 0, "created_relationships": 0}],
                [stored_anchor],
                [relationship_record(from_entity_id="scoped_anchor_1")],
            ]
        )
        self.assertTrue(
            repository.put_scoped_entity_relationship_bundle(
                self.PRINCIPAL,
                self.VAULT,
                2,
                self.ALLOWED,
                helpers,
                relationship,
            )
        )

    def test_zero_row_relationship_retry_accepts_only_exact_ciphertext(
        self,
    ) -> None:
        expected = ScopedEncryptedRelationshipRow(
            vault_id=self.VAULT,
            scope_id="scope_orders",
            relationship_id="scoped_relationship_1",
            from_entity_id="scoped_entity_1",
            to_entity_id="scoped_entity_2",
            payload=payload(),
        )
        repository, driver = self.repository(
            [
                [{"created": 0}],
                [relationship_record()],
            ]
        )

        self.assertTrue(
            repository.put_scoped_relationship(
                self.PRINCIPAL,
                self.VAULT,
                2,
                self.ALLOWED,
                expected,
            )
        )
        self.assertEqual(
            driver.calls[1][0],
            Neo4jScopedGraphRepository._GET_SCOPED_RELATIONSHIP,
        )

        mismatched = relationship_record()
        mismatched["ciphertext"] = b"z" * 32
        repository, _ = self.repository(
            [
                [{"created": 0}],
                [mismatched],
            ]
        )
        self.assertFalse(
            repository.put_scoped_relationship(
                self.PRINCIPAL,
                self.VAULT,
                2,
                self.ALLOWED,
                expected,
            )
        )

    def test_snapshot_decodes_ciphertext_and_fetches_limit_plus_one(
        self,
    ) -> None:
        first_entity = entity_record()
        second_entity = entity_record(
            "scoped_entity_2",
            scope_id="scope_profile",
        )
        relation = relationship_record()
        repository, driver = self.repository(
            [
                [
                    {
                        "entities": [first_entity, second_entity],
                        "relationships": [relation],
                    }
                ]
            ]
        )

        snapshot = repository.get_scoped_vault_snapshot(
            self.PRINCIPAL,
            self.VAULT,
            7,
            self.ALLOWED,
            entity_limit=5,
            relationship_limit=8,
        )

        assert snapshot is not None
        self.assertEqual(
            snapshot.entities,
            (
                ScopedEncryptedEntityRow(
                    vault_id=self.VAULT,
                    scope_id="scope_orders",
                    entity_id="scoped_entity_1",
                    payload=payload(),
                ),
                ScopedEncryptedEntityRow(
                    vault_id=self.VAULT,
                    scope_id="scope_profile",
                    entity_id="scoped_entity_2",
                    payload=payload(),
                ),
            ),
        )
        self.assertEqual(
            snapshot.relationships,
            (
                ScopedEncryptedRelationshipRow(
                    vault_id=self.VAULT,
                    scope_id="scope_orders",
                    relationship_id="scoped_relationship_1",
                    from_entity_id="scoped_entity_1",
                    to_entity_id="scoped_entity_2",
                    payload=payload(),
                ),
            ),
        )
        query, kwargs = driver.calls[0]
        self.assertEqual(
            query,
            Neo4jScopedGraphRepository._GET_SCOPED_VAULT_SNAPSHOT,
        )
        self.assertEqual(kwargs["parameters_"]["entity_fetch_limit"], 6)
        self.assertEqual(
            kwargs["parameters_"]["relationship_fetch_limit"],
            9,
        )
        self.assertEqual(
            kwargs["parameters_"]["allowed_scope_ids"],
            list(self.ALLOWED),
        )

    def test_snapshot_decoder_rejects_malformed_nested_storage(self) -> None:
        malformed_results = (
            {
                "entities": (entity_record(),),
                "relationships": [],
            },
            {
                "entities": [
                    entity_record(),
                    entity_record(),
                ],
                "relationships": [],
            },
            {
                "entities": [entity_record()],
                "relationships": [
                    relationship_record(from_scope_id="scope_hidden")
                ],
            },
            {
                "entities": [
                    {
                        **entity_record(),
                        "payload_version": True,
                    }
                ],
                "relationships": [],
            },
            {
                "entities": [entity_record()],
                "relationships": [
                    relationship_record(expected_key_version=2)
                ],
            },
        )
        for malformed in malformed_results:
            with self.subTest(malformed=malformed):
                repository, _ = self.repository([[malformed]])
                with self.assertRaises(IntegrityViolation):
                    repository.get_scoped_vault_snapshot(
                        self.PRINCIPAL,
                        self.VAULT,
                        1,
                        self.ALLOWED,
                        entity_limit=5,
                        relationship_limit=5,
                    )

    def test_snapshot_missing_vault_and_invalid_limits_fail_closed(self) -> None:
        repository, _ = self.repository([[]])
        self.assertIsNone(
            repository.get_scoped_vault_snapshot(
                self.PRINCIPAL,
                self.VAULT,
                1,
                self.ALLOWED,
                entity_limit=5,
                relationship_limit=5,
            )
        )

        repository, driver = self.repository([])
        for entity_limit, relationship_limit in (
            (0, 1),
            (1, 0),
            (True, 1),
            (1, 1.5),
        ):
            with self.subTest(
                entity_limit=entity_limit,
                relationship_limit=relationship_limit,
            ):
                with self.assertRaises(ValueError):
                    repository.get_scoped_vault_snapshot(
                        self.PRINCIPAL,
                        self.VAULT,
                        1,
                        self.ALLOWED,
                        entity_limit=entity_limit,  # type: ignore[arg-type]
                        relationship_limit=relationship_limit,  # type: ignore[arg-type]
                    )
        self.assertEqual(driver.calls, [])

    def test_write_rejects_wrong_scope_or_payload_without_query(self) -> None:
        repository, driver = self.repository([])
        hidden_relationship = ScopedEncryptedRelationshipRow(
            vault_id=self.VAULT,
            scope_id="scope_hidden",
            relationship_id="scoped_relationship_1",
            from_entity_id="scoped_entity_1",
            to_entity_id="scoped_entity_2",
            payload=payload(),
        )
        self.assertFalse(
            repository.put_scoped_relationship(
                self.PRINCIPAL,
                self.VAULT,
                1,
                self.ALLOWED,
                hidden_relationship,
            )
        )
        malformed_entity = ScopedEncryptedEntityRow(
            vault_id=self.VAULT,
            scope_id="scope_orders",
            entity_id="scoped_entity_1",
            payload=replace(payload(), nonce=b"short"),
        )
        self.assertFalse(
            repository.put_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                1,
                malformed_entity,
            )
        )
        self.assertIsNone(
            repository.get_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                1,
                (["not_hashable"],),  # type: ignore[arg-type]
                "scoped_entity_1",
            )
        )
        self.assertEqual(driver.calls, [])

    def test_get_relationship_discovers_endpoints_inside_fixed_query(
        self,
    ) -> None:
        expected = ScopedEncryptedRelationshipRow(
            vault_id=self.VAULT,
            scope_id="scope_orders",
            relationship_id="scoped_relationship_1",
            from_entity_id="scoped_entity_1",
            to_entity_id="scoped_entity_2",
            payload=payload(),
        )
        repository, driver = self.repository([[relationship_record()]])

        self.assertEqual(
            repository.get_scoped_relationship(
                self.PRINCIPAL,
                self.VAULT,
                4,
                self.ALLOWED,
                expected.relationship_id,
            ),
            expected,
        )
        parameters = driver.calls[0][1]["parameters_"]
        self.assertNotIn("from_entity_id", parameters)
        self.assertNotIn("to_entity_id", parameters)
        self.assertEqual(parameters["allowed_scope_ids"], list(self.ALLOWED))

    def test_scoped_entity_replace_is_revision_cas_and_retry_safe(
        self,
    ) -> None:
        updated = ScopedEncryptedEntityRow(
            vault_id=self.VAULT,
            scope_id="scope_orders",
            entity_id="scoped_entity_1",
            payload=payload(),
            record_revision=2,
        )
        repository, driver = self.repository([[{"updated": 1}]])
        self.assertTrue(
            repository.replace_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                3,
                self.ALLOWED,
                1,
                updated,
            )
        )
        query, kwargs = driver.calls[0]
        self.assertEqual(
            query,
            Neo4jScopedGraphRepository._REPLACE_SCOPED_ENTITY,
        )
        self.assertIn("coalesce(entity.record_revision, 1)", query)
        self.assertEqual(kwargs["parameters_"]["record_revision"], 2)
        self.assertEqual(kwargs["parameters_"]["expected_record_revision"], 1)

        repository, _ = self.repository(
            [[{"updated": 0}], [entity_record(record_revision=2)]]
        )
        self.assertTrue(
            repository.replace_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                3,
                self.ALLOWED,
                1,
                updated,
            )
        )

    def test_scoped_relationship_replace_requires_all_visible_scopes(
        self,
    ) -> None:
        updated = ScopedEncryptedRelationshipRow(
            vault_id=self.VAULT,
            scope_id="scope_orders",
            relationship_id="scoped_relationship_1",
            from_entity_id="scoped_entity_1",
            to_entity_id="scoped_entity_2",
            payload=payload(),
            record_revision=2,
        )
        repository, driver = self.repository([[{"updated": 1}]])
        self.assertTrue(
            repository.replace_scoped_relationship(
                self.PRINCIPAL,
                self.VAULT,
                3,
                self.ALLOWED,
                1,
                updated,
            )
        )
        query, parameters = (
            driver.calls[0][0],
            driver.calls[0][1]["parameters_"],
        )
        self.assertIn(
            "relationship_scope.scope_id IN $allowed_scope_ids",
            query,
        )
        self.assertIn("source_scope.scope_id IN $allowed_scope_ids", query)
        self.assertIn("target_scope.scope_id IN $allowed_scope_ids", query)
        self.assertEqual(parameters["record_revision"], 2)

    def test_scoped_deletes_are_revision_fenced_and_entity_is_restrictive(
        self,
    ) -> None:
        repository, driver = self.repository(
            [[{"deleted": 1}], [{"deleted": 1}]]
        )
        self.assertTrue(
            repository.delete_scoped_relationship(
                self.PRINCIPAL,
                self.VAULT,
                5,
                self.ALLOWED,
                "scoped_relationship_1",
                2,
            )
        )
        self.assertTrue(
            repository.delete_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                5,
                self.ALLOWED,
                "scoped_entity_1",
                2,
            )
        )
        relationship_query = driver.calls[0][0]
        entity_query = driver.calls[1][0]
        self.assertIn(
            "coalesce(link.record_revision, 1)",
            relationship_query,
        )
        self.assertIn(
            "NOT EXISTS {\n            MATCH "
            "(entity)-[:AG_SCOPED_LINK]-()",
            entity_query,
        )
        self.assertNotIn("DETACH DELETE", entity_query)

    def test_invalid_record_revisions_fail_closed(self) -> None:
        repository, driver = self.repository([[entity_record(
            record_revision=True
        )]])
        with self.assertRaises(IntegrityViolation):
            repository.get_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                1,
                self.ALLOWED,
                "scoped_entity_1",
            )

        repository, driver = self.repository([])
        invalid_update = ScopedEncryptedEntityRow(
            vault_id=self.VAULT,
            scope_id="scope_orders",
            entity_id="scoped_entity_1",
            payload=payload(),
            record_revision=3,
        )
        self.assertFalse(
            repository.replace_scoped_entity(
                self.PRINCIPAL,
                self.VAULT,
                1,
                self.ALLOWED,
                1,
                invalid_update,
            )
        )
        self.assertEqual(driver.calls, [])


if __name__ == "__main__":
    unittest.main()
