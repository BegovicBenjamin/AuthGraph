from __future__ import annotations

import unittest
from dataclasses import replace

from authgraph.crypto import CryptoEngine
from authgraph.errors import (
    ConflictError,
    IntegrityViolation,
    RecordNotFound,
    ValidationError,
)
from authgraph.memory_repository import InMemoryGraphRepository
from authgraph.models import (
    KdfParameters,
    ScopedEncryptedEntityRow,
    ScopedEncryptedRelationshipRow,
)
from authgraph.scoped_service import (
    SCOPED_PAYLOAD_VERSION,
    ScopedAuthGraphService,
    _entity_aad,
    _relationship_aad,
)
from authgraph.scoped_sessions import ScopedSessionBroker


class InspectableCrudRepository(InMemoryGraphRepository):
    def scoped_counts(self) -> tuple[int, int]:
        with self._lock:
            return (
                len(self._scoped_entities),
                len(self._scoped_relationships),
            )

    def tamper_entity_revision(
        self,
        vault_id: str,
        entity_id: str,
        record_revision: int,
    ) -> None:
        with self._lock:
            key = (vault_id, entity_id)
            self._scoped_entities[key] = replace(
                self._scoped_entities[key],
                record_revision=record_revision,
            )


class ScopedCrudTests(unittest.TestCase):
    PRINCIPAL = "idp|scoped-crud|alice"
    PASSPHRASE = b"correct horse battery staple"

    def setUp(self) -> None:
        self.repository = InspectableCrudRepository()
        self.crypto = CryptoEngine(
            KdfParameters.insecure_for_testing(),
            allow_insecure_kdf_for_testing=True,
        )
        self.sessions = ScopedSessionBroker(
            default_ttl_seconds=30,
            max_ttl_seconds=30,
            sweep_interval_seconds=None,
        )
        self.service = ScopedAuthGraphService(
            self.repository,
            self.crypto,
            self.sessions,
        )
        self.vault_id = self.service.create_vault(
            self.PRINCIPAL,
            self.PASSPHRASE,
        )
        self.scope_a = self.service.create_protection_scope(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
        )
        self.scope_b = self.service.create_protection_scope(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
        )
        self.relationship_scope = self.service.create_protection_scope(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
        )

    def tearDown(self) -> None:
        self.sessions.close_all()

    def unlock(self, *scope_ids: str):
        return self.service.unlock(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
            tuple(scope_ids),
        )

    def create_relationship_fixture(
        self,
    ) -> tuple[object, str, str, str]:
        context = self.unlock(
            self.scope_a,
            self.scope_b,
            self.relationship_scope,
        )
        entity_a = self.service.create_entity(
            context,
            self.scope_a,
            "Customer",
            {"name": "Alice"},
        )
        entity_b = self.service.create_entity(
            context,
            self.scope_b,
            "Order",
            {"number": "A-100"},
        )
        relationship_id = self.service.create_relationship(
            context,
            self.relationship_scope,
            entity_a,
            entity_b,
            "PLACED",
            {"channel": "web"},
        )
        return context, entity_a, entity_b, relationship_id

    def test_idempotent_entity_create_returns_one_stable_record(self) -> None:
        context = self.unlock(self.scope_a)
        first = self.service.create_entity(
            context,
            self.scope_a,
            "Profile",
            {"tags": ("one", "two")},
            idempotency_key="request-entity-1",
        )
        second = self.service.create_entity(
            context,
            self.scope_a,
            "Profile",
            {"tags": ("one", "two")},
            idempotency_key="request-entity-1",
        )

        self.assertEqual(first, second)
        self.assertEqual(self.repository.scoped_counts(), (1, 0))
        self.assertEqual(
            self.service.get_entity(context, first).properties,
            {"tags": ["one", "two"]},
        )
        with self.assertRaises(ConflictError):
            self.service.create_entity(
                context,
                self.scope_a,
                "Profile",
                {"tags": ["changed"]},
                idempotency_key="request-entity-1",
            )

    def test_entity_update_uses_authenticated_record_revision(self) -> None:
        context = self.unlock(self.scope_a)
        entity_id = self.service.create_entity(
            context,
            self.scope_a,
            "Profile",
            {"status": "new"},
        )
        self.assertEqual(
            self.service.get_entity(context, entity_id).record_revision,
            1,
        )

        updated = self.service.update_entity(
            context,
            entity_id,
            "Profile",
            {"status": "active"},
            expected_revision=1,
        )
        self.assertEqual(updated.record_revision, 2)
        self.assertEqual(updated.properties, {"status": "active"})
        with self.assertRaises(ConflictError):
            self.service.update_entity(
                context,
                entity_id,
                "Profile",
                {"status": "stale"},
                expected_revision=1,
            )
        self.assertEqual(
            self.service.get_entity(context, entity_id).properties,
            {"status": "active"},
        )

        self.repository.tamper_entity_revision(
            self.vault_id,
            entity_id,
            3,
        )
        with self.assertRaises(IntegrityViolation):
            self.service.get_entity(context, entity_id)

    def test_legacy_two_field_semantics_are_revision_one_and_updatable(
        self,
    ) -> None:
        context = self.unlock(self.scope_a)
        entity_id = "scoped_legacy_entity"
        with self.sessions.guarded_lease(context) as lease:
            key = lease.scope_keys[self.scope_a]
            payload = self.crypto.encrypt_json(
                key.dek,
                {"kind": "Legacy", "properties": {"value": 1}},
                aad_parts=_entity_aad(
                    lease.principal_id,
                    lease.vault_id,
                    self.scope_a,
                    entity_id,
                ),
                key_version=key.key_version,
                payload_version=SCOPED_PAYLOAD_VERSION,
            )
            self.assertTrue(
                self.repository.put_scoped_entity(
                    lease.principal_id,
                    lease.vault_id,
                    lease.envelope_revision,
                    ScopedEncryptedEntityRow(
                        vault_id=lease.vault_id,
                        scope_id=self.scope_a,
                        entity_id=entity_id,
                        payload=payload,
                    ),
                )
            )

        legacy = self.service.get_entity(context, entity_id)
        self.assertEqual(legacy.record_revision, 1)
        updated = self.service.update_entity(
            context,
            entity_id,
            "Legacy",
            {"value": 2},
            expected_revision=1,
        )
        self.assertEqual(updated.record_revision, 2)

    def test_idempotent_relationship_create_checks_complete_intent(
        self,
    ) -> None:
        context, entity_a, entity_b, _ = (
            self.create_relationship_fixture()
        )
        first = self.service.create_relationship(
            context,
            self.relationship_scope,
            entity_a,
            entity_b,
            "OWNS",
            {"since": 2025},
            idempotency_key="request-relationship-1",
        )
        second = self.service.create_relationship(
            context,
            self.relationship_scope,
            entity_a,
            entity_b,
            "OWNS",
            {"since": 2025},
            idempotency_key="request-relationship-1",
        )
        self.assertEqual(first, second)
        self.assertEqual(self.repository.scoped_counts(), (2, 2))

        with self.assertRaises(ConflictError):
            self.service.create_relationship(
                context,
                self.relationship_scope,
                entity_b,
                entity_a,
                "OWNS",
                {"since": 2025},
                idempotency_key="request-relationship-1",
            )

    def test_relationship_get_update_and_delete(self) -> None:
        context, entity_a, entity_b, relationship_id = (
            self.create_relationship_fixture()
        )
        relationship = self.service.get_relationship(
            context,
            relationship_id,
        )
        self.assertEqual(relationship.record_revision, 1)
        self.assertEqual(relationship.from_entity_id, entity_a)
        self.assertEqual(relationship.to_entity_id, entity_b)

        updated = self.service.update_relationship(
            context,
            relationship_id,
            "PLACED",
            {"channel": "phone"},
            expected_revision=1,
        )
        self.assertEqual(updated.record_revision, 2)
        self.assertEqual(updated.properties, {"channel": "phone"})
        with self.assertRaises(ConflictError):
            self.service.update_relationship(
                context,
                relationship_id,
                "PLACED",
                {"channel": "stale"},
                expected_revision=1,
            )

        self.service.delete_relationship(
            context,
            relationship_id,
            expected_revision=2,
        )
        with self.assertRaises(RecordNotFound):
            self.service.get_relationship(context, relationship_id)

    def test_relationship_bundle_atomically_creates_scoped_helpers(
        self,
    ) -> None:
        context = self.unlock(self.scope_a, self.scope_b)
        existing = self.service.create_entity(
            context,
            self.scope_b,
            "PublicAnchor",
            {"opaque": "anchor"},
        )
        relationship_id, new_entity_ids = (
            self.service.create_relationship_bundle(
                context,
                self.scope_a,
                (("PrivateRecord", {"value": 7}),),
                existing,
                0,
                "POINTS_TO",
                {"source": "import"},
            )
        )

        self.assertEqual(len(new_entity_ids), 1)
        helper = self.service.get_entity(context, new_entity_ids[0])
        relationship = self.service.get_relationship(
            context,
            relationship_id,
        )
        self.assertEqual(helper.scope_id, self.scope_a)
        self.assertEqual(helper.record_revision, 1)
        self.assertEqual(relationship.scope_id, self.scope_a)
        self.assertEqual(relationship.from_entity_id, existing)
        self.assertEqual(
            relationship.to_entity_id,
            new_entity_ids[0],
        )
        self.assertEqual(self.repository.scoped_counts(), (2, 1))

        before = self.repository.scoped_counts()
        with self.assertRaises(ValidationError):
            self.service.create_relationship_bundle(
                context,
                self.scope_a,
                (
                    ("One", {}),
                    ("Unreferenced", {}),
                ),
                existing,
                0,
                "INVALID_BUNDLE",
            )
        self.assertEqual(self.repository.scoped_counts(), before)

    def test_repository_bundle_accepts_only_new_record_revision_one(
        self,
    ) -> None:
        context = self.unlock(self.scope_a)
        entity_id = "scoped_bundle_revision_entity"
        relationship_id = "scoped_bundle_revision_relationship"
        with self.sessions.guarded_lease(context) as lease:
            key = lease.scope_keys[self.scope_a]

            def entity_row(record_revision: int):
                return ScopedEncryptedEntityRow(
                    vault_id=lease.vault_id,
                    scope_id=self.scope_a,
                    entity_id=entity_id,
                    payload=self.crypto.encrypt_json(
                        key.dek,
                        {
                            "kind": "Helper",
                            "properties": {},
                            "record_revision": record_revision,
                        },
                        aad_parts=_entity_aad(
                            lease.principal_id,
                            lease.vault_id,
                            self.scope_a,
                            entity_id,
                        ),
                        key_version=key.key_version,
                        payload_version=SCOPED_PAYLOAD_VERSION,
                    ),
                    record_revision=record_revision,
                )

            def relationship_row(record_revision: int):
                return ScopedEncryptedRelationshipRow(
                    vault_id=lease.vault_id,
                    scope_id=self.scope_a,
                    relationship_id=relationship_id,
                    from_entity_id=entity_id,
                    to_entity_id=entity_id,
                    payload=self.crypto.encrypt_json(
                        key.dek,
                        {
                            "kind": "SELF",
                            "properties": {},
                            "record_revision": record_revision,
                        },
                        aad_parts=_relationship_aad(
                            lease.principal_id,
                            lease.vault_id,
                            self.scope_a,
                            relationship_id,
                            entity_id,
                            self.scope_a,
                            entity_id,
                            self.scope_a,
                        ),
                        key_version=key.key_version,
                        payload_version=SCOPED_PAYLOAD_VERSION,
                    ),
                    record_revision=record_revision,
                )

            self.assertFalse(
                self.repository.put_scoped_entity_relationship_bundle(
                    lease.principal_id,
                    lease.vault_id,
                    lease.envelope_revision,
                    (self.scope_a,),
                    (entity_row(2),),
                    relationship_row(1),
                )
            )
            self.assertFalse(
                self.repository.put_scoped_entity_relationship_bundle(
                    lease.principal_id,
                    lease.vault_id,
                    lease.envelope_revision,
                    (self.scope_a,),
                    (entity_row(1),),
                    relationship_row(2),
                )
            )
        self.assertEqual(self.repository.scoped_counts(), (0, 0))

    def test_relationship_crud_requires_all_three_scopes(self) -> None:
        context, _, _, relationship_id = (
            self.create_relationship_fixture()
        )
        self.service.lock(context)

        missing_endpoint = self.unlock(
            self.scope_a,
            self.relationship_scope,
        )
        with self.assertRaises(RecordNotFound):
            self.service.get_relationship(
                missing_endpoint,
                relationship_id,
            )

        missing_relationship_scope = self.unlock(
            self.scope_a,
            self.scope_b,
        )
        with self.assertRaises(RecordNotFound):
            self.service.get_relationship(
                missing_relationship_scope,
                relationship_id,
            )

    def test_entity_delete_is_restrict_even_when_edge_is_hidden(self) -> None:
        context, entity_a, _, relationship_id = (
            self.create_relationship_fixture()
        )
        self.service.lock(context)

        only_entity_scope = self.unlock(self.scope_a)
        with self.assertRaises(ConflictError):
            self.service.delete_entity(
                only_entity_scope,
                entity_a,
                expected_revision=1,
            )
        self.assertEqual(
            self.service.get_entity(only_entity_scope, entity_a).entity_id,
            entity_a,
        )
        self.service.lock(only_entity_scope)

        complete = self.unlock(
            self.scope_a,
            self.scope_b,
            self.relationship_scope,
        )
        self.service.delete_relationship(
            complete,
            relationship_id,
            expected_revision=1,
        )
        self.service.delete_entity(
            complete,
            entity_a,
            expected_revision=1,
        )
        with self.assertRaises(RecordNotFound):
            self.service.get_entity(complete, entity_a)

    def test_revision_and_idempotency_inputs_are_strict(self) -> None:
        context = self.unlock(self.scope_a)
        with self.assertRaises(ValidationError):
            self.service.create_entity(
                context,
                self.scope_a,
                "Profile",
                {},
                idempotency_key="",
            )
        entity_id = self.service.create_entity(
            context,
            self.scope_a,
            "Profile",
            {},
        )
        for revision in (True, 0, -1):
            with self.subTest(revision=revision):
                with self.assertRaises(ValidationError):
                    self.service.update_entity(
                        context,
                        entity_id,
                        "Profile",
                        {},
                        expected_revision=revision,
                    )


if __name__ == "__main__":
    unittest.main()
