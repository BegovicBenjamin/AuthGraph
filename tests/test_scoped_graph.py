from __future__ import annotations

import json
import unittest
from dataclasses import replace

from authgraph import (
    AuthGraphService,
    CryptoEngine,
    InMemoryGraphRepository,
    InMemorySessionBroker,
    KdfParameters,
)
from authgraph.errors import (
    AuthorizationDenied,
    IntegrityViolation,
    RecordNotFound,
    SessionUnavailable,
    UnlockDenied,
    ValidationError,
)
from authgraph.scoped_service import ScopedAuthGraphService
from authgraph.scoped_sessions import (
    MAX_SCOPES_PER_SESSION,
    ScopedSessionBroker,
)
from authgraph.service import (
    MAX_VAULT_SNAPSHOT_ENTITIES,
    MAX_VAULT_SNAPSHOT_RELATIONSHIPS,
)


class FakeClock:
    def __init__(self) -> None:
        self.value = 1_000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class InspectableScopedRepository(InMemoryGraphRepository):
    """Test-only mutation helpers for authenticated-storage assertions."""

    def tamper_scoped_entity_ciphertext(
        self,
        vault_id: str,
        entity_id: str,
    ) -> None:
        with self._lock:
            key = (vault_id, entity_id)
            row = self._scoped_entities[key]
            changed = bytearray(row.payload.ciphertext)
            changed[0] ^= 1
            self._scoped_entities[key] = replace(
                row,
                payload=replace(
                    row.payload,
                    ciphertext=bytes(changed),
                ),
            )

    def swap_scoped_entity_payloads(
        self,
        vault_id: str,
        first_entity_id: str,
        second_entity_id: str,
    ) -> None:
        with self._lock:
            first_key = (vault_id, first_entity_id)
            second_key = (vault_id, second_entity_id)
            first = self._scoped_entities[first_key]
            second = self._scoped_entities[second_key]
            self._scoped_entities[first_key] = replace(
                first,
                payload=second.payload,
            )
            self._scoped_entities[second_key] = replace(
                second,
                payload=first.payload,
            )

    def move_scoped_entity_metadata(
        self,
        vault_id: str,
        entity_id: str,
        scope_id: str,
    ) -> None:
        with self._lock:
            key = (vault_id, entity_id)
            self._scoped_entities[key] = replace(
                self._scoped_entities[key],
                scope_id=scope_id,
            )

    def malform_scoped_entity_id(
        self,
        vault_id: str,
        entity_id: str,
    ) -> None:
        with self._lock:
            key = (vault_id, entity_id)
            self._scoped_entities[key] = replace(
                self._scoped_entities[key],
                entity_id="",
            )

    def redirect_scoped_relationship(
        self,
        vault_id: str,
        relationship_id: str,
        *,
        from_entity_id: str,
    ) -> None:
        with self._lock:
            key = (vault_id, relationship_id)
            self._scoped_relationships[key] = replace(
                self._scoped_relationships[key],
                from_entity_id=from_entity_id,
            )

    def swap_scope_envelopes(
        self,
        vault_id: str,
        first_scope_id: str,
        second_scope_id: str,
    ) -> None:
        with self._lock:
            first_key = (vault_id, first_scope_id)
            second_key = (vault_id, second_scope_id)
            first = self._protection_scopes[first_key]
            second = self._protection_scopes[second_key]
            self._protection_scopes[first_key] = replace(
                first,
                envelope=second.envelope,
            )
            self._protection_scopes[second_key] = replace(
                second,
                envelope=first.envelope,
            )


class ScopedGraphSecurityTests(unittest.TestCase):
    PRINCIPAL = "idp|scoped-tests|alice"
    OTHER_PRINCIPAL = "idp|scoped-tests|bob"
    PASSPHRASE = b"correct horse battery staple"
    NEW_PASSPHRASE = b"new correct horse battery staple"
    OTHER_PASSPHRASE = b"another correct horse battery staple"

    def setUp(self) -> None:
        self.clock = FakeClock()
        self.repository = InspectableScopedRepository()
        self.crypto = CryptoEngine(
            KdfParameters.insecure_for_testing(),
            allow_insecure_kdf_for_testing=True,
        )
        self.sessions = ScopedSessionBroker(
            default_ttl_seconds=30,
            max_ttl_seconds=30,
            sweep_interval_seconds=None,
            clock=self.clock,
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

    def tearDown(self) -> None:
        self.sessions.close_all()

    def unlock(
        self,
        *scope_ids: str,
        ttl_seconds: int | None = None,
    ):
        return self.service.unlock(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
            tuple(scope_ids),
            ttl_seconds=ttl_seconds,
        )

    def seed_two_scopes(self) -> tuple[str, str]:
        context = self.unlock(self.scope_a, self.scope_b)
        try:
            entity_a = self.service.create_entity(
                context,
                self.scope_a,
                "PrivateProfile",
                {"secret": "alice-scope-a-sentinel"},
            )
            entity_b = self.service.create_entity(
                context,
                self.scope_b,
                "PrivateOrder",
                {"secret": "alice-scope-b-sentinel"},
            )
            return entity_a, entity_b
        finally:
            self.service.lock(context)

    def create_relationship_fixture(
        self,
    ) -> tuple[str, str, str, str]:
        relation_scope = self.service.create_protection_scope(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
        )
        context = self.unlock(
            self.scope_a,
            self.scope_b,
            relation_scope,
        )
        try:
            entity_a = self.service.create_entity(
                context,
                self.scope_a,
                "Profile",
                {"name": "scope-a-profile"},
            )
            entity_b = self.service.create_entity(
                context,
                self.scope_b,
                "Order",
                {"number": "scope-b-order"},
            )
            relationship_id = self.service.connect(
                context,
                relation_scope,
                entity_a,
                entity_b,
                "PLACED",
                {"channel": "scope-relation-sentinel"},
            )
            return (
                relation_scope,
                entity_a,
                entity_b,
                relationship_id,
            )
        finally:
            self.service.lock(context)

    def test_independent_scope_keys_and_requested_scope_isolation(self) -> None:
        entity_a, entity_b = self.seed_two_scopes()

        combined = self.unlock(self.scope_a, self.scope_b)
        with self.sessions.guarded_lease(combined) as lease:
            self.assertEqual(
                set(lease.scope_keys),
                {self.scope_a, self.scope_b},
            )
            key_a = lease.scope_keys[self.scope_a].dek
            key_b = lease.scope_keys[self.scope_b].dek
            self.assertNotEqual(bytes(key_a), bytes(key_b))
        self.assertEqual(key_a, bytearray(len(key_a)))
        self.assertEqual(key_b, bytearray(len(key_b)))
        self.service.lock(combined)

        only_a = self.unlock(self.scope_a)
        self.assertEqual(self.sessions.resident_scope_ciphertext_count, 1)
        self.assertEqual(
            self.service.get_entity(only_a, entity_a).properties["secret"],
            "alice-scope-a-sentinel",
        )
        with self.assertRaises(RecordNotFound):
            self.service.get_entity(only_a, entity_b)
        with self.assertRaises(AuthorizationDenied):
            self.service.create_entity(
                only_a,
                self.scope_b,
                "Forbidden",
                {"secret": "must-not-write"},
            )
        snapshot = self.service.get_vault_snapshot(only_a)
        self.assertEqual(
            {entity.entity_id for entity in snapshot.entities},
            {entity_a},
        )
        self.service.lock(only_a)

        only_b = self.unlock(self.scope_b)
        self.assertEqual(
            self.service.get_entity(only_b, entity_b).properties["secret"],
            "alice-scope-b-sentinel",
        )
        with self.assertRaises(RecordNotFound):
            self.service.get_entity(only_b, entity_a)
        self.service.lock(only_b)

    def test_unlock_rejects_invalid_or_unavailable_scope_grants(self) -> None:
        invalid_grants = (
            (),
            (self.scope_a, self.scope_a),
            tuple(
                f"scope_synthetic_{index}"
                for index in range(MAX_SCOPES_PER_SESSION + 1)
            ),
            ("scope_does_not_exist",),
        )
        for scope_ids in invalid_grants:
            with self.subTest(scope_count=len(scope_ids)):
                with self.assertRaises(UnlockDenied):
                    self.service.unlock(
                        self.PRINCIPAL,
                        self.vault_id,
                        self.PASSPHRASE,
                        scope_ids,
                    )
        self.assertEqual(self.sessions.active_count, 0)
        self.assertEqual(self.sessions.resident_scope_ciphertext_count, 0)

    def test_unhashable_scope_grant_fails_as_generic_unlock_denial(self) -> None:
        with self.assertRaises(UnlockDenied):
            self.service.unlock(
                self.PRINCIPAL,
                self.vault_id,
                self.PASSPHRASE,
                (["not", "an", "opaque", "scope"],),  # type: ignore[arg-type]
            )
        self.assertEqual(self.sessions.active_count, 0)

    def test_cross_owner_records_and_scopes_are_unavailable(self) -> None:
        alice_context = self.unlock(self.scope_a)
        alice_entity = self.service.create_entity(
            alice_context,
            self.scope_a,
            "AliceRecord",
            {"owner": "alice"},
        )

        other_vault = self.service.create_vault(
            self.OTHER_PRINCIPAL,
            self.OTHER_PASSPHRASE,
        )
        other_scope = self.service.create_protection_scope(
            self.OTHER_PRINCIPAL,
            other_vault,
            self.OTHER_PASSPHRASE,
        )
        other_context = self.service.unlock(
            self.OTHER_PRINCIPAL,
            other_vault,
            self.OTHER_PASSPHRASE,
            (other_scope,),
        )
        other_entity = self.service.create_entity(
            other_context,
            other_scope,
            "BobRecord",
            {"owner": "bob"},
        )

        with self.assertRaises(RecordNotFound):
            self.service.get_entity(alice_context, other_entity)
        with self.assertRaises(RecordNotFound):
            self.service.connect(
                alice_context,
                self.scope_a,
                alice_entity,
                other_entity,
                "CROSS_OWNER",
            )
        with self.assertRaises(AuthorizationDenied):
            self.service.create_entity(
                alice_context,
                other_scope,
                "CrossOwnerWrite",
                {},
            )
        with self.assertRaises(UnlockDenied):
            self.service.unlock(
                self.PRINCIPAL,
                other_vault,
                self.OTHER_PASSPHRASE,
                (other_scope,),
            )

        self.service.lock(other_context)
        self.service.lock(alice_context)

    def test_relationship_requires_its_scope_and_both_endpoint_scopes(self) -> None:
        (
            relation_scope,
            entity_a,
            entity_b,
            relationship_id,
        ) = self.create_relationship_fixture()

        expectations = (
            ((self.scope_a,), {entity_a}, set()),
            ((self.scope_b,), {entity_b}, set()),
            ((relation_scope,), set(), set()),
            (
                (self.scope_a, self.scope_b),
                {entity_a, entity_b},
                set(),
            ),
            (
                (self.scope_a, relation_scope),
                {entity_a},
                set(),
            ),
            (
                (self.scope_b, relation_scope),
                {entity_b},
                set(),
            ),
            (
                (self.scope_a, self.scope_b, relation_scope),
                {entity_a, entity_b},
                {relationship_id},
            ),
        )
        for scopes, expected_entities, expected_relationships in expectations:
            with self.subTest(scopes=scopes):
                context = self.unlock(*scopes)
                snapshot = self.service.get_vault_snapshot(context)
                self.assertEqual(
                    {entity.entity_id for entity in snapshot.entities},
                    expected_entities,
                )
                self.assertEqual(
                    {
                        relationship.relationship_id
                        for relationship in snapshot.relationships
                    },
                    expected_relationships,
                )
                self.service.lock(context)

        endpoint_only = self.unlock(self.scope_a, self.scope_b)
        with self.assertRaises(AuthorizationDenied):
            self.service.connect(
                endpoint_only,
                relation_scope,
                entity_a,
                entity_b,
                "FORBIDDEN_RELATIONSHIP_SCOPE",
            )
        self.service.lock(endpoint_only)

        missing_endpoint_scope = self.unlock(self.scope_a, relation_scope)
        with self.assertRaises(RecordNotFound):
            self.service.connect(
                missing_endpoint_scope,
                relation_scope,
                entity_a,
                entity_b,
                "FORBIDDEN_HIDDEN_ENDPOINT",
            )
        self.service.lock(missing_endpoint_scope)

    def test_entity_ciphertext_bit_flip_fails_authentication(self) -> None:
        entity_a, _ = self.seed_two_scopes()
        self.repository.tamper_scoped_entity_ciphertext(
            self.vault_id,
            entity_a,
        )
        context = self.unlock(self.scope_a)
        with self.assertRaises(IntegrityViolation):
            self.service.get_entity(context, entity_a)
        self.service.lock(context)

    def test_entity_payload_swap_is_bound_to_entity_id(self) -> None:
        context = self.unlock(self.scope_a)
        first = self.service.create_entity(
            context,
            self.scope_a,
            "First",
            {"value": "first"},
        )
        second = self.service.create_entity(
            context,
            self.scope_a,
            "Second",
            {"value": "second"},
        )
        self.service.lock(context)
        self.repository.swap_scoped_entity_payloads(
            self.vault_id,
            first,
            second,
        )

        context = self.unlock(self.scope_a)
        with self.assertRaises(IntegrityViolation):
            self.service.get_vault_snapshot(context)
        self.service.lock(context)

    def test_entity_ciphertext_is_bound_to_scope_metadata(self) -> None:
        entity_a, _ = self.seed_two_scopes()
        self.repository.move_scoped_entity_metadata(
            self.vault_id,
            entity_a,
            self.scope_b,
        )
        context = self.unlock(self.scope_a, self.scope_b)
        with self.assertRaises(IntegrityViolation):
            self.service.get_vault_snapshot(context)
        self.service.lock(context)

    def test_malformed_stored_object_id_is_an_integrity_failure(self) -> None:
        entity_a, _ = self.seed_two_scopes()
        self.repository.malform_scoped_entity_id(
            self.vault_id,
            entity_a,
        )
        context = self.unlock(self.scope_a)
        with self.assertRaises(IntegrityViolation):
            self.service.get_entity(context, entity_a)
        self.service.lock(context)

    def test_relationship_ciphertext_is_bound_to_endpoints(self) -> None:
        (
            relation_scope,
            entity_a,
            entity_b,
            relationship_id,
        ) = self.create_relationship_fixture()
        context = self.unlock(self.scope_a, self.scope_b, relation_scope)
        replacement_source = self.service.create_entity(
            context,
            self.scope_a,
            "OtherProfile",
            {"name": "replacement-source"},
        )
        self.service.lock(context)
        self.repository.redirect_scoped_relationship(
            self.vault_id,
            relationship_id,
            from_entity_id=replacement_source,
        )

        context = self.unlock(self.scope_a, self.scope_b, relation_scope)
        with self.assertRaises(IntegrityViolation):
            self.service.get_vault_snapshot(context)
        self.assertNotEqual(entity_a, replacement_source)
        self.assertNotEqual(entity_b, replacement_source)
        self.service.lock(context)

    def test_scope_envelopes_cannot_be_swapped(self) -> None:
        self.repository.swap_scope_envelopes(
            self.vault_id,
            self.scope_a,
            self.scope_b,
        )
        with self.assertRaises(IntegrityViolation):
            self.unlock(self.scope_a, self.scope_b)
        self.assertEqual(self.sessions.active_count, 0)
        self.assertEqual(self.sessions.resident_scope_ciphertext_count, 0)

    def test_v2_vault_is_fenced_from_legacy_service(self) -> None:
        legacy_sessions = InMemorySessionBroker(
            default_ttl_seconds=30,
            max_ttl_seconds=30,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        try:
            legacy_service = AuthGraphService(
                self.repository,
                self.crypto,
                legacy_sessions,
            )
            with self.assertRaises(UnlockDenied):
                legacy_service.unlock(
                    self.PRINCIPAL,
                    self.vault_id,
                    self.PASSPHRASE,
                )
            self.assertEqual(legacy_sessions.active_count, 0)
        finally:
            legacy_sessions.close_all()

    def test_expiry_denies_reads_and_purges_scoped_session_material(self) -> None:
        entity_a, _ = self.seed_two_scopes()
        context = self.unlock(self.scope_a, ttl_seconds=2)
        self.assertEqual(
            self.service.get_entity(context, entity_a).entity_id,
            entity_a,
        )
        self.clock.advance(2)
        with self.assertRaises(SessionUnavailable):
            self.service.get_entity(context, entity_a)
        self.sessions.purge_expired()
        self.assertEqual(self.sessions.active_count, 0)
        self.assertEqual(self.sessions.resident_scope_ciphertext_count, 0)

    def test_base_expiry_sweep_does_not_leave_orphan_scope_ciphertext(
        self,
    ) -> None:
        context = self.unlock(self.scope_a, ttl_seconds=2)
        self.assertEqual(self.sessions.resident_scope_ciphertext_count, 1)
        self.clock.advance(2)

        # ScopedSessionBroker delegates its background sweeper to this base
        # broker, so this is the same cleanup the worker performs.
        self.sessions._base.purge_expired()

        self.assertEqual(self.sessions._base.active_count, 0)
        self.assertEqual(self.sessions.resident_scope_ciphertext_count, 0)
        with self.assertRaises(SessionUnavailable):
            with self.sessions.guarded_lease(context):
                pass

    def test_lock_revokes_session_and_clears_resident_scope_ciphertext(
        self,
    ) -> None:
        context = self.unlock(self.scope_a, self.scope_b)
        digest = self.sessions._digest(context)
        record = self.sessions._records[digest]
        resident_buffers = [
            wrapped.ciphertext
            for wrapped in record.scope_keys.values()
        ]
        self.assertTrue(all(any(buffer) for buffer in resident_buffers))

        self.service.lock(context)

        self.assertEqual(self.sessions.active_count, 0)
        self.assertEqual(self.sessions.resident_scope_ciphertext_count, 0)
        self.assertTrue(
            all(buffer == bytearray(len(buffer)) for buffer in resident_buffers)
        )
        with self.assertRaises(SessionUnavailable):
            with self.sessions.guarded_lease(context):
                pass

    def test_passphrase_change_preserves_scoped_data_and_revokes_old_session(
        self,
    ) -> None:
        entity_a, entity_b = self.seed_two_scopes()
        old_context = self.unlock(self.scope_a, self.scope_b)
        stored_before = self.repository.ciphertext_snapshot()
        entity_ciphertext_before = stored_before["scoped_entities"]
        scope_envelopes_before = stored_before["protection_scopes"]

        self.service.change_passphrase(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
            self.NEW_PASSPHRASE,
        )

        with self.assertRaises(SessionUnavailable):
            self.service.get_vault_snapshot(old_context)
        with self.assertRaises(UnlockDenied):
            self.service.unlock(
                self.PRINCIPAL,
                self.vault_id,
                self.PASSPHRASE,
                (self.scope_a, self.scope_b),
            )
        new_context = self.service.unlock(
            self.PRINCIPAL,
            self.vault_id,
            self.NEW_PASSPHRASE,
            (self.scope_a, self.scope_b),
        )
        snapshot = self.service.get_vault_snapshot(new_context)
        self.assertEqual(
            {entity.entity_id for entity in snapshot.entities},
            {entity_a, entity_b},
        )
        stored_after = self.repository.ciphertext_snapshot()
        self.assertEqual(
            stored_after["scoped_entities"],
            entity_ciphertext_before,
        )
        self.assertEqual(
            stored_after["protection_scopes"],
            scope_envelopes_before,
        )
        self.service.lock(new_context)

    def test_snapshot_count_and_input_bounds_fail_instead_of_truncating(
        self,
    ) -> None:
        context = self.unlock(self.scope_a)
        first = self.service.create_entity(
            context,
            self.scope_a,
            "First",
            {"value": 1},
        )
        second = self.service.create_entity(
            context,
            self.scope_a,
            "Second",
            {"value": 2},
        )
        self.service.connect(
            context,
            self.scope_a,
            first,
            second,
            "FIRST_LINK",
        )
        self.service.connect(
            context,
            self.scope_a,
            second,
            first,
            "SECOND_LINK",
        )

        with self.assertRaises(ValidationError):
            self.service.get_vault_snapshot(
                context,
                entity_limit=1,
            )
        with self.assertRaises(ValidationError):
            self.service.get_vault_snapshot(
                context,
                relationship_limit=1,
            )
        for invalid_entity_limit in (
            0,
            MAX_VAULT_SNAPSHOT_ENTITIES + 1,
        ):
            with self.assertRaises(ValidationError):
                self.service.get_vault_snapshot(
                    context,
                    entity_limit=invalid_entity_limit,
                )
        for invalid_relationship_limit in (
            0,
            MAX_VAULT_SNAPSHOT_RELATIONSHIPS + 1,
        ):
            with self.assertRaises(ValidationError):
                self.service.get_vault_snapshot(
                    context,
                    relationship_limit=invalid_relationship_limit,
                )
        self.service.lock(context)

    def test_repository_snapshot_contains_ciphertext_not_semantics(self) -> None:
        context = self.unlock(self.scope_a, self.scope_b)
        first = self.service.create_entity(
            context,
            self.scope_a,
            "HighlySensitiveProfile",
            {"secret": "never-store-this-profile-plaintext"},
        )
        second = self.service.create_entity(
            context,
            self.scope_b,
            "HighlySensitiveOrder",
            {"secret": "never-store-this-order-plaintext"},
        )
        self.service.connect(
            context,
            self.scope_a,
            first,
            second,
            "HIGHLY_SENSITIVE_CONNECTION",
            {"secret": "never-store-this-link-plaintext"},
        )
        self.service.lock(context)

        storage = self.repository.ciphertext_snapshot()
        serialized = json.dumps(storage, sort_keys=True)
        for plaintext in (
            "HighlySensitiveProfile",
            "HighlySensitiveOrder",
            "HIGHLY_SENSITIVE_CONNECTION",
            "never-store-this-profile-plaintext",
            "never-store-this-order-plaintext",
            "never-store-this-link-plaintext",
        ):
            self.assertNotIn(plaintext, serialized)
        self.assertEqual(len(storage["entities"]), 0)
        self.assertEqual(len(storage["relationships"]), 0)
        self.assertEqual(
            {
                row["payload"]["version"]
                for row in storage["scoped_entities"]
            },
            {2},
        )
        self.assertEqual(
            {
                row["payload"]["version"]
                for row in storage["scoped_relationships"]
            },
            {2},
        )
        self.assertEqual(storage["vaults"][0]["envelope"]["version"], 2)


if __name__ == "__main__":
    unittest.main()
