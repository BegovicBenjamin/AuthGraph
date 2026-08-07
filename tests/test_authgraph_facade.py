from __future__ import annotations

import unittest

from authgraph.authgraph import (
    PRIVATE_ENTITY_WRAPPER_KIND,
    PRIVATE_RELATIONSHIP_WRAPPER_KIND,
    PUBLIC_ANCHOR_WRAPPER_KIND,
    AuthGraph,
)
from authgraph.crypto import CryptoEngine
from authgraph.errors import (
    AuthorizationDenied,
    ConflictError,
    IntegrityViolation,
    RecordNotFound,
    SessionUnavailable,
    ValidationError,
)
from authgraph.memory_public_repository import InMemoryPublicGraphRepository
from authgraph.memory_repository import InMemoryGraphRepository
from authgraph.models import (
    GraphEntityRef,
    GraphPolicy,
    GraphRelationshipRef,
    KdfParameters,
    LockedDisclosure,
    ProtectionLevel,
)
from authgraph.retrieval import (
    DisclosurePolicy,
    LayeredGraphViewProvider,
    SessionVisibleGraphGateway,
)
from authgraph.scoped_service import ScopedAuthGraphService
from authgraph.scoped_sessions import ScopedSessionBroker


class AuthGraphFacadeTests(unittest.TestCase):
    PRINCIPAL = "idp|facade-tests|alice"
    PASSPHRASE = b"correct horse battery staple"

    def setUp(self) -> None:
        self.private_repository = InMemoryGraphRepository()
        self.public_repository = InMemoryPublicGraphRepository()
        self.crypto = CryptoEngine(
            KdfParameters.insecure_for_testing(),
            allow_insecure_kdf_for_testing=True,
        )
        self.sessions = ScopedSessionBroker(
            default_ttl_seconds=60,
            max_ttl_seconds=300,
            sweep_interval_seconds=None,
        )
        self.addCleanup(self.sessions.close_all)
        self.protected = ScopedAuthGraphService(
            self.private_repository,
            self.crypto,
            self.sessions,
        )
        self.publisher = object()
        self.graph = AuthGraph(
            self.protected,
            self.public_repository,
            default_policy=GraphPolicy(
                allow_public_overrides=True,
                locked_disclosure=LockedDisclosure.GENERIC_BADGE,
            ),
            public_write_authorizer=(
                lambda publisher, graph_id: (
                    publisher is self.publisher
                    and graph_id in {"support", "other"}
                )
            ),
        )
        self.vault_id = self.graph.create_vault(
            self.PRINCIPAL,
            self.PASSPHRASE,
        )
        self.scope_a = self.graph.create_scope(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
        )
        self.scope_b = self.graph.create_protection_scope(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
        )

    def unlock(self, *scope_ids: str):
        return self.graph.unlock(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
            tuple(scope_ids),
        )

    def test_private_default_round_trip_and_locked_view(self) -> None:
        self.assertIsInstance(self.graph, LayeredGraphViewProvider)
        context = self.unlock(self.scope_a)
        entity = self.graph.create_entity(
            "support",
            "Order",
            {"number": "ORDER-1001", "status": "delayed"},
            context=context,
            scope_id=self.scope_a,
        )

        resolved = self.graph.get_entity(
            "support",
            entity,
            context=context,
        )
        self.assertEqual(resolved.kind, "Order")
        self.assertEqual(resolved.properties["status"], "delayed")
        self.assertIs(resolved.protection, ProtectionLevel.PRIVATE)
        self.assertEqual(resolved.record_revision, 1)

        locked = self.graph.get_public_view("support")
        self.assertEqual(locked.entities, ())
        self.assertFalse(locked.private_overlay_included)
        self.assertIs(
            locked.locked_disclosure,
            LockedDisclosure.GENERIC_BADGE,
        )

        unlocked = self.graph.get_unlocked_view("support", context)
        self.assertEqual(
            [row.entity_id for row in unlocked.entities],
            [entity.entity_id],
        )
        self.assertTrue(unlocked.private_overlay_included)
        self.assertIs(unlocked.locked_disclosure, LockedDisclosure.HIDDEN)

        self.graph.lock(context)
        with self.assertRaises(SessionUnavailable):
            self.graph.get_unlocked_view("support", context)

    def test_public_entity_requires_authorized_publisher(self) -> None:
        with self.assertRaises(AuthorizationDenied):
            self.graph.create_entity(
                "support",
                "Product",
                {"name": "Headphones"},
                protection=ProtectionLevel.PUBLIC,
                publisher=object(),
            )

        entity = self.graph.create_entity(
            "support",
            "Product",
            {"name": "Headphones"},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        resolved = self.graph.get_entity("support", entity)
        self.assertEqual(resolved.properties["name"], "Headphones")
        self.assertIs(resolved.protection, ProtectionLevel.PUBLIC)
        self.assertEqual(
            self.graph.get_public_view("support").entities[0].entity_id,
            entity.entity_id,
        )

    def test_public_records_cannot_select_a_private_scope(self) -> None:
        with self.assertRaises(ValidationError):
            self.graph.create_entity(
                "support",
                "Product",
                {},
                scope_id=self.scope_a,
                protection=ProtectionLevel.PUBLIC,
                publisher=self.publisher,
            )

    def test_policy_must_explicitly_allow_public_override(self) -> None:
        strict = AuthGraph(
            self.protected,
            self.public_repository,
            public_write_authorizer=lambda publisher, graph_id: True,
        )
        with self.assertRaises(ValidationError):
            strict.create_entity(
                "support",
                "Product",
                {},
                protection=ProtectionLevel.PUBLIC,
                publisher=self.publisher,
            )

    def test_private_graph_id_isolation(self) -> None:
        context = self.unlock(self.scope_a)
        support = self.graph.create_entity(
            "support",
            "Order",
            {"secret": "support-secret"},
            context=context,
            scope_id=self.scope_a,
        )
        other = self.graph.create_entity(
            "other",
            "Profile",
            {"secret": "other-secret"},
            context=context,
            scope_id=self.scope_a,
        )

        support_view = self.graph.get_unlocked_view("support", context)
        self.assertEqual(
            [row.entity_id for row in support_view.entities],
            [support.entity_id],
        )
        self.assertNotIn("other-secret", repr(support_view))
        with self.assertRaises(RecordNotFound):
            self.graph.get_entity(
                "support",
                GraphEntityRef(
                    graph_id="support",
                    entity_id=other.entity_id,
                    protection=ProtectionLevel.PRIVATE,
                ),
                context=context,
            )

    def test_private_relationship_round_trip(self) -> None:
        context = self.unlock(self.scope_a, self.scope_b)
        first = self.graph.create_entity(
            "support",
            "Customer",
            {"name": "Synthetic Alice"},
            context=context,
            scope_id=self.scope_a,
        )
        second = self.graph.create_entity(
            "support",
            "Order",
            {"number": "ORDER-7"},
            context=context,
            scope_id=self.scope_b,
        )
        relationship = self.graph.connect(
            "support",
            first,
            second,
            "PLACED",
            {"channel": "web"},
            context=context,
            scope_id=self.scope_a,
        )

        view = self.graph.get_unlocked_view("support", context)
        self.assertEqual(len(view.entities), 2)
        self.assertEqual(len(view.relationships), 1)
        decoded = view.relationships[0]
        self.assertEqual(decoded.relationship_id, relationship.relationship_id)
        self.assertEqual(decoded.kind, "PLACED")
        self.assertEqual(decoded.properties["channel"], "web")
        self.assertIs(decoded.protection, ProtectionLevel.PRIVATE)
        record = self.graph.get_relationship(
            "support",
            relationship,
            context=context,
        )
        self.assertEqual(record.record_revision, 1)
        self.assertEqual(record.from_entity_id, first.entity_id)
        self.assertEqual(record.to_entity_id, second.entity_id)

    def test_private_entity_idempotency_update_and_delete(self) -> None:
        context = self.unlock(self.scope_a)
        first = self.graph.create_entity(
            "support",
            "Order",
            {"status": "processing"},
            context=context,
            scope_id=self.scope_a,
            idempotency_key="create-order-1001",
        )
        replay = self.graph.create_entity(
            "support",
            "Order",
            {"status": "processing"},
            context=context,
            scope_id=self.scope_a,
            idempotency_key="create-order-1001",
        )
        self.assertEqual(replay, first)

        with self.assertRaises(ConflictError):
            self.graph.create_entity(
                "support",
                "Order",
                {"status": "different"},
                context=context,
                scope_id=self.scope_a,
                idempotency_key="create-order-1001",
            )

        updated = self.graph.update_entity(
            "support",
            first,
            "Order",
            {"status": "shipped"},
            context=context,
            expected_revision=1,
        )
        self.assertEqual(updated.record_revision, 2)
        self.assertEqual(updated.properties["status"], "shipped")
        with self.assertRaises(ConflictError):
            self.graph.update_entity(
                "support",
                first,
                "Order",
                {"status": "stale"},
                context=context,
                expected_revision=1,
            )

        self.graph.delete_entity(
            "support",
            first,
            context=context,
            expected_revision=2,
        )
        with self.assertRaises(RecordNotFound):
            self.graph.get_entity("support", first, context=context)

    def test_private_relationship_idempotency_update_and_delete(self) -> None:
        context = self.unlock(self.scope_a)
        first = self.graph.create_entity(
            "support",
            "Customer",
            {},
            context=context,
            scope_id=self.scope_a,
        )
        second = self.graph.create_entity(
            "support",
            "Order",
            {},
            context=context,
            scope_id=self.scope_a,
        )
        relationship = self.graph.connect(
            "support",
            first,
            second,
            "PLACED",
            {"channel": "web"},
            context=context,
            scope_id=self.scope_a,
            idempotency_key="connect-order-1001",
        )
        replay = self.graph.connect(
            "support",
            first,
            second,
            "PLACED",
            {"channel": "web"},
            context=context,
            scope_id=self.scope_a,
            idempotency_key="connect-order-1001",
        )
        self.assertEqual(replay, relationship)

        updated = self.graph.update_relationship(
            "support",
            relationship,
            "PLACED",
            {"channel": "phone"},
            context=context,
            expected_revision=1,
        )
        self.assertEqual(updated.record_revision, 2)
        self.assertEqual(updated.properties["channel"], "phone")

        with self.assertRaises(ConflictError):
            self.graph.delete_entity(
                "support",
                first,
                context=context,
                expected_revision=1,
            )
        self.graph.delete_relationship(
            "support",
            relationship,
            context=context,
            expected_revision=2,
        )
        with self.assertRaises(RecordNotFound):
            self.graph.get_relationship(
                "support",
                relationship,
                context=context,
            )
        self.graph.delete_entity(
            "support",
            first,
            context=context,
            expected_revision=1,
        )

    def test_public_entity_crud_and_idempotent_create(self) -> None:
        first = self.graph.create_entity(
            "support",
            "Product",
            {"name": "Headphones"},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
            idempotency_key="public-product-1001",
        )
        replay = self.graph.create_entity(
            "support",
            "Product",
            {"name": "Headphones"},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
            idempotency_key="public-product-1001",
        )
        self.assertEqual(replay, first)
        self.assertIn("public_entity_", first.entity_id)

        with self.assertRaises(ConflictError):
            self.graph.create_entity(
                "support",
                "Product",
                {"name": "Different"},
                protection=ProtectionLevel.PUBLIC,
                publisher=self.publisher,
                idempotency_key="public-product-1001",
            )

        current = self.graph.get_entity("support", first)
        self.assertEqual(current.record_revision, 1)
        updated = self.graph.update_entity(
            "support",
            first,
            "Product",
            {"name": "Headphones v2"},
            expected_revision=1,
            publisher=self.publisher,
        )
        self.assertEqual(updated.record_revision, 2)
        self.assertEqual(updated.properties["name"], "Headphones v2")
        with self.assertRaises(ConflictError):
            self.graph.update_entity(
                "support",
                first,
                "Product",
                {"name": "stale"},
                expected_revision=1,
                publisher=self.publisher,
            )
        with self.assertRaises(AuthorizationDenied):
            self.graph.delete_entity(
                "support",
                first,
                expected_revision=2,
                publisher=object(),
            )
        self.graph.delete_entity(
            "support",
            first,
            expected_revision=2,
            publisher=self.publisher,
        )
        with self.assertRaises(RecordNotFound):
            self.graph.get_entity("support", first)

    def test_public_relationship_crud_and_idempotent_create(self) -> None:
        first = self.graph.create_entity(
            "support",
            "Product",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        second = self.graph.create_entity(
            "support",
            "Product",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        relationship = self.graph.connect(
            "support",
            first,
            second,
            "RELATED_TO",
            {"rank": 1},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
            idempotency_key="public-relationship-1001",
        )
        replay = self.graph.connect(
            "support",
            first,
            second,
            "RELATED_TO",
            {"rank": 1},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
            idempotency_key="public-relationship-1001",
        )
        self.assertEqual(replay, relationship)
        self.assertIn("public_relationship_", relationship.relationship_id)
        resolved = self.graph.get_relationship("support", relationship)
        self.assertEqual(resolved.from_entity_id, first.entity_id)
        self.assertEqual(resolved.to_entity_id, second.entity_id)
        self.assertEqual(resolved.record_revision, 1)

        with self.assertRaises(ConflictError):
            self.graph.connect(
                "support",
                first,
                second,
                "RELATED_TO",
                {"rank": 2},
                protection=ProtectionLevel.PUBLIC,
                publisher=self.publisher,
                idempotency_key="public-relationship-1001",
            )

        updated = self.graph.update_relationship(
            "support",
            relationship,
            "RELATED_TO",
            {"rank": 2},
            expected_revision=1,
            publisher=self.publisher,
        )
        self.assertEqual(updated.record_revision, 2)
        self.assertEqual(updated.properties["rank"], 2)
        with self.assertRaises(ConflictError):
            self.graph.delete_entity(
                "support",
                first,
                expected_revision=1,
                publisher=self.publisher,
            )
        self.graph.delete_relationship(
            "support",
            relationship,
            expected_revision=2,
            publisher=self.publisher,
        )
        with self.assertRaises(RecordNotFound):
            self.graph.get_relationship(
                "support",
                relationship,
            )
        self.graph.delete_entity(
            "support",
            first,
            expected_revision=1,
            publisher=self.publisher,
        )

    def test_scope_limited_view_omits_locked_endpoint_and_edge(self) -> None:
        all_scopes = self.unlock(self.scope_a, self.scope_b)
        first = self.graph.create_entity(
            "support",
            "Customer",
            {},
            context=all_scopes,
            scope_id=self.scope_a,
        )
        second = self.graph.create_entity(
            "support",
            "Order",
            {},
            context=all_scopes,
            scope_id=self.scope_b,
        )
        self.graph.connect(
            "support",
            first,
            second,
            "PLACED",
            context=all_scopes,
            scope_id=self.scope_a,
        )
        self.graph.lock(all_scopes)

        limited = self.unlock(self.scope_a)
        view = self.graph.get_unlocked_view("support", limited)
        self.assertEqual(
            [row.entity_id for row in view.entities],
            [first.entity_id],
        )
        self.assertEqual(view.relationships, ())

    def test_public_relationship_round_trip(self) -> None:
        first = self.graph.create_entity(
            "support",
            "Product",
            {"name": "Headphones"},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        second = self.graph.create_entity(
            "support",
            "Product",
            {"name": "Case"},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        relationship = self.graph.connect(
            "support",
            first,
            second,
            "RELATED_TO",
            {"rank": 1},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        view = self.graph.get_public_view("support")
        self.assertEqual(len(view.entities), 2)
        self.assertEqual(len(view.relationships), 1)
        self.assertEqual(
            view.relationships[0].relationship_id,
            relationship.relationship_id,
        )
        self.assertEqual(view.relationships[0].properties["rank"], 1)

    def test_forged_reference_does_not_select_another_store(self) -> None:
        context = self.unlock(self.scope_a)
        private = self.graph.create_entity(
            "support",
            "Order",
            {},
            context=context,
            scope_id=self.scope_a,
        )
        public = self.graph.create_entity(
            "support",
            "Product",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )

        forged_public = GraphEntityRef(
            graph_id="support",
            entity_id=private.entity_id,
            protection=ProtectionLevel.PUBLIC,
        )
        with self.assertRaises(RecordNotFound):
            self.graph.get_entity("support", forged_public)

        forged_private = GraphEntityRef(
            graph_id="support",
            entity_id=public.entity_id,
            protection=ProtectionLevel.PRIVATE,
        )
        with self.assertRaises(RecordNotFound):
            self.graph.get_entity(
                "support",
                forged_private,
                context=context,
            )

    def test_cross_graph_private_connection_fails(self) -> None:
        context = self.unlock(self.scope_a)
        first = self.graph.create_entity(
            "support",
            "Order",
            {},
            context=context,
            scope_id=self.scope_a,
        )
        other = self.graph.create_entity(
            "other",
            "Profile",
            {},
            context=context,
            scope_id=self.scope_a,
        )
        forged_other = GraphEntityRef(
            graph_id="support",
            entity_id=other.entity_id,
            protection=ProtectionLevel.PRIVATE,
        )
        with self.assertRaises(RecordNotFound):
            self.graph.connect(
                "support",
                first,
                forged_other,
                "LINKED",
                context=context,
                scope_id=self.scope_a,
            )

    def test_relationship_lookup_validates_actual_endpoint_graphs(self) -> None:
        context = self.unlock(self.scope_a)
        first = self.graph.create_entity(
            "support",
            "Order",
            {},
            context=context,
            scope_id=self.scope_a,
        )
        other = self.graph.create_entity(
            "other",
            "Profile",
            {},
            context=context,
            scope_id=self.scope_a,
        )
        raw_relationship_id = self.protected.connect(
            context,
            self.scope_a,
            first.entity_id,
            other.entity_id,
            PRIVATE_RELATIONSHIP_WRAPPER_KIND,
            {
                "graph_id": "support",
                "kind": "INVALID_CROSS_GRAPH_LINK",
                "properties": {},
            },
        )
        reference = GraphRelationshipRef(
            graph_id="support",
            relationship_id=raw_relationship_id,
            protection=ProtectionLevel.PRIVATE,
        )
        with self.assertRaises(RecordNotFound):
            self.graph.get_relationship(
                "support",
                reference,
                context=context,
            )

    def test_mixed_relationship_uses_an_encrypted_atomic_anchor(self) -> None:
        context = self.unlock(self.scope_a)
        private = self.graph.create_entity(
            "support",
            "Order",
            {},
            context=context,
            scope_id=self.scope_a,
        )
        public = self.graph.create_entity(
            "support",
            "Product",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        relationship = self.graph.connect(
            "support",
            private,
            public,
            "CONTAINS",
            {"quantity": 1},
            context=context,
            scope_id=self.scope_a,
        )
        after = self.private_repository.ciphertext_snapshot()
        self.assertEqual(len(after["scoped_entities"]), 2)
        self.assertEqual(len(after["scoped_relationships"]), 1)
        self.assertNotIn(public.entity_id, repr(after))

        resolved = self.graph.get_relationship(
            "support",
            relationship,
            context=context,
        )
        self.assertEqual(resolved.from_entity_id, private.entity_id)
        self.assertEqual(resolved.to_entity_id, public.entity_id)
        self.assertEqual(resolved.properties, {"quantity": 1})

        view = self.graph.get_unlocked_view("support", context)
        self.assertEqual(
            {entity.entity_id for entity in view.entities},
            {private.entity_id, public.entity_id},
        )
        self.assertEqual(view.relationships[0].from_entity_id, private.entity_id)
        self.assertEqual(view.relationships[0].to_entity_id, public.entity_id)

        before_delete = self.private_repository.ciphertext_snapshot()
        with self.assertRaises(ConflictError):
            self.graph.delete_relationship(
                "support",
                relationship,
                context=context,
                expected_revision=2,
            )
        self.assertEqual(
            self.private_repository.ciphertext_snapshot(),
            before_delete,
        )
        self.graph.delete_relationship(
            "support",
            relationship,
            context=context,
            expected_revision=1,
        )
        deleted = self.private_repository.ciphertext_snapshot()
        self.assertEqual(len(deleted["scoped_entities"]), 1)
        self.assertEqual(len(deleted["scoped_relationships"]), 0)

    def test_targeted_retrieval_resolves_mixed_anchor_and_current_public_row(
        self,
    ) -> None:
        context = self.unlock(self.scope_a)
        private = self.graph.create_entity(
            "support",
            "Order",
            {"status": "delayed"},
            context=context,
            scope_id=self.scope_a,
        )
        public = self.graph.create_entity(
            "support",
            "Product",
            {"name": "Headphones"},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        relationship = self.graph.connect(
            "support",
            private,
            public,
            "CONTAINS",
            context=context,
            scope_id=self.scope_a,
        )
        gateway = SessionVisibleGraphGateway(
            self.graph,
            graph_id="support",
            policy=DisclosurePolicy(
                allowed_entity_kinds=frozenset({"Order", "Product"}),
                allowed_relationship_kinds=frozenset({"CONTAINS"}),
                entity_property_allowlist={
                    "Order": frozenset({"status"}),
                    "Product": frozenset({"name"}),
                },
                relationship_property_allowlist={
                    "CONTAINS": frozenset(),
                },
                max_nodes=5,
                max_edges=5,
                max_hops=1,
            ),
        )
        baseline = gateway.retrieve("delayed", context=context)
        index = gateway.build_candidate_index(context=context)
        self.addCleanup(index.close)

        result = gateway.retrieve(
            "delayed",
            context=context,
            candidate_index=index,
        )
        self.assertEqual(result, baseline)
        self.assertEqual(
            [entity.entity_id for entity in result.entities],
            [private.entity_id, public.entity_id],
        )
        self.assertEqual(
            [row.relationship_id for row in result.relationships],
            [relationship.relationship_id],
        )
        self.assertEqual(
            result.relationships[0].to_entity_id,
            public.entity_id,
        )

        self.graph.delete_entity(
            "support",
            public,
            expected_revision=1,
            publisher=self.publisher,
        )
        stale_result = gateway.retrieve(
            "delayed",
            context=context,
            candidate_index=index,
        )
        self.assertEqual(
            [entity.entity_id for entity in stale_result.entities],
            [private.entity_id],
        )
        self.assertEqual(stale_result.relationships, ())

    def test_mixed_idempotency_replays_and_rejects_altered_intent(self) -> None:
        context = self.unlock(self.scope_a)
        private = self.graph.create_entity(
            "support",
            "Order",
            {},
            context=context,
            scope_id=self.scope_a,
        )
        public = self.graph.create_entity(
            "support",
            "Product",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        first = self.graph.connect(
            "support",
            private,
            public,
            "CONTAINS",
            {"quantity": 1},
            context=context,
            scope_id=self.scope_a,
            idempotency_key="mixed-edge",
        )
        before_replay = self.private_repository.ciphertext_snapshot()
        replay = self.graph.connect(
            "support",
            private,
            public,
            "CONTAINS",
            {"quantity": 1},
            context=context,
            scope_id=self.scope_a,
            idempotency_key="mixed-edge",
        )
        self.assertEqual(replay, first)
        self.assertEqual(
            self.private_repository.ciphertext_snapshot(),
            before_replay,
        )

        with self.assertRaises(ConflictError):
            self.graph.connect(
                "support",
                private,
                public,
                "CONTAINS",
                {"quantity": 2},
                context=context,
                scope_id=self.scope_a,
                idempotency_key="mixed-edge",
            )
        other_public = self.graph.create_entity(
            "support",
            "Product",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        with self.assertRaises(ConflictError):
            self.graph.connect(
                "support",
                private,
                other_public,
                "CONTAINS",
                {"quantity": 1},
                context=context,
                scope_id=self.scope_a,
                idempotency_key="mixed-edge",
            )
        self.assertEqual(
            self.private_repository.ciphertext_snapshot(),
            before_replay,
        )

    def test_private_edge_public_self_loop_reuses_one_idempotent_anchor(
        self,
    ) -> None:
        context = self.unlock(self.scope_a)
        public = self.graph.create_entity(
            "support",
            "Product",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        first = self.graph.connect(
            "support",
            public,
            public,
            "RELATED_TO_SELF",
            context=context,
            scope_id=self.scope_a,
            idempotency_key="public-self-loop",
        )
        replay = self.graph.connect(
            "support",
            public,
            public,
            "RELATED_TO_SELF",
            context=context,
            scope_id=self.scope_a,
            idempotency_key="public-self-loop",
        )
        self.assertEqual(replay, first)
        stored = self.private_repository.ciphertext_snapshot()
        self.assertEqual(len(stored["scoped_entities"]), 1)
        self.assertEqual(len(stored["scoped_relationships"]), 1)

        self.graph.delete_relationship(
            "support",
            first,
            context=context,
            expected_revision=1,
        )
        deleted = self.private_repository.ciphertext_snapshot()
        self.assertEqual(len(deleted["scoped_entities"]), 0)
        self.assertEqual(len(deleted["scoped_relationships"]), 0)

    def test_private_edge_between_public_entities_uses_two_anchors(
        self,
    ) -> None:
        context = self.unlock(self.scope_a)
        first_public = self.graph.create_entity(
            "support",
            "Product",
            {"name": "First"},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        second_public = self.graph.create_entity(
            "support",
            "Product",
            {"name": "Second"},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        first = self.graph.connect(
            "support",
            first_public,
            second_public,
            "RELATED_TO",
            context=context,
            scope_id=self.scope_a,
            idempotency_key="two-public-anchors",
        )
        replay = self.graph.connect(
            "support",
            first_public,
            second_public,
            "RELATED_TO",
            context=context,
            scope_id=self.scope_a,
            idempotency_key="two-public-anchors",
        )
        self.assertEqual(replay, first)
        stored = self.private_repository.ciphertext_snapshot()
        self.assertEqual(len(stored["scoped_entities"]), 2)
        self.assertEqual(len(stored["scoped_relationships"]), 1)

        self.graph.delete_relationship(
            "support",
            first,
            context=context,
            expected_revision=1,
        )
        deleted = self.private_repository.ciphertext_snapshot()
        self.assertEqual(len(deleted["scoped_entities"]), 0)
        self.assertEqual(len(deleted["scoped_relationships"]), 0)

    def test_deleted_public_endpoint_hides_and_can_clean_up_mixed_edge(
        self,
    ) -> None:
        context = self.unlock(self.scope_a)
        private = self.graph.create_entity(
            "support",
            "Order",
            {},
            context=context,
            scope_id=self.scope_a,
        )
        public = self.graph.create_entity(
            "support",
            "Product",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        relationship = self.graph.connect(
            "support",
            private,
            public,
            "CONTAINS",
            context=context,
            scope_id=self.scope_a,
        )
        self.graph.delete_entity(
            "support",
            public,
            expected_revision=1,
            publisher=self.publisher,
        )

        view = self.graph.get_unlocked_view("support", context)
        self.assertEqual(
            [entity.entity_id for entity in view.entities],
            [private.entity_id],
        )
        self.assertEqual(view.relationships, ())
        with self.assertRaises(RecordNotFound):
            self.graph.get_relationship(
                "support",
                relationship,
                context=context,
            )

        self.graph.delete_relationship(
            "support",
            relationship,
            context=context,
            expected_revision=1,
        )
        deleted = self.private_repository.ciphertext_snapshot()
        self.assertEqual(len(deleted["scoped_entities"]), 1)
        self.assertEqual(len(deleted["scoped_relationships"]), 0)

    def test_mixed_delete_leaves_everything_when_anchor_is_shared(
        self,
    ) -> None:
        context = self.unlock(self.scope_a)
        private = self.graph.create_entity(
            "support",
            "Order",
            {},
            context=context,
            scope_id=self.scope_a,
        )
        other_private = self.graph.create_entity(
            "support",
            "Order",
            {},
            context=context,
            scope_id=self.scope_a,
        )
        public = self.graph.create_entity(
            "support",
            "Product",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        relationship = self.graph.connect(
            "support",
            private,
            public,
            "CONTAINS",
            context=context,
            scope_id=self.scope_a,
        )
        snapshot = self.protected.get_vault_snapshot(context)
        anchor = next(
            entity
            for entity in snapshot.entities
            if entity.kind == PUBLIC_ANCHOR_WRAPPER_KIND
        )
        self.protected.connect(
            context,
            self.scope_a,
            anchor.entity_id,
            other_private.entity_id,
            "RAW_SHARED_ANCHOR",
        )
        before = self.private_repository.ciphertext_snapshot()

        with self.assertRaises(ConflictError):
            self.graph.delete_relationship(
                "support",
                relationship,
                context=context,
                expected_revision=1,
            )
        self.assertEqual(
            self.private_repository.ciphertext_snapshot(),
            before,
        )
        self.assertEqual(
            self.graph.get_relationship(
                "support",
                relationship,
                context=context,
            ).kind,
            "CONTAINS",
        )

    def test_raw_scoped_records_are_not_reinterpreted(self) -> None:
        context = self.unlock(self.scope_a)
        raw_id = self.protected.create_entity(
            context,
            self.scope_a,
            "RawLowLevelRecord",
            {"secret": "must-not-leak"},
        )
        view = self.graph.get_unlocked_view("support", context)
        self.assertEqual(view.entities, ())
        raw_ref = GraphEntityRef(
            graph_id="support",
            entity_id=raw_id,
            protection=ProtectionLevel.PRIVATE,
        )
        with self.assertRaises(RecordNotFound):
            self.graph.get_entity("support", raw_ref, context=context)

    def test_malformed_private_wrapper_fails_closed(self) -> None:
        context = self.unlock(self.scope_a)
        self.protected.create_entity(
            context,
            self.scope_a,
            PRIVATE_ENTITY_WRAPPER_KIND,
            {"graph_id": "support", "kind": "Order"},
        )
        with self.assertRaises(IntegrityViolation):
            self.graph.get_unlocked_view("support", context)


if __name__ == "__main__":
    unittest.main()
