from __future__ import annotations

import unittest

from authgraph import CryptoEngine, InMemoryGraphRepository, KdfParameters
from authgraph.errors import IntegrityViolation, SessionUnavailable
from authgraph.models import (
    LayeredEntity,
    LayeredGraphView,
    LayeredRelationship,
    LockedDisclosure,
    ProtectionLevel,
)
from authgraph.retrieval import (
    DisclosurePolicy,
    RetrievalSource,
    SessionVisibleGraphGateway,
)
from authgraph.scoped_retrieval import ScopedGraphViewAdapter
from authgraph.scoped_service import ScopedAuthGraphService
from authgraph.scoped_sessions import ScopedSessionBroker


class FakeClock:
    def __init__(self) -> None:
        self.value = 1_000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class StaticPublicProvider:
    def __init__(self, view: LayeredGraphView) -> None:
        self.view = view

    def get_public_view(self, graph_id: str) -> LayeredGraphView:
        return self.view

    def get_unlocked_view(
        self,
        graph_id: str,
        context: object,
    ) -> LayeredGraphView:
        return self.view


class ScopedGraphRagIntegrationTests(unittest.TestCase):
    PRINCIPAL = "idp|graphrag-owner"
    PASSPHRASE = bytearray(b"synthetic graphrag owner password")

    def setUp(self) -> None:
        self.clock = FakeClock()
        self.repository = InMemoryGraphRepository()
        self.sessions = ScopedSessionBroker(
            default_ttl_seconds=60,
            max_ttl_seconds=300,
            sweep_interval_seconds=None,
            clock=self.clock,
        )
        self.addCleanup(self.sessions.close_all)
        self.service = ScopedAuthGraphService(
            self.repository,
            CryptoEngine(
                KdfParameters.insecure_for_testing(),
                allow_insecure_kdf_for_testing=True,
            ),
            self.sessions,
            clock=self.clock,
        )
        self.vault_id = self.service.create_vault(
            self.PRINCIPAL,
            self.PASSPHRASE,
        )
        self.profile_scope = self.service.create_protection_scope(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
        )
        self.orders_scope = self.service.create_protection_scope(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
        )
        self.relationship_scope = self.service.create_protection_scope(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
        )
        setup = self.service.unlock(
            self.PRINCIPAL,
            self.vault_id,
            self.PASSPHRASE,
            (
                self.profile_scope,
                self.orders_scope,
                self.relationship_scope,
            ),
        )
        self.profile_id = self.service.create_entity(
            setup,
            self.profile_scope,
            "Profile",
            {"display_name": "Synthetic Owner", "internal_note": "redact"},
        )
        self.order_id = self.service.create_entity(
            setup,
            self.orders_scope,
            "Order",
            {"status": "delayed", "tracking": "TRACK-1"},
        )
        self.relationship_id = self.service.connect(
            setup,
            self.relationship_scope,
            self.profile_id,
            self.order_id,
            "PLACED",
            {"source": "test"},
        )
        self.service.lock(setup)

        self.adapter = ScopedGraphViewAdapter(
            self.service,
            graph_id="owner-knowledge",
        )
        self.gateway = SessionVisibleGraphGateway(
            self.adapter,
            graph_id="owner-knowledge",
            policy=DisclosurePolicy(
                allowed_entity_kinds=frozenset({"Profile", "Order"}),
                allowed_relationship_kinds=frozenset({"PLACED"}),
                entity_property_allowlist={
                    "Profile": frozenset({"display_name"}),
                    "Order": frozenset({"status", "tracking"}),
                },
                relationship_property_allowlist={
                    "PLACED": frozenset(),
                },
                max_candidates=10,
                max_nodes=10,
                max_edges=10,
                max_hops=1,
            ),
        )

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

    @staticmethod
    def public_view(
        *,
        entities: tuple[LayeredEntity, ...] = (),
        relationships: tuple[LayeredRelationship, ...] = (),
    ) -> LayeredGraphView:
        return LayeredGraphView(
            graph_id="owner-knowledge",
            entities=entities,
            relationships=relationships,
            private_overlay_included=False,
            locked_disclosure=LockedDisclosure.HIDDEN,
        )

    def adapter_with_public_view(
        self,
        view: LayeredGraphView,
    ) -> ScopedGraphViewAdapter:
        return ScopedGraphViewAdapter(
            self.service,
            graph_id="owner-knowledge",
            public_provider=StaticPublicProvider(view),
        )

    def test_locked_retrieval_reveals_no_private_existence(self) -> None:
        result = self.gateway.retrieve("delayed order")
        self.assertEqual(result.entities, ())
        self.assertEqual(result.relationships, ())

    def test_retrieval_uses_only_session_granted_scope(self) -> None:
        context = self.unlock(self.orders_scope)
        result = self.gateway.retrieve("delayed order", context=context)
        self.assertEqual(
            [(entity.kind, entity.properties) for entity in result.entities],
            [("Order", {"status": "delayed", "tracking": "TRACK-1"})],
        )
        self.assertEqual(result.relationships, ())
        serialized = repr(result)
        self.assertNotIn(self.orders_scope, serialized)
        self.assertNotIn(self.profile_scope, serialized)
        self.service.lock(context)

    def test_locked_or_expired_context_never_falls_back_to_public(self) -> None:
        locked = self.unlock(self.orders_scope)
        self.service.lock(locked)
        with self.assertRaises(SessionUnavailable):
            self.gateway.retrieve("delayed order", context=locked)

        expired = self.unlock(
            self.orders_scope,
            ttl_seconds=2,
        )
        self.clock.advance(3)
        with self.assertRaises(SessionUnavailable):
            self.gateway.retrieve("delayed order", context=expired)

    def test_relationship_requires_relation_and_both_endpoint_scopes(self) -> None:
        without_relation = self.unlock(
            self.profile_scope,
            self.orders_scope,
        )
        result = self.gateway.retrieve("Synthetic delayed", context=without_relation)
        self.assertEqual(len(result.entities), 2)
        self.assertEqual(result.relationships, ())
        self.service.lock(without_relation)

        without_profile_endpoint = self.unlock(
            self.orders_scope,
            self.relationship_scope,
        )
        result = self.gateway.retrieve(
            "delayed order",
            context=without_profile_endpoint,
        )
        self.assertEqual(
            [entity.kind for entity in result.entities],
            ["Order"],
        )
        self.assertEqual(result.relationships, ())
        self.service.lock(without_profile_endpoint)

        complete = self.unlock(
            self.profile_scope,
            self.orders_scope,
            self.relationship_scope,
        )
        result = self.gateway.retrieve("Synthetic", context=complete)
        self.assertEqual(
            [relationship.kind for relationship in result.relationships],
            ["PLACED"],
        )
        self.assertEqual(result.relationships[0].properties, {})
        canonical = result.canonical_json_bytes().decode("utf-8")
        for scope_id in (
            self.profile_scope,
            self.orders_scope,
            self.relationship_scope,
        ):
            self.assertNotIn(scope_id, canonical)
        self.service.lock(complete)

    def test_ephemeral_vector_seed_is_intersected_with_visible_scopes(
        self,
    ) -> None:
        context = self.unlock(self.orders_scope)
        embedded_documents: list[str] = []

        def embed_entity(document: str) -> tuple[float, float]:
            embedded_documents.append(document)
            return (1.0, 0.0)

        with self.gateway.build_vector_index(
            dimension=2,
            max_items=2,
            context=context,
            entity_embedder=embed_entity,
        ) as index:
            result = self.gateway.retrieve(
                "",
                context=context,
                vector_index=index,
                query_embedding=[1.0, 0.0],
            )
        self.assertEqual([entity.entity_id for entity in result.entities], [
            self.order_id
        ])
        self.assertIn(
            RetrievalSource.VECTOR,
            result.entities[0].provenance.sources,
        )
        self.assertEqual(len(embedded_documents), 1)
        self.assertIn("TRACK-1", embedded_documents[0])
        self.assertNotIn("Benjamin", embedded_documents[0])
        self.service.lock(context)

    def test_public_view_rejects_duplicate_entity_ids(self) -> None:
        first = LayeredEntity(
            entity_id="public-entity",
            kind="FAQ",
            properties={},
            protection=ProtectionLevel.PUBLIC,
        )
        duplicate = LayeredEntity(
            entity_id="public-entity",
            kind="Other",
            properties={},
            protection=ProtectionLevel.PUBLIC,
        )
        adapter = self.adapter_with_public_view(
            self.public_view(entities=(first, duplicate))
        )

        with self.assertRaises(IntegrityViolation):
            adapter.get_public_view("owner-knowledge")

    def test_public_view_rejects_duplicate_relationship_ids(self) -> None:
        first = LayeredEntity(
            entity_id="public-a",
            kind="FAQ",
            properties={},
            protection=ProtectionLevel.PUBLIC,
        )
        second = LayeredEntity(
            entity_id="public-b",
            kind="FAQ",
            properties={},
            protection=ProtectionLevel.PUBLIC,
        )
        relationship = LayeredRelationship(
            relationship_id="public-relationship",
            from_entity_id=first.entity_id,
            to_entity_id=second.entity_id,
            kind="LINK",
            properties={},
            protection=ProtectionLevel.PUBLIC,
        )
        duplicate = LayeredRelationship(
            relationship_id="public-relationship",
            from_entity_id=second.entity_id,
            to_entity_id=first.entity_id,
            kind="BACKLINK",
            properties={},
            protection=ProtectionLevel.PUBLIC,
        )
        adapter = self.adapter_with_public_view(
            self.public_view(
                entities=(first, second),
                relationships=(relationship, duplicate),
            )
        )

        with self.assertRaises(IntegrityViolation):
            adapter.get_public_view("owner-knowledge")

    def test_dangling_public_relationship_cannot_be_repaired_by_private_merge(
        self,
    ) -> None:
        public = LayeredEntity(
            entity_id="public-anchor",
            kind="FAQ",
            properties={},
            protection=ProtectionLevel.PUBLIC,
        )
        dangling = LayeredRelationship(
            relationship_id="dangling-public-relationship",
            from_entity_id=public.entity_id,
            to_entity_id=self.order_id,
            kind="LINK",
            properties={},
            protection=ProtectionLevel.PUBLIC,
        )
        adapter = self.adapter_with_public_view(
            self.public_view(
                entities=(public,),
                relationships=(dangling,),
            )
        )
        context = self.unlock(self.orders_scope)
        self.addCleanup(self.service.lock, context)

        with self.assertRaises(IntegrityViolation):
            adapter.get_unlocked_view("owner-knowledge", context)

    def test_public_private_entity_id_collision_fails_closed(self) -> None:
        colliding = LayeredEntity(
            entity_id=self.order_id,
            kind="FAQ",
            properties={},
            protection=ProtectionLevel.PUBLIC,
        )
        adapter = self.adapter_with_public_view(
            self.public_view(entities=(colliding,))
        )
        context = self.unlock(self.orders_scope)
        self.addCleanup(self.service.lock, context)

        with self.assertRaises(IntegrityViolation):
            adapter.get_unlocked_view("owner-knowledge", context)

    def test_public_private_relationship_id_collision_fails_closed(self) -> None:
        first = LayeredEntity(
            entity_id="public-a",
            kind="FAQ",
            properties={},
            protection=ProtectionLevel.PUBLIC,
        )
        second = LayeredEntity(
            entity_id="public-b",
            kind="FAQ",
            properties={},
            protection=ProtectionLevel.PUBLIC,
        )
        colliding = LayeredRelationship(
            relationship_id=self.relationship_id,
            from_entity_id=first.entity_id,
            to_entity_id=second.entity_id,
            kind="LINK",
            properties={},
            protection=ProtectionLevel.PUBLIC,
        )
        adapter = self.adapter_with_public_view(
            self.public_view(
                entities=(first, second),
                relationships=(colliding,),
            )
        )
        context = self.unlock(
            self.profile_scope,
            self.orders_scope,
            self.relationship_scope,
        )
        self.addCleanup(self.service.lock, context)

        with self.assertRaises(IntegrityViolation):
            adapter.get_unlocked_view("owner-knowledge", context)


if __name__ == "__main__":
    unittest.main()
