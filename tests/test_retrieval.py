from __future__ import annotations

import inspect
import json
import math
import unittest
from unittest.mock import patch

from authgraph import (
    AuthGraphService,
    ConflictError,
    CryptoEngine,
    GraphPolicy,
    InMemoryGraphRepository,
    InMemoryPublicGraphRepository,
    InMemorySessionBroker,
    KdfParameters,
    LayeredGraphService,
    ProtectionLevel,
    SessionUnavailable,
    ValidationError,
)
from authgraph.retrieval import (
    HARD_MAX_HOPS,
    HARD_MAX_VECTOR_DIMENSIONS,
    HARD_MAX_VECTOR_ITEMS,
    HARD_MAX_VECTOR_VALUES,
    MAX_QUERY_CHARS,
    DisclosurePolicy,
    EphemeralVectorIndex,
    RetrievalLimit,
    RetrievalSource,
    SessionBoundRetrievalTool,
    SessionVisibleGraphGateway,
)


class SessionVisibleGraphGatewayTests(unittest.TestCase):
    PASSWORD = bytearray(b"correct horse battery staple for retrieval")
    OTHER_PASSWORD = bytearray(b"other correct horse battery staple")

    def setUp(self) -> None:
        self.private_repository = InMemoryGraphRepository()
        self.public_repository = InMemoryPublicGraphRepository()
        self.sessions = InMemorySessionBroker(
            default_ttl_seconds=60,
            max_ttl_seconds=300,
            sweep_interval_seconds=None,
        )
        self.addCleanup(self.sessions.close_all)
        self.protected = AuthGraphService(
            self.private_repository,
            CryptoEngine(
                KdfParameters.insecure_for_testing(),
                allow_insecure_kdf_for_testing=True,
            ),
            self.sessions,
        )
        self.publisher = object()
        self.layered = LayeredGraphService(
            self.protected,
            self.public_repository,
            default_policy=GraphPolicy(allow_public_overrides=True),
            public_write_authorizer=(
                lambda publisher, graph_id: (
                    publisher is self.publisher
                    and graph_id
                    in {
                        "support",
                        "other-graph",
                    }
                )
            ),
        )
        self.vault_id = self.protected.create_vault(
            "idp|owner",
            self.PASSWORD,
        )
        self.context = self.protected.unlock(
            "idp|owner",
            self.vault_id,
            self.PASSWORD,
        )

    def gateway(
        self,
        *,
        allowed_entity_kinds: frozenset[str],
        allowed_relationship_kinds: frozenset[str] = frozenset(),
        entity_property_allowlist: dict[str, frozenset[str]] | None = None,
        relationship_property_allowlist: (
            dict[str, frozenset[str]] | None
        ) = None,
        **limits: int,
    ) -> SessionVisibleGraphGateway:
        return SessionVisibleGraphGateway(
            self.layered,
            graph_id="support",
            policy=DisclosurePolicy(
                allowed_entity_kinds=allowed_entity_kinds,
                allowed_relationship_kinds=allowed_relationship_kinds,
                entity_property_allowlist=(
                    {}
                    if entity_property_allowlist is None
                    else entity_property_allowlist
                ),
                relationship_property_allowlist=(
                    {}
                    if relationship_property_allowlist is None
                    else relationship_property_allowlist
                ),
                **limits,
            ),
        )

    def public_entity(
        self,
        kind: str,
        properties: dict[str, object],
    ):
        return self.layered.create_entity(
            "support",
            kind,
            properties,
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )

    def test_locked_view_is_public_only_and_allowed_properties_drive_search(
        self,
    ) -> None:
        public = self.public_entity(
            "FAQ",
            {
                "title": "Shipping help",
                "answer": "Public tracking guidance",
            },
        )
        private = self.layered.create_entity(
            "support",
            "Order",
            {
                "status": "delayed",
                "internal_note": "needle-secret",
            },
            context=self.context,
        )
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"FAQ", "Order"}),
            entity_property_allowlist={
                "FAQ": frozenset({"title", "answer"}),
                "Order": frozenset({"status"}),
            },
        )

        locked = gateway.retrieve("tracking guidance")
        self.assertEqual(
            [entity.entity_id for entity in locked.entities],
            [public.entity_id],
        )
        self.assertEqual(gateway.retrieve("delayed").entities, ())

        unlocked = gateway.retrieve("delayed", context=self.context)
        self.assertEqual(
            [entity.entity_id for entity in unlocked.entities],
            [private.entity_id],
        )
        self.assertEqual(unlocked.entities[0].properties, {"status": "delayed"})
        self.assertNotIn("needle-secret", repr(unlocked))

        # A hidden property cannot influence seed selection.
        hidden_property_query = gateway.retrieve(
            "needle secret",
            context=self.context,
        )
        self.assertEqual(hidden_property_query.entities, ())

    def test_unlocked_retrieval_never_composes_another_owner(self) -> None:
        own = self.layered.create_entity(
            "support",
            "Order",
            {"status": "owner-sentinel"},
            context=self.context,
        )
        other_vault = self.protected.create_vault(
            "idp|other",
            self.OTHER_PASSWORD,
        )
        other_context = self.protected.unlock(
            "idp|other",
            other_vault,
            self.OTHER_PASSWORD,
        )
        other = self.layered.create_entity(
            "support",
            "Order",
            {"status": "other-sentinel"},
            context=other_context,
        )
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"Order"}),
            entity_property_allowlist={
                "Order": frozenset({"status"}),
            },
        )

        own_result = gateway.retrieve(
            "sentinel",
            context=self.context,
        )
        other_result = gateway.retrieve(
            "sentinel",
            context=other_context,
        )
        self.assertEqual(
            [entity.entity_id for entity in own_result.entities],
            [own.entity_id],
        )
        self.assertNotIn(other.entity_id, repr(own_result))
        self.assertEqual(
            [entity.entity_id for entity in other_result.entities],
            [other.entity_id],
        )
        self.assertNotIn(own.entity_id, repr(other_result))

    def test_deterministic_lexical_ranking_and_candidate_cap(self) -> None:
        strongest = self.public_entity(
            "Note",
            {"text": "alpha alpha"},
        )
        tied = [
            self.public_entity("Note", {"text": "alpha"}),
            self.public_entity("Note", {"text": "alpha"}),
        ]
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"Note"}),
            entity_property_allowlist={
                "Note": frozenset({"text"}),
            },
            max_candidates=2,
            max_nodes=2,
            max_hops=0,
        )

        first = gateway.retrieve("alpha alpha")
        second = gateway.retrieve("alpha alpha")
        expected_tie = min(reference.entity_id for reference in tied)
        self.assertEqual(first, second)
        self.assertEqual(
            [entity.entity_id for entity in first.entities],
            [strongest.entity_id, expected_tie],
        )
        self.assertIn(RetrievalLimit.CANDIDATES, first.limits_reached)
        self.assertEqual(
            first.entities[0].provenance.sources,
            (RetrievalSource.LEXICAL,),
        )
        self.assertEqual(first.entities[0].provenance.lexical_score, 2)

    def test_bounded_traversal_filters_relationship_properties_and_tracks_path(
        self,
    ) -> None:
        root = self.public_entity("Topic", {"name": "startword"})
        middle = self.public_entity("Topic", {"name": "middle"})
        end = self.public_entity("Topic", {"name": "end"})
        first_edge = self.layered.connect(
            "support",
            root,
            middle,
            "LINK",
            {
                "label": "visible-label",
                "secret": "hidden-edge-secret",
            },
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        self.layered.connect(
            "support",
            middle,
            end,
            "LINK",
            {"label": "second"},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"Topic"}),
            allowed_relationship_kinds=frozenset({"LINK"}),
            entity_property_allowlist={
                "Topic": frozenset({"name"}),
            },
            relationship_property_allowlist={
                "LINK": frozenset({"label"}),
            },
            max_candidates=1,
            max_nodes=5,
            max_edges=5,
            max_hops=1,
        )

        result = gateway.retrieve("startword")
        self.assertEqual(
            {entity.entity_id for entity in result.entities},
            {root.entity_id, middle.entity_id},
        )
        self.assertNotIn(end.entity_id, repr(result))
        self.assertEqual(
            [relationship.relationship_id for relationship in result.relationships],
            [first_edge.relationship_id],
        )
        self.assertEqual(
            result.relationships[0].properties,
            {"label": "visible-label"},
        )
        self.assertNotIn("hidden-edge-secret", repr(result))
        traversed = next(
            entity
            for entity in result.entities
            if entity.entity_id == middle.entity_id
        )
        self.assertEqual(
            traversed.provenance.sources,
            (RetrievalSource.TRAVERSAL,),
        )
        self.assertEqual(traversed.provenance.hop, 1)
        self.assertEqual(
            traversed.provenance.via_relationship_id,
            first_edge.relationship_id,
        )
        self.assertIn(RetrievalLimit.HOPS, result.limits_reached)

    def test_complete_one_hop_result_is_not_marked_as_hop_truncated(self) -> None:
        root = self.public_entity("Topic", {"name": "complete-root"})
        neighbor = self.public_entity("Topic", {"name": "only-neighbor"})
        self.layered.connect(
            "support",
            root,
            neighbor,
            "LINK",
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"Topic"}),
            allowed_relationship_kinds=frozenset({"LINK"}),
            entity_property_allowlist={
                "Topic": frozenset({"name"}),
            },
            max_candidates=1,
            max_nodes=5,
            max_edges=5,
            max_hops=1,
        )

        result = gateway.retrieve("complete root")
        self.assertEqual(len(result.entities), 2)
        self.assertEqual(len(result.relationships), 1)
        self.assertNotIn(RetrievalLimit.HOPS, result.limits_reached)
        self.assertFalse(result.truncated)

    def test_node_edge_and_output_budgets_fail_bounded(self) -> None:
        root = self.public_entity(
            "Topic",
            {"name": "budget-root " + ("x" * 5_000)},
        )
        neighbor = self.public_entity("Topic", {"name": "neighbor"})
        self.layered.connect(
            "support",
            root,
            neighbor,
            "LINK",
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        common = {
            "allowed_entity_kinds": frozenset({"Topic"}),
            "allowed_relationship_kinds": frozenset({"LINK"}),
            "entity_property_allowlist": {
                "Topic": frozenset({"name"}),
            },
        }

        node_limited = self.gateway(
            **common,
            max_nodes=1,
            max_edges=5,
            max_hops=1,
        ).retrieve("budget root")
        self.assertEqual(
            [entity.entity_id for entity in node_limited.entities],
            [root.entity_id],
        )
        self.assertIn(RetrievalLimit.NODES, node_limited.limits_reached)

        edge_limited = self.gateway(
            **common,
            max_nodes=5,
            max_edges=0,
            max_hops=1,
        ).retrieve("budget root")
        self.assertEqual(
            [entity.entity_id for entity in edge_limited.entities],
            [root.entity_id],
        )
        self.assertIn(RetrievalLimit.EDGES, edge_limited.limits_reached)

        byte_limited = self.gateway(
            **common,
            max_plaintext_bytes=1_000,
        ).retrieve("budget root")
        self.assertEqual(byte_limited.entities, ())
        self.assertIn(
            RetrievalLimit.PLAINTEXT_BYTES,
            byte_limited.limits_reached,
        )
        self.assertEqual(
            len(byte_limited.canonical_json_bytes()),
            byte_limited.plaintext_bytes,
        )
        self.assertLessEqual(byte_limited.plaintext_bytes, 1_000)

        token_limited = self.gateway(
            **common,
            max_plaintext_bytes=256 * 1024,
            max_token_estimate=256,
        ).retrieve("budget root")
        self.assertEqual(token_limited.entities, ())
        self.assertIn(
            RetrievalLimit.TOKEN_ESTIMATE,
            token_limited.limits_reached,
        )
        self.assertEqual(
            token_limited.token_estimate,
            (token_limited.plaintext_bytes + 3) // 4,
        )
        self.assertLessEqual(token_limited.token_estimate, 256)

    def test_reported_plaintext_bytes_cover_complete_canonical_result(
        self,
    ) -> None:
        entity = self.public_entity(
            "FAQ",
            {"title": "Unicode shipping: 🚚"},
        )
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"FAQ"}),
            entity_property_allowlist={
                "FAQ": frozenset({"title"}),
            },
        )

        result = gateway.retrieve("Unicode shipping")
        canonical = result.canonical_json_bytes()

        self.assertEqual([item.entity_id for item in result.entities], [
            entity.entity_id
        ])
        self.assertEqual(len(canonical), result.plaintext_bytes)
        self.assertEqual(
            result.token_estimate,
            (len(canonical) + 3) // 4,
        )
        self.assertLessEqual(
            result.plaintext_bytes,
            gateway.policy.max_plaintext_bytes,
        )
        self.assertLessEqual(
            result.token_estimate,
            gateway.policy.max_token_estimate,
        )

    def test_vector_seed_is_optional_intersected_with_visible_entities(
        self,
    ) -> None:
        closest = self.public_entity(
            "Article",
            {
                "title": "Closest",
                "hidden_note": "must-never-reach-embedder",
            },
        )
        other = self.public_entity("Article", {"title": "Other"})
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"Article"}),
            entity_property_allowlist={
                "Article": frozenset({"title"}),
            },
            max_candidates=1,
            max_nodes=1,
            max_hops=0,
        )
        embedded_documents: list[str] = []

        def embed_entity(document: str) -> tuple[float, float]:
            embedded_documents.append(document)
            if '"title":"Closest"' in document:
                return (0.9, 0.1)
            return (0.0, 1.0)

        index = gateway.build_vector_index(
            dimension=2,
            max_items=3,
            entity_embedder=embed_entity,
        )
        self.addCleanup(index.close)

        result = gateway.retrieve(
            "",
            vector_index=index,
            query_embedding=[1.0, 0.0],
        )
        self.assertEqual(
            [entity.entity_id for entity in result.entities],
            [closest.entity_id],
        )
        self.assertEqual(
            result.entities[0].provenance.sources,
            (RetrievalSource.VECTOR,),
        )
        self.assertIsNotNone(result.entities[0].provenance.vector_score)
        self.assertIn(RetrievalLimit.CANDIDATES, result.limits_reached)
        self.assertEqual(len(embedded_documents), 2)
        self.assertNotIn(
            "must-never-reach-embedder",
            "\n".join(embedded_documents),
        )
        with self.assertRaises(ConflictError):
            index.add(other.entity_id, [1.0, 0.0])

    def test_vector_arguments_are_paired_and_session_lifecycle_is_enforced(
        self,
    ) -> None:
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"Article"}),
        )
        index = EphemeralVectorIndex(2)
        with self.assertRaises(ValidationError):
            gateway.retrieve("", vector_index=index)
        with self.assertRaises(ValidationError):
            gateway.retrieve("", query_embedding=[1.0, 0.0])
        with self.assertRaisesRegex(
            ValidationError,
            "Vector index is not bound",
        ):
            gateway.retrieve(
                "",
                vector_index=index,
                query_embedding=[1.0, 0.0],
            )
        with self.assertRaisesRegex(
            ValidationError,
            "Vector index is not bound",
        ):
            SessionBoundRetrievalTool(
                gateway,
                vector_index=index,
                query_embedder=lambda question: (1.0, 0.0),
            )
        index.close()
        with self.assertRaises(SessionUnavailable):
            gateway.retrieve(
                "",
                vector_index=index,
                query_embedding=[1.0, 0.0],
            )

    def test_vector_index_is_bound_to_exact_gateway_and_context(self) -> None:
        self.public_entity("Article", {"title": "Public"})
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"Article"}),
            entity_property_allowlist={
                "Article": frozenset({"title"}),
            },
        )
        other_gateway = self.gateway(
            allowed_entity_kinds=frozenset({"Article"}),
            entity_property_allowlist={
                "Article": frozenset({"title"}),
            },
        )
        index = gateway.build_vector_index(
            dimension=2,
            entity_embedder=lambda document: (1.0, 0.0),
        )
        self.addCleanup(index.close)

        with self.assertRaisesRegex(
            ValidationError,
            "Vector index is not bound",
        ):
            other_gateway.retrieve(
                "",
                vector_index=index,
                query_embedding=[1.0, 0.0],
            )
        with self.assertRaisesRegex(
            ValidationError,
            "Vector index is not bound",
        ):
            gateway.retrieve(
                "",
                context=self.context,
                vector_index=index,
                query_embedding=[1.0, 0.0],
            )

    def test_model_facing_method_has_no_scope_limit_or_cypher_selectors(
        self,
    ) -> None:
        parameters = inspect.signature(
            SessionVisibleGraphGateway.retrieve
        ).parameters
        self.assertNotIn("principal_id", parameters)
        self.assertNotIn("vault_id", parameters)
        self.assertNotIn("cypher", parameters)
        self.assertNotIn("max_nodes", parameters)
        self.assertNotIn("max_hops", parameters)

        # Cypher-looking text remains ordinary lexical text and is never sent
        # to a repository as a query.
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"FAQ"}),
        )
        tool = SessionBoundRetrievalTool(
            gateway,
            context=self.context,
        )
        self.assertEqual(
            tuple(inspect.signature(tool.search).parameters),
            ("question",),
        )
        self.assertEqual(
            tool.search("MATCH (n) DETACH DELETE n").entities,
            (),
        )

    def test_question_only_tool_binds_vector_inputs_out_of_band(self) -> None:
        article = self.public_entity("Article", {"title": "Nearest"})
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"Article"}),
            entity_property_allowlist={
                "Article": frozenset({"title"}),
            },
            max_candidates=1,
            max_nodes=1,
            max_hops=0,
        )
        index = gateway.build_vector_index(
            dimension=2,
            entity_embedder=lambda document: (1.0, 0.0),
        )
        self.addCleanup(index.close)
        embedded_questions: list[str] = []

        def embed(question: str) -> tuple[float, float]:
            embedded_questions.append(question)
            return (1.0, 0.0)

        tool = SessionBoundRetrievalTool(
            gateway,
            vector_index=index,
            query_embedder=embed,
        )
        result = tool.search("Where is it?")

        self.assertEqual(embedded_questions, ["Where is it?"])
        self.assertEqual(
            [entity.entity_id for entity in result.entities],
            [article.entity_id],
        )
        self.assertIn(
            RetrievalSource.VECTOR,
            result.entities[0].provenance.sources,
        )

    def test_question_only_tool_validates_before_calling_embedder(self) -> None:
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"Article"}),
        )
        index = gateway.build_vector_index(
            dimension=2,
            entity_embedder=lambda document: (1.0, 0.0),
        )
        self.addCleanup(index.close)
        embedded_questions: list[str] = []

        def embed(question: str) -> tuple[float, float]:
            embedded_questions.append(question)
            return (1.0, 0.0)

        tool = SessionBoundRetrievalTool(
            gateway,
            vector_index=index,
            query_embedder=embed,
        )

        with self.assertRaisesRegex(
            ValidationError,
            "Retrieval query must be bounded text.",
        ):
            tool.search(123)  # type: ignore[arg-type]
        with self.assertRaisesRegex(
            ValidationError,
            "Retrieval query must be bounded text.",
        ):
            tool.search("x" * (MAX_QUERY_CHARS + 1))

        self.assertEqual(embedded_questions, [])

    def test_result_properties_are_deeply_immutable_and_stay_accounted(
        self,
    ) -> None:
        root = self.public_entity(
            "Topic",
            {
                "name": "immutable root",
                "profile": {"city": "Berlin"},
                "tags": [{"label": "priority"}],
            },
        )
        neighbor = self.public_entity(
            "Topic",
            {"name": "immutable neighbor"},
        )
        relationship = self.layered.connect(
            "support",
            root,
            neighbor,
            "LINK",
            {
                "metadata": {"channel": "support"},
                "labels": ["open"],
            },
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"Topic"}),
            allowed_relationship_kinds=frozenset({"LINK"}),
            entity_property_allowlist={
                "Topic": frozenset({"name", "profile", "tags"}),
            },
            relationship_property_allowlist={
                "LINK": frozenset({"metadata", "labels"}),
            },
            max_candidates=1,
            max_nodes=2,
            max_edges=1,
            max_hops=1,
        )

        result = gateway.retrieve("immutable root")
        root_result = next(
            entity
            for entity in result.entities
            if entity.entity_id == root.entity_id
        )
        relationship_result = next(
            item
            for item in result.relationships
            if item.relationship_id == relationship.relationship_id
        )
        canonical = result.canonical_json_bytes()

        with self.assertRaises(TypeError):
            root_result.properties["new"] = "unaccounted"
        with self.assertRaises(TypeError):
            root_result.properties["profile"]["city"] = "changed"
        with self.assertRaises(TypeError):
            root_result.properties["tags"][0]["label"] = "changed"
        with self.assertRaises(AttributeError):
            root_result.properties["tags"].append("changed")
        with self.assertRaises(TypeError):
            relationship_result.properties["metadata"]["channel"] = "changed"
        with self.assertRaises(AttributeError):
            relationship_result.properties["labels"].append("changed")

        self.assertEqual(result.canonical_json_bytes(), canonical)
        self.assertEqual(result.plaintext_bytes, len(canonical))
        decoded = json.loads(canonical)
        decoded_root = next(
            entity
            for entity in decoded["entities"]
            if entity["entity_id"] == root.entity_id
        )
        self.assertEqual(
            decoded_root["properties"]["tags"],
            [{"label": "priority"}],
        )

    def test_current_unlocked_gateway_still_calls_full_vault_snapshot(self) -> None:
        current = self.layered.create_entity(
            "support",
            "Order",
            {"status": "visible-current"},
            context=self.context,
        )
        unrelated = self.layered.create_entity(
            "other-graph",
            "OtherSecret",
            {"value": "must-not-return"},
            context=self.context,
        )
        gateway = self.gateway(
            allowed_entity_kinds=frozenset({"Order", "OtherSecret"}),
            entity_property_allowlist={
                "*": frozenset({"*"}),
            },
        )

        with patch.object(
            self.protected,
            "get_vault_snapshot",
            wraps=self.protected.get_vault_snapshot,
        ) as snapshot:
            result = gateway.retrieve(
                "visible current",
                context=self.context,
            )

        snapshot.assert_called_once()
        self.assertEqual(
            [entity.entity_id for entity in result.entities],
            [current.entity_id],
        )
        self.assertNotIn(unrelated.entity_id, repr(result))
        self.assertNotIn("must-not-return", repr(result))

    def test_disclosure_policy_rejects_unsafe_or_malformed_bounds(self) -> None:
        with self.assertRaises(ValidationError):
            DisclosurePolicy(max_hops=HARD_MAX_HOPS + 1)
        with self.assertRaises(ValidationError):
            DisclosurePolicy(max_edges=-1)
        with self.assertRaises(ValidationError):
            DisclosurePolicy(max_nodes=True)
        with self.assertRaises(ValidationError):
            DisclosurePolicy(
                entity_property_allowlist={
                    "Topic": frozenset({"bad\x00property"}),
                }
            )
        with self.assertRaises(ValidationError):
            self.gateway(
                allowed_entity_kinds=frozenset({"Topic"}),
                max_plaintext_bytes=1,
            )


class EphemeralVectorIndexTests(unittest.TestCase):
    def test_cosine_top_k_is_deterministic_and_validated(self) -> None:
        index = EphemeralVectorIndex(2, max_items=3)
        self.addCleanup(index.close)
        index.add("entity-b", [1.0, 0.0])
        index.add("entity-a", [2.0, 0.0])
        index.add("entity-c", [0.0, 1.0])

        matches = index.search([1.0, 0.0], top_k=3)
        self.assertEqual(
            [match.entity_id for match in matches],
            ["entity-a", "entity-b", "entity-c"],
        )
        self.assertAlmostEqual(matches[0].score, 1.0)
        self.assertAlmostEqual(matches[2].score, 0.0)

        with self.assertRaises(ConflictError):
            index.add("entity-a", [1.0, 0.0])
        with self.assertRaises(ValidationError):
            index.add("entity-d", [1.0])
        with self.assertRaises(ValidationError):
            index.search([0.0, 0.0], top_k=1)
        with self.assertRaises(ValidationError):
            index.search([math.nan, 0.0], top_k=1)
        with self.assertRaises(ValidationError):
            index.search([1e308, 1e308], top_k=1)
        with self.assertRaises(ValidationError):
            index.search([10**10_000, 1], top_k=1)
        with self.assertRaises(ValidationError):
            index.search([1.0, 0.0], top_k=0)

    def test_item_capacity_and_hard_constructor_limits(self) -> None:
        index = EphemeralVectorIndex(1, max_items=1)
        self.addCleanup(index.close)
        index.add("first", [1.0])
        with self.assertRaises(ValidationError):
            index.add("second", [1.0])
        with self.assertRaises(ValidationError):
            EphemeralVectorIndex(HARD_MAX_VECTOR_DIMENSIONS + 1)
        with self.assertRaises(ValidationError):
            EphemeralVectorIndex(
                1,
                max_items=HARD_MAX_VECTOR_ITEMS + 1,
            )
        with self.assertRaises(ValidationError):
            EphemeralVectorIndex(
                HARD_MAX_VECTOR_DIMENSIONS,
                max_items=(
                    HARD_MAX_VECTOR_VALUES // HARD_MAX_VECTOR_DIMENSIONS + 1
                ),
            )

    def test_close_zeroes_resident_arrays_best_effort_and_fails_closed(
        self,
    ) -> None:
        index = EphemeralVectorIndex(2)
        index.add("secret-vector", [3.0, 4.0])
        resident = index._vectors["secret-vector"]

        index.close()
        index.close()

        self.assertTrue(index.closed)
        self.assertEqual(index.item_count, 0)
        self.assertEqual(list(resident), [0.0, 0.0])
        with self.assertRaises(SessionUnavailable):
            index.add("new", [1.0, 0.0])
        with self.assertRaises(SessionUnavailable):
            index.search([1.0, 0.0], top_k=1)

    def test_context_manager_closes_index(self) -> None:
        with EphemeralVectorIndex(1) as index:
            index.add("one", [1.0])
            self.assertEqual(index.item_count, 1)
        self.assertTrue(index.closed)


if __name__ == "__main__":
    unittest.main()
