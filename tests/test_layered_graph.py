from __future__ import annotations

import json
import unittest
from dataclasses import replace
from unittest.mock import patch

from authgraph import (
    AuthorizationDenied,
    AuthGraphService,
    CryptoEngine,
    GraphEntityRef,
    GraphPolicy,
    InMemoryGraphRepository,
    InMemoryPublicGraphRepository,
    InMemorySessionBroker,
    IntegrityViolation,
    KdfParameters,
    LayeredGraphService,
    LockedDisclosure,
    Neo4jPublicGraphRepository,
    ProtectionLevel,
    RecordNotFound,
    SessionUnavailable,
    ValidationError,
)
from authgraph.models import (
    PublicEntityRow,
    PublicGraphSnapshotRow,
    PublicRelationshipRow,
)
from authgraph.layered_service import (
    MAX_PUBLIC_SNAPSHOT_JSON_BYTES,
    PRIVATE_ENTITY_WRAPPER_KIND,
    PRIVATE_RELATIONSHIP_WRAPPER_KIND,
    PUBLIC_ANCHOR_WRAPPER_KIND,
)
from authgraph.neo4j_public_repository import (
    IncompleteCommit as PublicIncompleteCommit,
)


class RecordingDriver:
    encrypted = True

    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute_query(self, query: str, **kwargs: object) -> object:
        self.calls.append((query, kwargs))
        records = self.responses.pop(0)
        if isinstance(records, BaseException):
            raise records
        return type("Result", (), {"records": records})()


class LayeredGraphTests(unittest.TestCase):
    BENJAMIN_PASSWORD = bytearray(
        b"benjamin correct horse battery staple"
    )
    ALEXA_PASSWORD = bytearray(b"alexa correct horse battery staple")

    def setUp(self) -> None:
        self.private_repository = InMemoryGraphRepository()
        self.public_repository = InMemoryPublicGraphRepository()
        self.crypto = CryptoEngine(
            KdfParameters.insecure_for_testing(),
            allow_insecure_kdf_for_testing=True,
        )
        self.sessions = InMemorySessionBroker(
            default_ttl_seconds=60,
            max_ttl_seconds=300,
            sweep_interval_seconds=None,
        )
        self.addCleanup(self.sessions.close_all)
        self.protected = AuthGraphService(
            self.private_repository,
            self.crypto,
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
                        "customer-graph",
                        "empty-graph",
                        "populated-graph",
                        "public-catalog",
                    }
                )
            ),
        )
        self.benjamin_vault = self.protected.create_vault(
            "idp|benjamin",
            self.BENJAMIN_PASSWORD,
        )
        self.benjamin = self.protected.unlock(
            "idp|benjamin",
            self.benjamin_vault,
            self.BENJAMIN_PASSWORD,
        )

    def test_secure_defaults_store_private_and_locked_view_hides_everything(
        self,
    ) -> None:
        private = self.layered.create_entity(
            "customer-graph",
            "SecretProfile",
            {"favorite_color": "forest green"},
            context=self.benjamin,
        )

        self.assertIs(private.protection, ProtectionLevel.PRIVATE)
        self.assertEqual(self.public_repository.plaintext_snapshot().entities, ())
        raw_storage = json.dumps(
            self.private_repository.ciphertext_snapshot(),
            sort_keys=True,
        )
        self.assertNotIn("SecretProfile", raw_storage)
        self.assertNotIn("forest green", raw_storage)

        locked = self.layered.get_public_view("customer-graph")
        self.assertEqual(locked.entities, ())
        self.assertEqual(locked.relationships, ())
        self.assertFalse(locked.private_overlay_included)
        self.assertIs(locked.locked_disclosure, LockedDisclosure.HIDDEN)

        unlocked = self.layered.get_unlocked_view(
            "customer-graph",
            self.benjamin,
        )
        self.assertEqual(
            [(entity.kind, entity.properties) for entity in unlocked.entities],
            [("SecretProfile", {"favorite_color": "forest green"})],
        )
        self.assertIs(
            unlocked.entities[0].protection,
            ProtectionLevel.PRIVATE,
        )
        self.assertTrue(unlocked.private_overlay_included)
        self.assertIs(
            unlocked.locked_disclosure,
            LockedDisclosure.HIDDEN,
        )

    def test_per_record_public_private_choices_and_composed_relationships(
        self,
    ) -> None:
        person = self.layered.create_entity(
            "customer-graph",
            "Person",
            {"display_name": "Benjamin"},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        company = self.layered.create_entity(
            "customer-graph",
            "Company",
            {"name": "Example GmbH"},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        address = self.layered.create_entity(
            "customer-graph",
            "Address",
            {"city": "Private City"},
            context=self.benjamin,
            protection=ProtectionLevel.PRIVATE,
        )
        public_edge = self.layered.connect(
            "customer-graph",
            person,
            company,
            "WORKS_AT",
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        private_address_edge = self.layered.connect(
            "customer-graph",
            person,
            address,
            "LIVES_AT",
            context=self.benjamin,
            protection=ProtectionLevel.PRIVATE,
        )
        private_public_edge = self.layered.connect(
            "customer-graph",
            person,
            company,
            "HAS_PRIVATE_CONTRACT_WITH",
            {"contract": "C-123"},
            context=self.benjamin,
            protection=ProtectionLevel.PRIVATE,
        )

        locked = self.layered.get_public_view("customer-graph")
        self.assertEqual(
            {entity.kind for entity in locked.entities},
            {"Person", "Company"},
        )
        self.assertEqual(
            {relationship.kind for relationship in locked.relationships},
            {"WORKS_AT"},
        )
        locked_text = repr(locked)
        self.assertNotIn("Private City", locked_text)
        self.assertNotIn("C-123", locked_text)
        self.assertNotIn(address.entity_id, locked_text)

        unlocked = self.layered.get_unlocked_view(
            "customer-graph",
            self.benjamin,
        )
        self.assertEqual(
            {entity.kind for entity in unlocked.entities},
            {"Person", "Company", "Address"},
        )
        self.assertEqual(
            {relationship.kind for relationship in unlocked.relationships},
            {
                "WORKS_AT",
                "LIVES_AT",
                "HAS_PRIVATE_CONTRACT_WITH",
            },
        )
        relationships = {
            relationship.relationship_id: relationship
            for relationship in unlocked.relationships
        }
        self.assertIs(
            relationships[public_edge.relationship_id].protection,
            ProtectionLevel.PUBLIC,
        )
        self.assertEqual(
            relationships[private_address_edge.relationship_id].to_entity_id,
            address.entity_id,
        )
        self.assertEqual(
            relationships[private_public_edge.relationship_id].from_entity_id,
            person.entity_id,
        )
        self.assertEqual(
            relationships[private_public_edge.relationship_id].to_entity_id,
            company.entity_id,
        )

    def test_one_unlocked_owner_never_composes_another_owners_overlay(
        self,
    ) -> None:
        shared = self.layered.create_entity(
            "customer-graph",
            "Company",
            {"name": "Shared Company"},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        benjamin_secret = self.layered.create_entity(
            "customer-graph",
            "PrivatePreference",
            {"owner": "Benjamin", "value": "green"},
            context=self.benjamin,
        )
        self.layered.connect(
            "customer-graph",
            shared,
            benjamin_secret,
            "HAS_PREFERENCE",
            context=self.benjamin,
        )

        alexa_vault = self.protected.create_vault(
            "idp|alexa",
            self.ALEXA_PASSWORD,
        )
        alexa = self.protected.unlock(
            "idp|alexa",
            alexa_vault,
            self.ALEXA_PASSWORD,
        )
        alexa_secret = self.layered.create_entity(
            "customer-graph",
            "PrivatePreference",
            {"owner": "Alexa", "value": "blue"},
            context=alexa,
        )
        self.layered.connect(
            "customer-graph",
            shared,
            alexa_secret,
            "HAS_PREFERENCE",
            context=alexa,
        )

        benjamin_view = repr(
            self.layered.get_unlocked_view(
                "customer-graph",
                self.benjamin,
            )
        )
        alexa_view = repr(
            self.layered.get_unlocked_view("customer-graph", alexa)
        )
        self.assertIn("Benjamin", benjamin_view)
        self.assertNotIn("Alexa", benjamin_view)
        self.assertNotIn(alexa_secret.entity_id, benjamin_view)
        self.assertIn("Alexa", alexa_view)
        self.assertNotIn("Benjamin", alexa_view)
        self.assertNotIn(benjamin_secret.entity_id, alexa_view)

    def test_one_owner_can_hold_two_graph_overlays_without_mixing_views(
        self,
    ) -> None:
        first = self.layered.create_entity(
            "first-graph",
            "FirstSecret",
            {"sentinel": "only-first"},
            context=self.benjamin,
        )
        second = self.layered.create_entity(
            "second-graph",
            "SecondSecret",
            {"sentinel": "only-second"},
            context=self.benjamin,
        )
        first_view = repr(
            self.layered.get_unlocked_view("first-graph", self.benjamin)
        )
        second_view = repr(
            self.layered.get_unlocked_view("second-graph", self.benjamin)
        )
        self.assertIn("only-first", first_view)
        self.assertNotIn("only-second", first_view)
        self.assertNotIn(second.entity_id, first_view)
        self.assertIn("only-second", second_view)
        self.assertNotIn("only-first", second_view)
        self.assertNotIn(first.entity_id, second_view)

    def test_cross_owner_private_connection_fails_before_creating_anchors(
        self,
    ) -> None:
        shared = self.layered.create_entity(
            "customer-graph",
            "Shared",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        alexa_vault = self.protected.create_vault(
            "idp|alexa",
            self.ALEXA_PASSWORD,
        )
        alexa = self.protected.unlock(
            "idp|alexa",
            alexa_vault,
            self.ALEXA_PASSWORD,
        )
        alexa_secret = self.layered.create_entity(
            "customer-graph",
            "AlexaSecret",
            {},
            context=alexa,
        )
        with self.assertRaises(RecordNotFound):
            self.layered.connect(
                "customer-graph",
                shared,
                alexa_secret,
                "CROSS_OWNER",
                context=self.benjamin,
            )
        benjamin_snapshot = self.protected.get_vault_snapshot(self.benjamin)
        self.assertEqual(benjamin_snapshot.entities, ())
        self.assertEqual(benjamin_snapshot.relationships, ())

    def test_wrong_graph_private_reference_cannot_be_connected(
        self,
    ) -> None:
        shared = self.layered.create_entity(
            "customer-graph",
            "Shared",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        other_graph_private = self.layered.create_entity(
            "other-graph",
            "OtherSecret",
            {},
            context=self.benjamin,
        )
        forged_scope = replace(
            other_graph_private,
            graph_id="customer-graph",
        )
        with self.assertRaises(RecordNotFound):
            self.layered.connect(
                "customer-graph",
                shared,
                forged_scope,
                "WRONG_GRAPH",
                context=self.benjamin,
            )
        snapshot = self.protected.get_vault_snapshot(self.benjamin)
        self.assertEqual(len(snapshot.entities), 1)
        self.assertEqual(snapshot.relationships, ())

    def test_private_anchor_and_relationship_write_is_atomic_on_failure(
        self,
    ) -> None:
        first = self.layered.create_entity(
            "customer-graph",
            "First",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        second = self.layered.create_entity(
            "customer-graph",
            "Second",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        with patch.object(
            self.private_repository,
            "put_entity_relationship_bundle",
            side_effect=RuntimeError("synthetic atomic write failure"),
        ), self.assertRaisesRegex(RuntimeError, "synthetic atomic"):
            self.layered.connect(
                "customer-graph",
                first,
                second,
                "PRIVATE_EDGE",
                context=self.benjamin,
            )
        snapshot = self.protected.get_vault_snapshot(self.benjamin)
        self.assertEqual(snapshot.entities, ())
        self.assertEqual(snapshot.relationships, ())

    def test_public_relationship_rejects_private_or_forged_endpoints(
        self,
    ) -> None:
        public = self.layered.create_entity(
            "customer-graph",
            "Public",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        private = self.layered.create_entity(
            "customer-graph",
            "Private",
            {},
            context=self.benjamin,
        )
        with self.assertRaises(ValidationError):
            self.layered.connect(
                "customer-graph",
                public,
                private,
                "LEAKS",
                protection=ProtectionLevel.PUBLIC,
                publisher=self.publisher,
            )

        forged = GraphEntityRef(
            graph_id="customer-graph",
            entity_id="public_missing",
            protection=ProtectionLevel.PUBLIC,
        )
        with self.assertRaises(RecordNotFound):
            self.layered.connect(
                "customer-graph",
                public,
                forged,
                "MISSING",
                protection=ProtectionLevel.PUBLIC,
                publisher=self.publisher,
            )
        self.assertEqual(
            self.public_repository.plaintext_snapshot().relationships,
            (),
        )

    def test_locked_badge_is_policy_driven_not_a_private_record_oracle(
        self,
    ) -> None:
        badge_policy = GraphPolicy(
            locked_disclosure=LockedDisclosure.GENERIC_BADGE
        )
        layered = LayeredGraphService(
            self.protected,
            self.public_repository,
            graph_policies={
                "empty-graph": badge_policy,
                "populated-graph": badge_policy,
            },
            public_write_authorizer=(
                lambda publisher, graph_id: publisher is self.publisher
            ),
        )
        empty = layered.get_public_view("empty-graph")
        layered.create_entity(
            "populated-graph",
            "Secret",
            {"secret": "not in badge"},
            context=self.benjamin,
        )
        populated = layered.get_public_view("populated-graph")
        self.assertFalse(empty.private_overlay_included)
        self.assertFalse(populated.private_overlay_included)
        self.assertIs(
            empty.locked_disclosure,
            LockedDisclosure.GENERIC_BADGE,
        )
        self.assertIs(
            populated.locked_disclosure,
            LockedDisclosure.GENERIC_BADGE,
        )
        self.assertEqual(empty.entities, ())
        self.assertEqual(populated.entities, ())

    def test_locked_view_never_touches_the_private_decryption_service(
        self,
    ) -> None:
        self.layered.create_entity(
            "customer-graph",
            "Public",
            {"safe": True},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        with patch.object(
            self.protected,
            "get_vault_snapshot",
            side_effect=AssertionError("private snapshot must not be read"),
        ):
            view = self.layered.get_public_view("customer-graph")
        self.assertEqual([entity.kind for entity in view.entities], ["Public"])

    def test_graph_policy_controls_defaults_and_record_overrides(self) -> None:
        public_only = GraphPolicy(
            default_entity_protection=ProtectionLevel.PUBLIC,
            default_relationship_protection=ProtectionLevel.PUBLIC,
            allow_public_overrides=False,
        )
        layered = LayeredGraphService(
            self.protected,
            self.public_repository,
            graph_policies={"public-catalog": public_only},
            public_write_authorizer=(
                lambda publisher, graph_id: (
                    publisher is self.publisher
                    and graph_id == "public-catalog"
                )
            ),
        )
        entity = layered.create_entity(
            "public-catalog",
            "Topic",
            {"x": 1},
            publisher=self.publisher,
        )
        self.assertIs(entity.protection, ProtectionLevel.PUBLIC)
        private = layered.create_entity(
            "public-catalog",
            "Secret",
            {},
            context=self.benjamin,
            protection=ProtectionLevel.PRIVATE,
        )
        self.assertIs(private.protection, ProtectionLevel.PRIVATE)
        with self.assertRaises(ValidationError):
            LayeredGraphService(
                self.protected,
                self.public_repository,
                default_policy=replace(
                    GraphPolicy(),
                    default_entity_protection="public",  # type: ignore[arg-type]
                ),
            )
        with self.assertRaises(ValidationError):
            self.layered.create_entity(
                "customer-graph",
                "Invalid",
                {},
                protection="public",  # type: ignore[arg-type]
                publisher=self.publisher,
            )

    def test_plaintext_public_override_and_write_both_require_opt_in(
        self,
    ) -> None:
        strict = LayeredGraphService(
            self.protected,
            InMemoryPublicGraphRepository(),
            public_write_authorizer=lambda publisher, graph_id: True,
        )
        with self.assertRaises(ValidationError):
            strict.create_entity(
                "customer-graph",
                "WouldBePublic",
                {},
                protection=ProtectionLevel.PUBLIC,
                publisher=object(),
            )

        opted_in_repository = InMemoryPublicGraphRepository()
        opted_in = LayeredGraphService(
            self.protected,
            opted_in_repository,
            default_policy=GraphPolicy(allow_public_overrides=True),
            public_write_authorizer=(
                lambda publisher, graph_id: publisher is self.publisher
            ),
        )
        with self.assertRaises(AuthorizationDenied):
            opted_in.create_entity(
                "customer-graph",
                "Denied",
                {},
                protection=ProtectionLevel.PUBLIC,
            )
        with self.assertRaises(AuthorizationDenied):
            opted_in.create_entity(
                "customer-graph",
                "Denied",
                {},
                protection=ProtectionLevel.PUBLIC,
                publisher=object(),
            )
        self.assertEqual(opted_in_repository.plaintext_snapshot().entities, ())

    def test_policy_changes_do_not_reclassify_existing_records(self) -> None:
        public = self.layered.create_entity(
            "customer-graph",
            "OriginallyPublic",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        private = self.layered.create_entity(
            "customer-graph",
            "OriginallyPrivate",
            {},
            context=self.benjamin,
        )
        rebuilt = LayeredGraphService(
            self.protected,
            self.public_repository,
            graph_policies={
                "customer-graph": GraphPolicy(
                    default_entity_protection=ProtectionLevel.PUBLIC,
                    default_relationship_protection=ProtectionLevel.PUBLIC,
                )
            },
            public_write_authorizer=(
                lambda publisher, graph_id: publisher is self.publisher
            ),
        )
        public_view = rebuilt.get_public_view("customer-graph")
        self.assertEqual(
            [entity.entity_id for entity in public_view.entities],
            [public.entity_id],
        )
        unlocked = rebuilt.get_unlocked_view(
            "customer-graph",
            self.benjamin,
        )
        protection = {
            entity.entity_id: entity.protection
            for entity in unlocked.entities
        }
        self.assertIs(protection[public.entity_id], ProtectionLevel.PUBLIC)
        self.assertIs(protection[private.entity_id], ProtectionLevel.PRIVATE)

    def test_public_properties_are_deep_copied_on_write_and_read(self) -> None:
        supplied = {"nested": {"value": "original"}}
        reference = self.layered.create_entity(
            "customer-graph",
            "Public",
            supplied,
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        supplied["nested"]["value"] = "mutated input"

        first = self.public_repository.get_public_entity(
            "customer-graph",
            reference.entity_id,
        )
        assert first is not None
        self.assertEqual(first.properties["nested"]["value"], "original")
        first.properties["nested"]["value"] = "mutated output"

        second = self.public_repository.get_public_entity(
            "customer-graph",
            reference.entity_id,
        )
        assert second is not None
        self.assertEqual(second.properties["nested"]["value"], "original")

    def test_invalid_unicode_properties_fail_with_public_errors(self) -> None:
        with self.assertRaises(ValidationError):
            self.layered.create_entity(
                "customer-graph",
                "Public",
                {"invalid": "\ud800"},
                protection=ProtectionLevel.PUBLIC,
                publisher=self.publisher,
            )
        driver = RecordingDriver([])
        repository = Neo4jPublicGraphRepository(driver, database="neo4j")
        with self.assertRaises(ValidationError):
            repository.put_public_entity(
                PublicEntityRow(
                    "customer-graph",
                    "public_invalid",
                    "Public",
                    {"invalid": "\ud800"},
                )
            )
        self.assertEqual(driver.calls, [])

    def test_expired_or_locked_context_cannot_fall_back_to_public_plus_private(
        self,
    ) -> None:
        self.layered.create_entity(
            "customer-graph",
            "Secret",
            {},
            context=self.benjamin,
        )
        self.protected.lock(self.benjamin)
        with self.assertRaises(SessionUnavailable):
            self.layered.get_unlocked_view(
                "customer-graph",
                self.benjamin,
            )
        locked = self.layered.get_public_view("customer-graph")
        self.assertEqual(locked.entities, ())

    def test_public_snapshot_overflow_and_dangling_edges_fail_closed(self) -> None:
        first = self.layered.create_entity(
            "customer-graph",
            "First",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        second = self.layered.create_entity(
            "customer-graph",
            "Second",
            {},
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        with self.assertRaises(ValidationError):
            self.layered.get_public_view(
                "customer-graph",
                public_entity_limit=1,
            )
        self.layered.connect(
            "customer-graph",
            first,
            second,
            "FIRST_EDGE",
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        self.layered.connect(
            "customer-graph",
            second,
            first,
            "SECOND_EDGE",
            protection=ProtectionLevel.PUBLIC,
            publisher=self.publisher,
        )
        with self.assertRaises(ValidationError):
            self.layered.get_public_view(
                "customer-graph",
                public_relationship_limit=1,
            )

        class CorruptRepository(InMemoryPublicGraphRepository):
            def get_public_graph_snapshot(
                self,
                graph_id: str,
                *,
                entity_limit: int,
                relationship_limit: int,
            ) -> PublicGraphSnapshotRow:
                del entity_limit, relationship_limit
                return PublicGraphSnapshotRow(
                    entities=(
                        PublicEntityRow(graph_id, first.entity_id, "First", {}),
                    ),
                    relationships=(
                        PublicRelationshipRow(
                            graph_id,
                            "public_edge",
                            first.entity_id,
                            second.entity_id,
                            "DANGLING",
                            {},
                        ),
                    ),
                )

        corrupt = LayeredGraphService(
            self.protected,
            CorruptRepository(),
        )
        with self.assertRaises(IntegrityViolation):
            corrupt.get_public_view("customer-graph")

        class MalformedRepository(InMemoryPublicGraphRepository):
            def get_public_graph_snapshot(
                self,
                graph_id: str,
                *,
                entity_limit: int,
                relationship_limit: int,
            ) -> PublicGraphSnapshotRow:
                del graph_id, entity_limit, relationship_limit
                return PublicGraphSnapshotRow(  # type: ignore[arg-type]
                    entities=None,
                    relationships=(),
                )

        malformed = LayeredGraphService(
            self.protected,
            MalformedRepository(),
        )
        with self.assertRaises(IntegrityViolation):
            malformed.get_public_view("customer-graph")

    def test_public_snapshot_aggregate_json_size_is_bounded(self) -> None:
        value = "x" * (MAX_PUBLIC_SNAPSHOT_JSON_BYTES // 5)
        for index in range(6):
            self.layered.create_entity(
                "customer-graph",
                f"LargePublic{index}",
                {"value": value},
                protection=ProtectionLevel.PUBLIC,
                publisher=self.publisher,
            )
        with self.assertRaises(ValidationError):
            self.layered.get_public_view("customer-graph")

    def test_malformed_private_wrappers_and_dangling_anchors_fail_closed(
        self,
    ) -> None:
        malformed_vault = self.protected.create_vault(
            "idp|malformed",
            bytearray(b"malformed correct horse battery staple"),
        )
        malformed_context = self.protected.unlock(
            "idp|malformed",
            malformed_vault,
            bytearray(b"malformed correct horse battery staple"),
        )
        self.protected.create_entity(
            malformed_context,
            PRIVATE_ENTITY_WRAPPER_KIND,
            {
                "graph_id": "customer-graph",
                "kind": 42,
                "properties": {},
            },
        )
        with self.assertRaises(IntegrityViolation):
            self.layered.get_unlocked_view(
                "customer-graph",
                malformed_context,
            )

        anchor_vault = self.protected.create_vault(
            "idp|dangling-anchor",
            bytearray(b"anchor correct horse battery staple"),
        )
        anchor_context = self.protected.unlock(
            "idp|dangling-anchor",
            anchor_vault,
            bytearray(b"anchor correct horse battery staple"),
        )
        self.protected.create_entity(
            anchor_context,
            PUBLIC_ANCHOR_WRAPPER_KIND,
            {
                "graph_id": "customer-graph",
                "public_entity_id": "public_missing",
            },
        )
        with self.assertRaises(IntegrityViolation):
            self.layered.get_unlocked_view(
                "customer-graph",
                anchor_context,
            )

    def test_layered_relationship_with_nonlayered_endpoints_fails_closed(
        self,
    ) -> None:
        first = self.protected.create_entity(
            self.benjamin,
            "Legacy",
            {},
        )
        second = self.protected.create_entity(
            self.benjamin,
            "Legacy",
            {},
        )
        self.protected.connect(
            self.benjamin,
            first,
            second,
            PRIVATE_RELATIONSHIP_WRAPPER_KIND,
            {
                "graph_id": "customer-graph",
                "kind": "FORGED_LAYERED_EDGE",
                "properties": {},
            },
        )
        with self.assertRaises(IntegrityViolation):
            self.layered.get_unlocked_view(
                "customer-graph",
                self.benjamin,
            )

    def test_neo4j_public_adapter_uses_fixed_scoped_plaintext_queries(
        self,
    ) -> None:
        driver = RecordingDriver(
            [
                [{"created": 1}],
                [
                    {
                        "entities": [
                            {
                                "entity_id": "public_e1",
                                "kind": "Topic",
                                "properties_json": '{"name":"Visible"}',
                            }
                        ],
                        "relationships": [],
                    }
                ],
            ]
        )
        repository = Neo4jPublicGraphRepository(driver, database="neo4j")
        row = PublicEntityRow(
            graph_id="base-graph",
            entity_id="public_e1",
            kind="Topic",
            properties={"name": "Visible"},
        )
        self.assertTrue(repository.put_public_entity(row))
        snapshot = repository.get_public_graph_snapshot(
            "base-graph",
            entity_limit=10,
            relationship_limit=10,
        )
        self.assertEqual(snapshot.entities, (row,))
        put_query, put_kwargs = driver.calls[0]
        self.assertIn("$graph_id", put_query)
        self.assertIn("AGPublicEntity", put_query)
        parameters = put_kwargs["parameters_"]
        self.assertEqual(parameters["properties_json"], '{"name":"Visible"}')
        self.assertEqual(put_kwargs["database_"], "neo4j")
        snapshot_parameters = driver.calls[1][1]["parameters_"]
        self.assertEqual(snapshot_parameters["entity_fetch_limit"], 11)
        self.assertEqual(snapshot_parameters["relationship_fetch_limit"], 11)

        for name, query in vars(Neo4jPublicGraphRepository).items():
            if name.startswith("_") and isinstance(query, str):
                self.assertNotIn("customer-graph", query)
        for name in (
            "_PUT_PUBLIC_ENTITY",
            "_PUT_PUBLIC_RELATIONSHIP",
            "_GET_PUBLIC_GRAPH_SNAPSHOT",
        ):
            query = getattr(Neo4jPublicGraphRepository, name)
            self.assertIn("SET graph._authgraph_lock = true", query)
            self.assertIn("REMOVE graph._authgraph_lock", query)

        insecure_driver = type("Driver", (), {"encrypted": False})()
        with self.assertRaises(ValueError):
            Neo4jPublicGraphRepository(insecure_driver, database="neo4j")

    def test_neo4j_public_adapter_rejects_malformed_plaintext_json(self) -> None:
        driver = RecordingDriver(
            [
                [
                    {
                        "entities": [
                            {
                                "entity_id": "public_e1",
                                "kind": "Topic",
                                "properties_json": "[]",
                            }
                        ],
                        "relationships": [],
                    }
                ]
            ]
        )
        repository = Neo4jPublicGraphRepository(driver, database="neo4j")
        with self.assertRaises(IntegrityViolation):
            repository.get_public_graph_snapshot(
                "base-graph",
                entity_limit=10,
                relationship_limit=10,
            )

    def test_neo4j_public_relationship_write_is_scoped_and_reconciled(
        self,
    ) -> None:
        row = PublicRelationshipRow(
            graph_id="base-graph",
            relationship_id="public_r1",
            from_entity_id="public_e1",
            to_entity_id="public_e2",
            kind="RELATES_TO",
            properties={"visible": True},
        )
        driver = RecordingDriver([[{"created": 1}]])
        repository = Neo4jPublicGraphRepository(driver, database="neo4j")
        self.assertTrue(repository.put_public_relationship(row))
        query, kwargs = driver.calls[0]
        self.assertEqual(
            query,
            Neo4jPublicGraphRepository._PUT_PUBLIC_RELATIONSHIP,
        )
        parameters = kwargs["parameters_"]
        self.assertEqual(parameters["graph_id"], "base-graph")
        self.assertEqual(parameters["from_entity_id"], "public_e1")
        self.assertEqual(parameters["to_entity_id"], "public_e2")
        self.assertEqual(
            parameters["properties_json"],
            '{"visible":true}',
        )

        ambiguous_driver = RecordingDriver(
            [
                PublicIncompleteCommit(),
                [
                    {
                        "kind": "RELATES_TO",
                        "properties_json": '{"visible":true}',
                    }
                ],
            ]
        )
        ambiguous_repository = Neo4jPublicGraphRepository(
            ambiguous_driver,
            database="neo4j",
        )
        self.assertTrue(ambiguous_repository.put_public_relationship(row))

        missing_driver = RecordingDriver([[{"created": 0}], []])
        missing_repository = Neo4jPublicGraphRepository(
            missing_driver,
            database="neo4j",
        )
        self.assertFalse(missing_repository.put_public_relationship(row))


if __name__ == "__main__":
    unittest.main()
