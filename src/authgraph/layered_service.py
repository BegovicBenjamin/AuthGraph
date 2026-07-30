"""Configurable public base graph plus encrypted per-owner overlays."""

from __future__ import annotations

import json
import secrets
import unicodedata
from collections.abc import Callable, Mapping
from typing import Any

from .errors import (
    AuthorizationDenied,
    ConflictError,
    IntegrityViolation,
    RecordNotFound,
    SessionUnavailable,
    ValidationError,
)
from .models import (
    AccessContext,
    GraphEntityRef,
    GraphPolicy,
    GraphRelationshipRef,
    LayeredEntity,
    LayeredGraphView,
    LayeredRelationship,
    LockedDisclosure,
    ProtectionLevel,
    PublicEntityRow,
    PublicGraphSnapshotRow,
    PublicRelationshipRow,
)
from .public_repository import PublicGraphRepository
from .service import (
    MAX_ID_CHARS,
    MAX_KIND_CHARS,
    MAX_VAULT_SNAPSHOT_ENTITIES,
    MAX_VAULT_SNAPSHOT_RELATIONSHIPS,
    AuthGraphService,
)


MAX_PUBLIC_JSON_BYTES = 64 * 1024
MAX_PUBLIC_SNAPSHOT_JSON_BYTES = 256 * 1024
PRIVATE_ENTITY_WRAPPER_KIND = "__authgraph_layered_private_entity_v1"
PUBLIC_ANCHOR_WRAPPER_KIND = "__authgraph_layered_public_anchor_v1"
PRIVATE_RELATIONSHIP_WRAPPER_KIND = (
    "__authgraph_layered_private_relationship_v1"
)


def _validate_id(value: str, description: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_ID_CHARS
        or any(unicodedata.category(char).startswith("C") for char in value)
    ):
        raise ValidationError(description)


def _validate_kind(kind: str) -> None:
    if (
        not isinstance(kind, str)
        or not kind
        or len(kind) > MAX_KIND_CHARS
        or any(unicodedata.category(char).startswith("C") for char in kind)
        or kind
        in {
            PRIVATE_ENTITY_WRAPPER_KIND,
            PUBLIC_ANCHOR_WRAPPER_KIND,
            PRIVATE_RELATIONSHIP_WRAPPER_KIND,
        }
    ):
        raise ValidationError("Entity and relationship kinds must be short text.")


def _copy_json_properties(properties: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(properties, Mapping):
        raise ValidationError("Properties must be supplied as a JSON object.")
    try:
        copied = dict(properties)
        encoded = json.dumps(
            copied,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        encoded_size = len(encoded.encode("utf-8"))
    except (
        TypeError,
        ValueError,
        RecursionError,
        UnicodeEncodeError,
    ) as exc:
        raise ValidationError("Properties must be a valid JSON object.") from exc
    if encoded_size > MAX_PUBLIC_JSON_BYTES:
        raise ValidationError(
            f"Properties may contain at most {MAX_PUBLIC_JSON_BYTES} bytes."
        )
    # Round-tripping creates an owned deep copy and gives public in-memory
    # storage the same JSON normalization as encrypted and Neo4j storage.
    return json.loads(encoded)


class LayeredGraphService:
    """Build and read a public graph with one optional private vault overlay.

    The public repository is intentionally plaintext at the application layer.
    Private records continue to flow exclusively through ``AuthGraphService``
    and its owner-scoped encrypted vault.

    This class is a trusted backend API. Applications must authorize public
    mutations separately and must never give an LLM a generic write tool.
    """

    def __init__(
        self,
        protected: AuthGraphService,
        public_repository: PublicGraphRepository,
        *,
        default_policy: GraphPolicy | None = None,
        graph_policies: Mapping[str, GraphPolicy] | None = None,
        public_write_authorizer: Callable[[object, str], bool] | None = None,
    ) -> None:
        if not isinstance(protected, AuthGraphService):
            raise TypeError("protected must be an AuthGraphService.")
        self._protected = protected
        self._public_repository = public_repository
        if (
            public_write_authorizer is not None
            and not callable(public_write_authorizer)
        ):
            raise TypeError("public_write_authorizer must be callable.")
        self._public_write_authorizer = public_write_authorizer
        self._default_policy = self._validate_policy(
            GraphPolicy() if default_policy is None else default_policy
        )
        supplied_policies = {} if graph_policies is None else dict(graph_policies)
        self._graph_policies: dict[str, GraphPolicy] = {}
        for graph_id, policy in supplied_policies.items():
            _validate_id(graph_id, "Invalid opaque public graph identifier.")
            self._graph_policies[graph_id] = self._validate_policy(policy)

    @staticmethod
    def _validate_policy(policy: GraphPolicy) -> GraphPolicy:
        if (
            not isinstance(policy, GraphPolicy)
            or type(policy.default_entity_protection) is not ProtectionLevel
            or type(policy.default_relationship_protection)
            is not ProtectionLevel
            or type(policy.allow_public_overrides) is not bool
            or type(policy.locked_disclosure) is not LockedDisclosure
        ):
            raise ValidationError("Invalid layered graph policy.")
        return policy

    def get_policy(self, graph_id: str) -> GraphPolicy:
        _validate_id(graph_id, "Invalid opaque public graph identifier.")
        return self._graph_policies.get(graph_id, self._default_policy)

    @staticmethod
    def _effective_protection(
        requested: ProtectionLevel | None,
        *,
        default: ProtectionLevel,
        policy: GraphPolicy,
    ) -> ProtectionLevel:
        if requested is None:
            return default
        if type(requested) is not ProtectionLevel:
            raise ValidationError(
                "Protection must be ProtectionLevel.PUBLIC or "
                "ProtectionLevel.PRIVATE."
            )
        # Tightening a public default to PRIVATE is always allowed. Weakening
        # a private default to plaintext PUBLIC requires an explicit graph
        # policy opt-in.
        if (
            requested is ProtectionLevel.PUBLIC
            and default is ProtectionLevel.PRIVATE
            and not policy.allow_public_overrides
        ):
            raise ValidationError(
                "This graph policy does not allow plaintext public overrides."
            )
        return requested

    @staticmethod
    def _require_context(context: AccessContext | None) -> AccessContext:
        if not isinstance(context, AccessContext):
            raise SessionUnavailable()
        return context

    def _authorize_public_write(
        self,
        publisher: object | None,
        graph_id: str,
    ) -> None:
        if publisher is None or self._public_write_authorizer is None:
            raise AuthorizationDenied()
        try:
            allowed = self._public_write_authorizer(publisher, graph_id)
        except Exception:
            raise AuthorizationDenied() from None
        if allowed is not True:
            raise AuthorizationDenied()

    def create_entity(
        self,
        graph_id: str,
        kind: str,
        properties: Mapping[str, Any],
        *,
        context: AccessContext | None = None,
        protection: ProtectionLevel | None = None,
        publisher: object | None = None,
    ) -> GraphEntityRef:
        """Create one record using the graph default or an explicit override."""

        _validate_id(graph_id, "Invalid opaque public graph identifier.")
        _validate_kind(kind)
        copied_properties = _copy_json_properties(properties)
        policy = self.get_policy(graph_id)
        effective = self._effective_protection(
            protection,
            default=policy.default_entity_protection,
            policy=policy,
        )
        if effective is ProtectionLevel.PRIVATE:
            entity_id = self._protected.create_entity(
                self._require_context(context),
                PRIVATE_ENTITY_WRAPPER_KIND,
                {
                    "graph_id": graph_id,
                    "kind": kind,
                    "properties": copied_properties,
                },
            )
            return GraphEntityRef(
                graph_id=graph_id,
                entity_id=entity_id,
                protection=effective,
            )

        self._authorize_public_write(publisher, graph_id)
        for _ in range(3):
            entity_id = f"public_{secrets.token_urlsafe(24)}"
            created = self._public_repository.put_public_entity(
                PublicEntityRow(
                    graph_id=graph_id,
                    entity_id=entity_id,
                    kind=kind,
                    properties=copied_properties,
                )
            )
            if created:
                return GraphEntityRef(
                    graph_id=graph_id,
                    entity_id=entity_id,
                    protection=effective,
                )
        raise ConflictError("Could not allocate a unique public entity identifier.")

    def connect(
        self,
        graph_id: str,
        from_entity: GraphEntityRef,
        to_entity: GraphEntityRef,
        kind: str,
        properties: Mapping[str, Any] | None = None,
        *,
        context: AccessContext | None = None,
        protection: ProtectionLevel | None = None,
        publisher: object | None = None,
    ) -> GraphRelationshipRef:
        """Create a public edge or an encrypted overlay edge.

        A public edge is permitted only when both endpoints are public. An
        encrypted edge may connect private entities and/or encrypted anchors
        that resolve to public entities after the owner unlocks the vault.
        """

        _validate_id(graph_id, "Invalid opaque public graph identifier.")
        _validate_kind(kind)
        relationship_properties = _copy_json_properties(
            {} if properties is None else properties
        )
        self._validate_ref(graph_id, from_entity)
        self._validate_ref(graph_id, to_entity)
        policy = self.get_policy(graph_id)
        effective = self._effective_protection(
            protection,
            default=policy.default_relationship_protection,
            policy=policy,
        )

        if effective is ProtectionLevel.PUBLIC:
            if (
                from_entity.protection is not ProtectionLevel.PUBLIC
                or to_entity.protection is not ProtectionLevel.PUBLIC
            ):
                raise ValidationError(
                    "A public relationship requires two public endpoints."
                )
            self._authorize_public_write(publisher, graph_id)
            self._require_public_entity(from_entity)
            self._require_public_entity(to_entity)
            for _ in range(3):
                relationship_id = f"public_{secrets.token_urlsafe(24)}"
                created = self._public_repository.put_public_relationship(
                    PublicRelationshipRow(
                        graph_id=graph_id,
                        relationship_id=relationship_id,
                        from_entity_id=from_entity.entity_id,
                        to_entity_id=to_entity.entity_id,
                        kind=kind,
                        properties=relationship_properties,
                    )
                )
                if created:
                    return GraphRelationshipRef(
                        graph_id=graph_id,
                        relationship_id=relationship_id,
                        protection=effective,
                    )
            raise ConflictError(
                "Could not allocate a unique public relationship identifier."
            )

        secure_context = self._require_context(context)
        # Validate every endpoint before creating any encrypted anchor. This
        # keeps expected validation failures free of partial helper records.
        for endpoint in (from_entity, to_entity):
            if endpoint.protection is ProtectionLevel.PUBLIC:
                self._require_public_entity(endpoint)
            else:
                self._require_private_entity(secure_context, endpoint)

        new_anchor_specs: list[tuple[str, Mapping[str, Any]]] = []
        anchor_indexes: dict[str, int] = {}

        def protected_endpoint(endpoint: GraphEntityRef) -> str | int:
            if endpoint.protection is ProtectionLevel.PRIVATE:
                return endpoint.entity_id
            existing = anchor_indexes.get(endpoint.entity_id)
            if existing is not None:
                return existing
            anchor_index = len(new_anchor_specs)
            new_anchor_specs.append(
                (
                    PUBLIC_ANCHOR_WRAPPER_KIND,
                    {
                        "graph_id": graph_id,
                        "public_entity_id": endpoint.entity_id,
                    },
                )
            )
            anchor_indexes[endpoint.entity_id] = anchor_index
            return anchor_index

        from_protected_id = protected_endpoint(from_entity)
        to_protected_id = protected_endpoint(to_entity)
        private_relationship_properties = {
            "graph_id": graph_id,
            "kind": kind,
            "properties": relationship_properties,
        }
        if new_anchor_specs:
            relationship_id, _ = self._protected.create_relationship_bundle(
                secure_context,
                tuple(new_anchor_specs),
                from_protected_id,
                to_protected_id,
                PRIVATE_RELATIONSHIP_WRAPPER_KIND,
                private_relationship_properties,
            )
        else:
            if (
                not isinstance(from_protected_id, str)
                or not isinstance(to_protected_id, str)
            ):
                raise IntegrityViolation()
            relationship_id = self._protected.connect(
                secure_context,
                from_protected_id,
                to_protected_id,
                PRIVATE_RELATIONSHIP_WRAPPER_KIND,
                private_relationship_properties,
            )
        return GraphRelationshipRef(
            graph_id=graph_id,
            relationship_id=relationship_id,
            protection=effective,
        )

    @staticmethod
    def _validate_ref(graph_id: str, reference: GraphEntityRef) -> None:
        if (
            not isinstance(reference, GraphEntityRef)
            or reference.graph_id != graph_id
            or type(reference.protection) is not ProtectionLevel
        ):
            raise ValidationError("Invalid graph entity reference.")
        _validate_id(reference.entity_id, "Invalid graph entity reference.")

    def _require_public_entity(
        self,
        reference: GraphEntityRef,
    ) -> PublicEntityRow:
        row = self._public_repository.get_public_entity(
            reference.graph_id,
            reference.entity_id,
        )
        if row is None:
            raise RecordNotFound()
        self._validate_public_entity_row(reference.graph_id, row)
        if row.entity_id != reference.entity_id:
            raise IntegrityViolation()
        return row

    def _require_private_entity(
        self,
        context: AccessContext,
        reference: GraphEntityRef,
    ) -> None:
        entity = self._protected.get_entity(context, reference.entity_id)
        if entity.kind != PRIVATE_ENTITY_WRAPPER_KIND:
            raise RecordNotFound()
        graph_id, _, _ = self._decode_private_entity(entity.properties)
        if graph_id != reference.graph_id:
            raise RecordNotFound()

    def get_public_view(
        self,
        graph_id: str,
        *,
        public_entity_limit: int = MAX_VAULT_SNAPSHOT_ENTITIES,
        public_relationship_limit: int = MAX_VAULT_SNAPSHOT_RELATIONSHIPS,
    ) -> LayeredGraphView:
        """Return only records classified public, without touching a vault."""

        return self._get_view(
            graph_id,
            context=None,
            public_entity_limit=public_entity_limit,
            public_relationship_limit=public_relationship_limit,
            private_entity_limit=MAX_VAULT_SNAPSHOT_ENTITIES,
            private_relationship_limit=MAX_VAULT_SNAPSHOT_RELATIONSHIPS,
        )

    def get_unlocked_view(
        self,
        graph_id: str,
        context: AccessContext,
        *,
        public_entity_limit: int = MAX_VAULT_SNAPSHOT_ENTITIES,
        public_relationship_limit: int = MAX_VAULT_SNAPSHOT_RELATIONSHIPS,
        private_entity_limit: int = MAX_VAULT_SNAPSHOT_ENTITIES,
        private_relationship_limit: int = MAX_VAULT_SNAPSHOT_RELATIONSHIPS,
    ) -> LayeredGraphView:
        """Compose public data with exactly one unlocked owner overlay."""

        return self._get_view(
            graph_id,
            context=self._require_context(context),
            public_entity_limit=public_entity_limit,
            public_relationship_limit=public_relationship_limit,
            private_entity_limit=private_entity_limit,
            private_relationship_limit=private_relationship_limit,
        )

    def _get_view(
        self,
        graph_id: str,
        *,
        context: AccessContext | None,
        public_entity_limit: int,
        public_relationship_limit: int,
        private_entity_limit: int,
        private_relationship_limit: int,
    ) -> LayeredGraphView:
        """Internal implementation shared by explicit public/unlocked reads."""

        _validate_id(graph_id, "Invalid opaque public graph identifier.")
        self._validate_limits(
            public_entity_limit,
            public_relationship_limit,
            private_entity_limit,
            private_relationship_limit,
        )
        public = self._public_repository.get_public_graph_snapshot(
            graph_id,
            entity_limit=public_entity_limit,
            relationship_limit=public_relationship_limit,
        )
        public_entities, public_relationships = self._decode_public_snapshot(
            graph_id,
            public,
            entity_limit=public_entity_limit,
            relationship_limit=public_relationship_limit,
        )
        if context is None:
            policy = self.get_policy(graph_id)
            return LayeredGraphView(
                graph_id=graph_id,
                entities=tuple(public_entities.values()),
                relationships=tuple(public_relationships.values()),
                private_overlay_included=False,
                locked_disclosure=policy.locked_disclosure,
            )
        secure_context = self._require_context(context)
        private = self._protected.get_vault_snapshot(
            secure_context,
            entity_limit=private_entity_limit,
            relationship_limit=private_relationship_limit,
        )
        entities = dict(public_entities)
        relationships = dict(public_relationships)
        private_entities: dict[str, LayeredEntity] = {}
        public_anchors: dict[str, str] = {}

        for entity in private.entities:
            if entity.kind == PRIVATE_ENTITY_WRAPPER_KIND:
                (
                    entity_graph_id,
                    semantic_kind,
                    semantic_properties,
                ) = self._decode_private_entity(entity.properties)
                if entity_graph_id != graph_id:
                    continue
                if entity.entity_id in entities or entity.entity_id in private_entities:
                    raise IntegrityViolation()
                private_entities[entity.entity_id] = LayeredEntity(
                    entity_id=entity.entity_id,
                    kind=semantic_kind,
                    properties=semantic_properties,
                    protection=ProtectionLevel.PRIVATE,
                )
            elif entity.kind == PUBLIC_ANCHOR_WRAPPER_KIND:
                anchor_graph_id, public_entity_id = self._decode_public_anchor(
                    entity.properties
                )
                if anchor_graph_id != graph_id:
                    continue
                if (
                    entity.entity_id in public_anchors
                    or public_entity_id not in public_entities
                ):
                    raise IntegrityViolation()
                public_anchors[entity.entity_id] = public_entity_id
            # Legacy encrypted entities and overlays for other graph adapters
            # remain private and are intentionally absent from this view.

        entities.update(private_entities)
        endpoint_ids = set(private_entities) | set(public_anchors)
        for relationship in private.relationships:
            if relationship.kind != PRIVATE_RELATIONSHIP_WRAPPER_KIND:
                continue
            (
                relationship_graph_id,
                semantic_kind,
                semantic_properties,
            ) = self._decode_private_relationship(relationship.properties)
            if relationship_graph_id != graph_id:
                continue
            if (
                relationship.from_entity_id not in endpoint_ids
                or relationship.to_entity_id not in endpoint_ids
                or relationship.relationship_id in relationships
            ):
                raise IntegrityViolation()
            from_entity_id = public_anchors.get(
                relationship.from_entity_id,
                relationship.from_entity_id,
            )
            to_entity_id = public_anchors.get(
                relationship.to_entity_id,
                relationship.to_entity_id,
            )
            if from_entity_id not in entities or to_entity_id not in entities:
                raise IntegrityViolation()
            relationships[relationship.relationship_id] = LayeredRelationship(
                relationship_id=relationship.relationship_id,
                from_entity_id=from_entity_id,
                to_entity_id=to_entity_id,
                kind=semantic_kind,
                properties=semantic_properties,
                protection=ProtectionLevel.PRIVATE,
            )

        return LayeredGraphView(
            graph_id=graph_id,
            entities=tuple(
                sorted(entities.values(), key=lambda entity: entity.entity_id)
            ),
            relationships=tuple(
                sorted(
                    relationships.values(),
                    key=lambda relationship: relationship.relationship_id,
                )
            ),
            private_overlay_included=True,
            locked_disclosure=LockedDisclosure.HIDDEN,
        )

    @staticmethod
    def _validate_limits(*limits: int) -> None:
        maximums = (
            MAX_VAULT_SNAPSHOT_ENTITIES,
            MAX_VAULT_SNAPSHOT_RELATIONSHIPS,
            MAX_VAULT_SNAPSHOT_ENTITIES,
            MAX_VAULT_SNAPSHOT_RELATIONSHIPS,
        )
        if any(
            type(limit) is not int or limit <= 0 or limit > maximum
            for limit, maximum in zip(limits, maximums, strict=True)
        ):
            raise ValidationError(
                "Layered graph snapshot limits exceed the supported bounds."
            )

    def _decode_public_snapshot(
        self,
        graph_id: str,
        snapshot: PublicGraphSnapshotRow,
        *,
        entity_limit: int,
        relationship_limit: int,
    ) -> tuple[dict[str, LayeredEntity], dict[str, LayeredRelationship]]:
        if not isinstance(snapshot, PublicGraphSnapshotRow):
            raise IntegrityViolation()
        try:
            entity_count = len(snapshot.entities)
            relationship_count = len(snapshot.relationships)
        except (AttributeError, TypeError):
            raise IntegrityViolation() from None
        if entity_count > entity_limit or relationship_count > relationship_limit:
            raise ValidationError(
                "The complete public graph does not fit within snapshot limits."
            )
        entities: dict[str, LayeredEntity] = {}
        public_semantic_bytes = 0
        try:
            for row in snapshot.entities:
                self._validate_public_entity_row(graph_id, row)
                if row.entity_id in entities:
                    raise IntegrityViolation()
                normalized_properties = _copy_json_properties(row.properties)
                public_semantic_bytes += len(row.kind.encode("utf-8")) + len(
                    json.dumps(
                        normalized_properties,
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                )
                if (
                    public_semantic_bytes
                    > MAX_PUBLIC_SNAPSHOT_JSON_BYTES
                ):
                    raise ValidationError(
                        "The complete public graph exceeds its byte limit."
                    )
                entities[row.entity_id] = LayeredEntity(
                    entity_id=row.entity_id,
                    kind=row.kind,
                    properties=normalized_properties,
                    protection=ProtectionLevel.PUBLIC,
                )
        except (AttributeError, TypeError, ValueError):
            raise IntegrityViolation() from None
        relationships: dict[str, LayeredRelationship] = {}
        try:
            for row in snapshot.relationships:
                self._validate_public_relationship_row(graph_id, row)
                if (
                    row.relationship_id in relationships
                    or row.from_entity_id not in entities
                    or row.to_entity_id not in entities
                ):
                    raise IntegrityViolation()
                normalized_properties = _copy_json_properties(row.properties)
                public_semantic_bytes += len(row.kind.encode("utf-8")) + len(
                    json.dumps(
                        normalized_properties,
                        ensure_ascii=False,
                        allow_nan=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                )
                if (
                    public_semantic_bytes
                    > MAX_PUBLIC_SNAPSHOT_JSON_BYTES
                ):
                    raise ValidationError(
                        "The complete public graph exceeds its byte limit."
                    )
                relationships[row.relationship_id] = LayeredRelationship(
                    relationship_id=row.relationship_id,
                    from_entity_id=row.from_entity_id,
                    to_entity_id=row.to_entity_id,
                    kind=row.kind,
                    properties=normalized_properties,
                    protection=ProtectionLevel.PUBLIC,
                )
        except (AttributeError, TypeError, ValueError):
            raise IntegrityViolation() from None
        return (
            dict(sorted(entities.items())),
            dict(sorted(relationships.items())),
        )

    @staticmethod
    def _validate_public_entity_row(
        graph_id: str,
        row: PublicEntityRow,
    ) -> None:
        try:
            if not isinstance(row, PublicEntityRow) or row.graph_id != graph_id:
                raise IntegrityViolation()
            _validate_id(row.entity_id, "Invalid public entity identifier.")
            _validate_kind(row.kind)
            _copy_json_properties(row.properties)
        except ValidationError:
            raise IntegrityViolation() from None

    @staticmethod
    def _validate_public_relationship_row(
        graph_id: str,
        row: PublicRelationshipRow,
    ) -> None:
        try:
            if (
                not isinstance(row, PublicRelationshipRow)
                or row.graph_id != graph_id
            ):
                raise IntegrityViolation()
            _validate_id(
                row.relationship_id,
                "Invalid public relationship identifier.",
            )
            _validate_id(row.from_entity_id, "Invalid public endpoint.")
            _validate_id(row.to_entity_id, "Invalid public endpoint.")
            _validate_kind(row.kind)
            _copy_json_properties(row.properties)
        except ValidationError:
            raise IntegrityViolation() from None

    @staticmethod
    def _decode_private_entity(
        properties: Mapping[str, Any],
    ) -> tuple[str, str, dict[str, Any]]:
        try:
            graph_id = properties["graph_id"]
            kind = properties["kind"]
            semantic_properties = properties["properties"]
            _validate_id(graph_id, "Invalid encrypted graph identifier.")
            _validate_kind(kind)
            copied = _copy_json_properties(semantic_properties)
            return graph_id, kind, copied
        except (KeyError, TypeError, ValidationError):
            raise IntegrityViolation() from None

    @staticmethod
    def _decode_public_anchor(
        properties: Mapping[str, Any],
    ) -> tuple[str, str]:
        try:
            graph_id = properties["graph_id"]
            public_entity_id = properties["public_entity_id"]
            _validate_id(graph_id, "Invalid encrypted graph identifier.")
            _validate_id(public_entity_id, "Invalid encrypted public anchor.")
            return graph_id, public_entity_id
        except (KeyError, TypeError, ValidationError):
            raise IntegrityViolation() from None

    @staticmethod
    def _decode_private_relationship(
        properties: Mapping[str, Any],
    ) -> tuple[str, str, dict[str, Any]]:
        try:
            graph_id = properties["graph_id"]
            kind = properties["kind"]
            semantic_properties = properties["properties"]
            _validate_id(graph_id, "Invalid encrypted graph identifier.")
            _validate_kind(kind)
            copied = _copy_json_properties(semantic_properties)
            return graph_id, kind, copied
        except (KeyError, TypeError, ValidationError):
            raise IntegrityViolation() from None
