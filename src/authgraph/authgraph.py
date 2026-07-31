"""Canonical public/private graph facade backed by scoped AuthGraph v2.

This module intentionally composes the existing scoped encryption service and
the public graph repository instead of teaching callers two unrelated graph
APIs.  It is a trusted-backend API: protection scopes, access contexts, and
public publisher capabilities must never be supplied by a language model.

Private graph metadata is stored inside authenticated scoped ciphertext using
small wrapper records.  Consequently, one owner vault may contain overlays for
more than one logical public graph without exposing ``graph_id`` on its
private Neo4j rows.
"""

from __future__ import annotations

import json
import secrets
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
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
    ScopedEntity,
    ScopedRelationship,
)
from .public_repository import PublicGraphRepository
from .scoped_service import ScopedAuthGraphService
from .service import (
    MAX_ID_CHARS,
    MAX_KIND_CHARS,
    MAX_VAULT_SNAPSHOT_ENTITIES,
    MAX_VAULT_SNAPSHOT_RELATIONSHIPS,
)


MAX_PUBLIC_JSON_BYTES = 64 * 1024
MAX_PUBLIC_SNAPSHOT_JSON_BYTES = 256 * 1024

PRIVATE_ENTITY_WRAPPER_KIND = "__authgraph_facade_private_entity_v2"
PUBLIC_ANCHOR_WRAPPER_KIND = "__authgraph_facade_public_anchor_v2"
PRIVATE_RELATIONSHIP_WRAPPER_KIND = (
    "__authgraph_facade_private_relationship_v2"
)

_ENTITY_WRAPPER_FIELDS = frozenset({"graph_id", "kind", "properties"})
_PUBLIC_ANCHOR_FIELDS = frozenset({"graph_id", "public_entity_id"})
_RELATIONSHIP_WRAPPER_FIELDS = frozenset(
    {"graph_id", "kind", "properties"}
)
_RESERVED_KINDS = frozenset(
    {
        PRIVATE_ENTITY_WRAPPER_KIND,
        PUBLIC_ANCHOR_WRAPPER_KIND,
        PRIVATE_RELATIONSHIP_WRAPPER_KIND,
    }
)


@dataclass(frozen=True, slots=True)
class GraphEntityRecord:
    """One resolved semantic entity without its private protection-scope ID.

    Public records currently have no mutation revision, so
    ``record_revision`` is ``None`` for them. Private scoped-v2 records always
    carry a positive revision suitable for optimistic updates and deletes.
    """

    graph_id: str
    entity_id: str
    kind: str
    properties: Mapping[str, Any]
    protection: ProtectionLevel
    record_revision: int | None


@dataclass(frozen=True, slots=True)
class GraphRelationshipRecord:
    """One resolved private relationship with optimistic revision metadata."""

    graph_id: str
    relationship_id: str
    from_entity_id: str
    to_entity_id: str
    kind: str
    properties: Mapping[str, Any]
    protection: ProtectionLevel
    record_revision: int


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
        or kind in _RESERVED_KINDS
    ):
        raise ValidationError(
            "Entity and relationship kinds must be short text."
        )


def _copy_json_properties(properties: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(properties, Mapping):
        raise ValidationError("Properties must be supplied as a JSON object.")
    try:
        encoded = json.dumps(
            dict(properties),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (
        TypeError,
        ValueError,
        RecursionError,
        UnicodeEncodeError,
    ) as exc:
        raise ValidationError("Properties must be a valid JSON object.") from exc
    if len(encoded) > MAX_PUBLIC_JSON_BYTES:
        raise ValidationError(
            f"Properties may contain at most {MAX_PUBLIC_JSON_BYTES} bytes."
        )
    # The round trip supplies a detached deep copy and a consistent JSON
    # normalization for both public rows and private wrapper semantics.
    return json.loads(encoded)


class AuthGraph:
    """One graph API for plaintext public data and scoped-v2 private data.

    ``scope_id`` and ``context`` parameters are server-owned authorization
    inputs.  A chatbot-facing tool must bind them out of band.

    Encrypted relationships can connect private records and/or encrypted
    anchors for public records. The anchor and edge are committed atomically.
    """

    def __init__(
        self,
        protected: ScopedAuthGraphService,
        public_repository: PublicGraphRepository,
        *,
        default_policy: GraphPolicy | None = None,
        graph_policies: Mapping[str, GraphPolicy] | None = None,
        public_write_authorizer: Callable[[object, str], bool] | None = None,
    ) -> None:
        if not isinstance(protected, ScopedAuthGraphService):
            raise TypeError(
                "protected must be a ScopedAuthGraphService."
            )
        required_repository_methods = (
            "put_public_entity",
            "get_public_entity",
            "put_public_relationship",
            "get_public_graph_snapshot",
        )
        if any(
            not callable(getattr(public_repository, name, None))
            for name in required_repository_methods
        ):
            raise TypeError(
                "public_repository must implement PublicGraphRepository."
            )
        if (
            public_write_authorizer is not None
            and not callable(public_write_authorizer)
        ):
            raise TypeError("public_write_authorizer must be callable.")

        self._protected = protected
        self._public_repository = public_repository
        self._public_write_authorizer = public_write_authorizer
        self._default_policy = self._validate_policy(
            GraphPolicy() if default_policy is None else default_policy
        )
        supplied_policies = (
            {} if graph_policies is None else dict(graph_policies)
        )
        self._graph_policies: dict[str, GraphPolicy] = {}
        for graph_id, policy in supplied_policies.items():
            _validate_id(graph_id, "Invalid opaque graph identifier.")
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
            raise ValidationError("Invalid graph policy.")
        return policy

    def get_policy(self, graph_id: str) -> GraphPolicy:
        _validate_id(graph_id, "Invalid opaque graph identifier.")
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
            permitted = self._public_write_authorizer(publisher, graph_id)
        except Exception:
            raise AuthorizationDenied() from None
        if permitted is not True:
            raise AuthorizationDenied()

    # These small delegates keep normal users on one service object while the
    # scoped cryptographic service remains independently testable.
    def create_vault(
        self,
        principal_id: str,
        passphrase: bytes | bytearray | memoryview,
    ) -> str:
        return self._protected.create_vault(principal_id, passphrase)

    def create_scope(
        self,
        principal_id: str,
        vault_id: str,
        passphrase: bytes | bytearray | memoryview,
    ) -> str:
        return self._protected.create_protection_scope(
            principal_id,
            vault_id,
            passphrase,
        )

    def create_protection_scope(
        self,
        principal_id: str,
        vault_id: str,
        passphrase: bytes | bytearray | memoryview,
    ) -> str:
        """Compatibility spelling for callers using the low-level term."""

        return self.create_scope(principal_id, vault_id, passphrase)

    def unlock(
        self,
        principal_id: str,
        vault_id: str,
        passphrase: bytes | bytearray | memoryview,
        scope_ids: tuple[str, ...],
        *,
        ttl_seconds: int | None = None,
    ) -> AccessContext:
        return self._protected.unlock(
            principal_id,
            vault_id,
            passphrase,
            scope_ids,
            ttl_seconds=ttl_seconds,
        )

    def lock(self, context: AccessContext) -> None:
        self._protected.lock(context)

    def change_passphrase(
        self,
        principal_id: str,
        vault_id: str,
        current_passphrase: bytes | bytearray | memoryview,
        new_passphrase: bytes | bytearray | memoryview,
    ) -> None:
        self._protected.change_passphrase(
            principal_id,
            vault_id,
            current_passphrase,
            new_passphrase,
        )

    def create_entity(
        self,
        graph_id: str,
        kind: str,
        properties: Mapping[str, Any],
        *,
        context: AccessContext | None = None,
        scope_id: str | None = None,
        protection: ProtectionLevel | None = None,
        publisher: object | None = None,
        idempotency_key: str | None = None,
    ) -> GraphEntityRef:
        """Create one public or independently scoped private entity."""

        _validate_id(graph_id, "Invalid opaque graph identifier.")
        _validate_kind(kind)
        copied = _copy_json_properties(properties)
        policy = self.get_policy(graph_id)
        effective = self._effective_protection(
            protection,
            default=policy.default_entity_protection,
            policy=policy,
        )

        if effective is ProtectionLevel.PRIVATE:
            if scope_id is None:
                raise ValidationError(
                    "A private entity requires a protection scope."
                )
            _validate_id(scope_id, "Invalid opaque protection scope.")
            entity_id = self._protected.create_entity(
                self._require_context(context),
                scope_id,
                PRIVATE_ENTITY_WRAPPER_KIND,
                {
                    "graph_id": graph_id,
                    "kind": kind,
                    "properties": copied,
                },
                idempotency_key=idempotency_key,
            )
            return GraphEntityRef(
                graph_id=graph_id,
                entity_id=entity_id,
                protection=ProtectionLevel.PRIVATE,
            )

        if scope_id is not None:
            raise ValidationError(
                "A public entity must not select a protection scope."
            )
        if idempotency_key is not None:
            raise ValidationError(
                "Public idempotent creation is not implemented."
            )
        self._authorize_public_write(publisher, graph_id)
        for _ in range(3):
            entity_id = f"public_{secrets.token_urlsafe(24)}"
            if self._public_repository.put_public_entity(
                PublicEntityRow(
                    graph_id=graph_id,
                    entity_id=entity_id,
                    kind=kind,
                    properties=copied,
                )
            ):
                return GraphEntityRef(
                    graph_id=graph_id,
                    entity_id=entity_id,
                    protection=ProtectionLevel.PUBLIC,
                )
        raise ConflictError("Could not allocate a unique public entity identifier.")

    def get_entity(
        self,
        graph_id: str,
        reference: GraphEntityRef,
        *,
        context: AccessContext | None = None,
    ) -> GraphEntityRecord:
        """Resolve a typed reference against its actual backing repository."""

        _validate_id(graph_id, "Invalid opaque graph identifier.")
        self._validate_ref(graph_id, reference)
        if reference.protection is ProtectionLevel.PUBLIC:
            row = self._public_repository.get_public_entity(
                graph_id,
                reference.entity_id,
            )
            if row is None:
                raise RecordNotFound()
            entity = self._decode_public_entity(graph_id, row)
            return GraphEntityRecord(
                graph_id=graph_id,
                entity_id=entity.entity_id,
                kind=entity.kind,
                properties=entity.properties,
                protection=ProtectionLevel.PUBLIC,
                record_revision=None,
            )

        entity = self._protected.get_entity(
            self._require_context(context),
            reference.entity_id,
        )
        if (
            not isinstance(entity, ScopedEntity)
            or entity.kind != PRIVATE_ENTITY_WRAPPER_KIND
        ):
            raise RecordNotFound()
        entity_graph_id, semantic_kind, semantic_properties = (
            self._decode_private_entity(entity)
        )
        if entity_graph_id != graph_id:
            raise RecordNotFound()
        return GraphEntityRecord(
            graph_id=graph_id,
            entity_id=entity.entity_id,
            kind=semantic_kind,
            properties=semantic_properties,
            protection=ProtectionLevel.PRIVATE,
            record_revision=entity.record_revision,
        )

    def update_entity(
        self,
        graph_id: str,
        reference: GraphEntityRef,
        kind: str,
        properties: Mapping[str, Any],
        *,
        context: AccessContext,
        expected_revision: int,
    ) -> GraphEntityRecord:
        """Update one private entity without changing its graph or scope."""

        _validate_id(graph_id, "Invalid opaque graph identifier.")
        self._validate_ref(graph_id, reference)
        if reference.protection is not ProtectionLevel.PRIVATE:
            raise ValidationError(
                "Public entity updates are not implemented."
            )
        _validate_kind(kind)
        copied = _copy_json_properties(properties)
        secure_context = self._require_context(context)
        # Do not let this facade reclassify a raw low-level scoped record into
        # one of its wrappers. Resolve the existing wrapper first.
        self.get_entity(graph_id, reference, context=secure_context)
        entity = self._protected.update_entity(
            secure_context,
            reference.entity_id,
            PRIVATE_ENTITY_WRAPPER_KIND,
            {
                "graph_id": graph_id,
                "kind": kind,
                "properties": copied,
            },
            expected_revision=expected_revision,
        )
        entity_graph_id, semantic_kind, semantic_properties = (
            self._decode_private_entity(entity)
        )
        if entity_graph_id != graph_id:
            raise IntegrityViolation()
        return GraphEntityRecord(
            graph_id=graph_id,
            entity_id=entity.entity_id,
            kind=semantic_kind,
            properties=semantic_properties,
            protection=ProtectionLevel.PRIVATE,
            record_revision=entity.record_revision,
        )

    def delete_entity(
        self,
        graph_id: str,
        reference: GraphEntityRef,
        *,
        context: AccessContext,
        expected_revision: int,
    ) -> None:
        """Delete one private entity if it has no incident relationships."""

        _validate_id(graph_id, "Invalid opaque graph identifier.")
        self._validate_ref(graph_id, reference)
        if reference.protection is not ProtectionLevel.PRIVATE:
            raise ValidationError(
                "Public entity deletion is not implemented."
            )
        secure_context = self._require_context(context)
        self.get_entity(graph_id, reference, context=secure_context)
        self._protected.delete_entity(
            secure_context,
            reference.entity_id,
            expected_revision=expected_revision,
        )

    def connect(
        self,
        graph_id: str,
        from_entity: GraphEntityRef,
        to_entity: GraphEntityRef,
        kind: str,
        properties: Mapping[str, Any] | None = None,
        *,
        context: AccessContext | None = None,
        scope_id: str | None = None,
        protection: ProtectionLevel | None = None,
        publisher: object | None = None,
        idempotency_key: str | None = None,
    ) -> GraphRelationshipRef:
        """Create a plaintext public edge or an encrypted scoped edge."""

        _validate_id(graph_id, "Invalid opaque graph identifier.")
        _validate_kind(kind)
        copied = _copy_json_properties(
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
            if scope_id is not None:
                raise ValidationError(
                    "A public relationship must not select a protection scope."
                )
            if idempotency_key is not None:
                raise ValidationError(
                    "Public idempotent creation is not implemented."
                )
            # Resolve both references before writing.  Their claimed
            # ProtectionLevel is not treated as proof of storage.
            self.get_entity(graph_id, from_entity)
            self.get_entity(graph_id, to_entity)
            self._authorize_public_write(publisher, graph_id)
            for _ in range(3):
                relationship_id = f"public_{secrets.token_urlsafe(24)}"
                if self._public_repository.put_public_relationship(
                    PublicRelationshipRow(
                        graph_id=graph_id,
                        relationship_id=relationship_id,
                        from_entity_id=from_entity.entity_id,
                        to_entity_id=to_entity.entity_id,
                        kind=kind,
                        properties=copied,
                    )
                ):
                    return GraphRelationshipRef(
                        graph_id=graph_id,
                        relationship_id=relationship_id,
                        protection=ProtectionLevel.PUBLIC,
                    )
            raise ConflictError(
                "Could not allocate a unique public relationship identifier."
            )

        if scope_id is None:
            raise ValidationError(
                "A private relationship requires a protection scope."
            )
        _validate_id(scope_id, "Invalid opaque protection scope.")
        secure_context = self._require_context(context)
        # Resolve every claimed reference before creating any helper record.
        # The ProtectionLevel carried by a reference is not authorization.
        for endpoint in (from_entity, to_entity):
            self.get_entity(
                graph_id,
                endpoint,
                context=(
                    secure_context
                    if endpoint.protection is ProtectionLevel.PRIVATE
                    else None
                ),
            )

        new_anchor_specs: list[tuple[str, Mapping[str, Any]]] = []
        anchor_indexes: dict[str, int] = {}

        def protected_endpoint(endpoint: GraphEntityRef) -> str | int:
            if endpoint.protection is ProtectionLevel.PRIVATE:
                return endpoint.entity_id
            existing_index = anchor_indexes.get(endpoint.entity_id)
            if existing_index is not None:
                return existing_index
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

        from_protected = protected_endpoint(from_entity)
        to_protected = protected_endpoint(to_entity)
        relationship_properties = {
            "graph_id": graph_id,
            "kind": kind,
            "properties": copied,
        }
        if new_anchor_specs:
            if idempotency_key is not None:
                raise ValidationError(
                    "Idempotent creation of encrypted public-anchor "
                    "relationships is not implemented."
                )
            relationship_id, _ = (
                self._protected.create_relationship_bundle(
                    secure_context,
                    scope_id,
                    tuple(new_anchor_specs),
                    from_protected,
                    to_protected,
                    PRIVATE_RELATIONSHIP_WRAPPER_KIND,
                    relationship_properties,
                )
            )
        else:
            if (
                not isinstance(from_protected, str)
                or not isinstance(to_protected, str)
            ):
                raise IntegrityViolation()
            relationship_id = self._protected.connect(
                secure_context,
                scope_id,
                from_protected,
                to_protected,
                PRIVATE_RELATIONSHIP_WRAPPER_KIND,
                relationship_properties,
                idempotency_key=idempotency_key,
            )
        return GraphRelationshipRef(
            graph_id=graph_id,
            relationship_id=relationship_id,
            protection=ProtectionLevel.PRIVATE,
        )

    def get_relationship(
        self,
        graph_id: str,
        reference: GraphRelationshipRef,
        *,
        context: AccessContext,
    ) -> GraphRelationshipRecord:
        """Resolve one private relationship without revealing its scope ID."""

        _validate_id(graph_id, "Invalid opaque graph identifier.")
        self._validate_relationship_ref(graph_id, reference)
        if reference.protection is not ProtectionLevel.PRIVATE:
            raise ValidationError(
                "Public relationship lookup is not implemented."
            )
        relationship = self._protected.get_relationship(
            self._require_context(context),
            reference.relationship_id,
        )
        if (
            not isinstance(relationship, ScopedRelationship)
            or relationship.kind != PRIVATE_RELATIONSHIP_WRAPPER_KIND
        ):
            raise RecordNotFound()
        (
            relationship_graph_id,
            semantic_kind,
            semantic_properties,
        ) = self._decode_private_relationship(relationship)
        if relationship_graph_id != graph_id:
            raise RecordNotFound()
        secure_context = self._require_context(context)
        from_entity_id = self._resolve_private_endpoint(
            graph_id,
            secure_context,
            relationship.from_entity_id,
        )
        to_entity_id = self._resolve_private_endpoint(
            graph_id,
            secure_context,
            relationship.to_entity_id,
        )
        return GraphRelationshipRecord(
            graph_id=graph_id,
            relationship_id=relationship.relationship_id,
            from_entity_id=from_entity_id,
            to_entity_id=to_entity_id,
            kind=semantic_kind,
            properties=semantic_properties,
            protection=ProtectionLevel.PRIVATE,
            record_revision=relationship.record_revision,
        )

    def _resolve_private_endpoint(
        self,
        graph_id: str,
        context: AccessContext,
        entity_id: str,
    ) -> str:
        """Resolve an encrypted entity wrapper or public anchor."""

        entity = self._protected.get_entity(context, entity_id)
        if not isinstance(entity, ScopedEntity):
            raise IntegrityViolation()
        if entity.kind == PRIVATE_ENTITY_WRAPPER_KIND:
            entity_graph_id, _, _ = self._decode_private_entity(entity)
            if entity_graph_id != graph_id:
                raise RecordNotFound()
            return entity.entity_id
        if entity.kind == PUBLIC_ANCHOR_WRAPPER_KIND:
            anchor_graph_id, public_entity_id = self._decode_public_anchor(
                entity
            )
            if anchor_graph_id != graph_id:
                raise RecordNotFound()
            self.get_entity(
                graph_id,
                GraphEntityRef(
                    graph_id=graph_id,
                    entity_id=public_entity_id,
                    protection=ProtectionLevel.PUBLIC,
                ),
            )
            return public_entity_id
        raise RecordNotFound()

    def update_relationship(
        self,
        graph_id: str,
        reference: GraphRelationshipRef,
        kind: str,
        properties: Mapping[str, Any] | None = None,
        *,
        context: AccessContext,
        expected_revision: int,
    ) -> GraphRelationshipRecord:
        """Update private relationship semantics without moving endpoints."""

        _validate_id(graph_id, "Invalid opaque graph identifier.")
        self._validate_relationship_ref(graph_id, reference)
        if reference.protection is not ProtectionLevel.PRIVATE:
            raise ValidationError(
                "Public relationship updates are not implemented."
            )
        _validate_kind(kind)
        copied = _copy_json_properties(
            {} if properties is None else properties
        )
        secure_context = self._require_context(context)
        self.get_relationship(
            graph_id,
            reference,
            context=secure_context,
        )
        relationship = self._protected.update_relationship(
            secure_context,
            reference.relationship_id,
            PRIVATE_RELATIONSHIP_WRAPPER_KIND,
            {
                "graph_id": graph_id,
                "kind": kind,
                "properties": copied,
            },
            expected_revision=expected_revision,
        )
        (
            relationship_graph_id,
            semantic_kind,
            semantic_properties,
        ) = self._decode_private_relationship(relationship)
        if relationship_graph_id != graph_id:
            raise IntegrityViolation()
        from_entity_id = self._resolve_private_endpoint(
            graph_id,
            secure_context,
            relationship.from_entity_id,
        )
        to_entity_id = self._resolve_private_endpoint(
            graph_id,
            secure_context,
            relationship.to_entity_id,
        )
        return GraphRelationshipRecord(
            graph_id=graph_id,
            relationship_id=relationship.relationship_id,
            from_entity_id=from_entity_id,
            to_entity_id=to_entity_id,
            kind=semantic_kind,
            properties=semantic_properties,
            protection=ProtectionLevel.PRIVATE,
            record_revision=relationship.record_revision,
        )

    def delete_relationship(
        self,
        graph_id: str,
        reference: GraphRelationshipRef,
        *,
        context: AccessContext,
        expected_revision: int,
    ) -> None:
        """Delete one private relationship with an optimistic revision."""

        _validate_id(graph_id, "Invalid opaque graph identifier.")
        self._validate_relationship_ref(graph_id, reference)
        if reference.protection is not ProtectionLevel.PRIVATE:
            raise ValidationError(
                "Public relationship deletion is not implemented."
            )
        secure_context = self._require_context(context)
        self.get_relationship(
            graph_id,
            reference,
            context=secure_context,
        )
        self._protected.delete_relationship(
            secure_context,
            reference.relationship_id,
            expected_revision=expected_revision,
        )

    @staticmethod
    def _validate_ref(
        graph_id: str,
        reference: GraphEntityRef,
    ) -> None:
        if (
            not isinstance(reference, GraphEntityRef)
            or reference.graph_id != graph_id
            or type(reference.protection) is not ProtectionLevel
        ):
            raise ValidationError("Invalid graph entity reference.")
        _validate_id(reference.entity_id, "Invalid graph entity reference.")

    @staticmethod
    def _validate_relationship_ref(
        graph_id: str,
        reference: GraphRelationshipRef,
    ) -> None:
        if (
            not isinstance(reference, GraphRelationshipRef)
            or reference.graph_id != graph_id
            or type(reference.protection) is not ProtectionLevel
        ):
            raise ValidationError("Invalid graph relationship reference.")
        _validate_id(
            reference.relationship_id,
            "Invalid graph relationship reference.",
        )

    def get_public_view(
        self,
        graph_id: str,
        *,
        entity_limit: int = MAX_VAULT_SNAPSHOT_ENTITIES,
        relationship_limit: int = MAX_VAULT_SNAPSHOT_RELATIONSHIPS,
    ) -> LayeredGraphView:
        """Return only intentionally public data without touching a vault."""

        entities, relationships = self._read_public(
            graph_id,
            entity_limit=entity_limit,
            relationship_limit=relationship_limit,
        )
        return LayeredGraphView(
            graph_id=graph_id,
            entities=tuple(entities.values()),
            relationships=tuple(relationships.values()),
            private_overlay_included=False,
            locked_disclosure=self.get_policy(graph_id).locked_disclosure,
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
        """Compose public data with wrappers visible to one scoped session."""

        entities, relationships = self._read_public(
            graph_id,
            entity_limit=public_entity_limit,
            relationship_limit=public_relationship_limit,
        )
        snapshot = self._protected.get_vault_snapshot(
            self._require_context(context),
            entity_limit=private_entity_limit,
            relationship_limit=private_relationship_limit,
        )

        private_entity_ids: set[str] = set()
        public_anchors: dict[str, str] = {}
        for entity in snapshot.entities:
            if not isinstance(entity, ScopedEntity):
                raise IntegrityViolation()
            if entity.kind == PUBLIC_ANCHOR_WRAPPER_KIND:
                anchor_graph_id, public_entity_id = (
                    self._decode_public_anchor(entity)
                )
                if anchor_graph_id != graph_id:
                    continue
                if (
                    entity.entity_id in public_anchors
                    or public_entity_id not in entities
                ):
                    raise IntegrityViolation()
                public_anchors[entity.entity_id] = public_entity_id
                continue
            if entity.kind != PRIVATE_ENTITY_WRAPPER_KIND:
                continue
            (
                entity_graph_id,
                semantic_kind,
                semantic_properties,
            ) = self._decode_private_entity(entity)
            if entity_graph_id != graph_id:
                continue
            if entity.entity_id in entities:
                raise IntegrityViolation()
            entities[entity.entity_id] = LayeredEntity(
                entity_id=entity.entity_id,
                kind=semantic_kind,
                properties=semantic_properties,
                protection=ProtectionLevel.PRIVATE,
            )
            private_entity_ids.add(entity.entity_id)

        for relationship in snapshot.relationships:
            if (
                not isinstance(relationship, ScopedRelationship)
                or relationship.kind != PRIVATE_RELATIONSHIP_WRAPPER_KIND
            ):
                continue
            (
                relationship_graph_id,
                semantic_kind,
                semantic_properties,
            ) = self._decode_private_relationship(relationship)
            if relationship_graph_id != graph_id:
                continue
            if (
                relationship.relationship_id in relationships
            ):
                raise IntegrityViolation()
            endpoint_ids = private_entity_ids | set(public_anchors)
            if (
                relationship.from_entity_id not in endpoint_ids
                or relationship.to_entity_id not in endpoint_ids
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
            relationships[relationship.relationship_id] = (
                LayeredRelationship(
                    relationship_id=relationship.relationship_id,
                    from_entity_id=from_entity_id,
                    to_entity_id=to_entity_id,
                    kind=semantic_kind,
                    properties=semantic_properties,
                    protection=ProtectionLevel.PRIVATE,
                )
            )

        return LayeredGraphView(
            graph_id=graph_id,
            entities=tuple(
                sorted(entities.values(), key=lambda row: row.entity_id)
            ),
            relationships=tuple(
                sorted(
                    relationships.values(),
                    key=lambda row: row.relationship_id,
                )
            ),
            private_overlay_included=True,
            locked_disclosure=LockedDisclosure.HIDDEN,
        )

    @staticmethod
    def _validate_limits(entity_limit: int, relationship_limit: int) -> None:
        if (
            type(entity_limit) is not int
            or entity_limit <= 0
            or entity_limit > MAX_VAULT_SNAPSHOT_ENTITIES
            or type(relationship_limit) is not int
            or relationship_limit <= 0
            or relationship_limit > MAX_VAULT_SNAPSHOT_RELATIONSHIPS
        ):
            raise ValidationError("Graph snapshot limits are invalid.")

    def _read_public(
        self,
        graph_id: str,
        *,
        entity_limit: int,
        relationship_limit: int,
    ) -> tuple[dict[str, LayeredEntity], dict[str, LayeredRelationship]]:
        _validate_id(graph_id, "Invalid opaque graph identifier.")
        self._validate_limits(entity_limit, relationship_limit)
        snapshot = self._public_repository.get_public_graph_snapshot(
            graph_id,
            entity_limit=entity_limit,
            relationship_limit=relationship_limit,
        )
        if not isinstance(snapshot, PublicGraphSnapshotRow):
            raise IntegrityViolation()
        try:
            if (
                len(snapshot.entities) > entity_limit
                or len(snapshot.relationships) > relationship_limit
            ):
                raise ValidationError(
                    "The complete public graph does not fit within limits."
                )
        except (AttributeError, TypeError):
            raise IntegrityViolation() from None

        entities: dict[str, LayeredEntity] = {}
        relationships: dict[str, LayeredRelationship] = {}
        semantic_bytes = 0
        for row in snapshot.entities:
            entity = self._decode_public_entity(graph_id, row)
            if entity.entity_id in entities:
                raise IntegrityViolation()
            semantic_bytes += self._semantic_size(
                entity.kind,
                entity.properties,
            )
            if semantic_bytes > MAX_PUBLIC_SNAPSHOT_JSON_BYTES:
                raise ValidationError(
                    "The complete public graph exceeds its byte limit."
                )
            entities[entity.entity_id] = entity

        for row in snapshot.relationships:
            relationship = self._decode_public_relationship(graph_id, row)
            if (
                relationship.relationship_id in relationships
                or relationship.from_entity_id not in entities
                or relationship.to_entity_id not in entities
            ):
                raise IntegrityViolation()
            semantic_bytes += self._semantic_size(
                relationship.kind,
                relationship.properties,
            )
            if semantic_bytes > MAX_PUBLIC_SNAPSHOT_JSON_BYTES:
                raise ValidationError(
                    "The complete public graph exceeds its byte limit."
                )
            relationships[relationship.relationship_id] = relationship
        return (
            dict(sorted(entities.items())),
            dict(sorted(relationships.items())),
        )

    @staticmethod
    def _semantic_size(kind: str, properties: Mapping[str, Any]) -> int:
        encoded = json.dumps(
            dict(properties),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return len(kind.encode("utf-8")) + len(encoded)

    @staticmethod
    def _decode_public_entity(
        graph_id: str,
        row: PublicEntityRow,
    ) -> LayeredEntity:
        try:
            if (
                not isinstance(row, PublicEntityRow)
                or row.graph_id != graph_id
            ):
                raise IntegrityViolation()
            _validate_id(row.entity_id, "Invalid public entity identifier.")
            _validate_kind(row.kind)
            properties = _copy_json_properties(row.properties)
        except ValidationError:
            raise IntegrityViolation() from None
        return LayeredEntity(
            entity_id=row.entity_id,
            kind=row.kind,
            properties=properties,
            protection=ProtectionLevel.PUBLIC,
        )

    @staticmethod
    def _decode_public_relationship(
        graph_id: str,
        row: PublicRelationshipRow,
    ) -> LayeredRelationship:
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
            properties = _copy_json_properties(row.properties)
        except ValidationError:
            raise IntegrityViolation() from None
        return LayeredRelationship(
            relationship_id=row.relationship_id,
            from_entity_id=row.from_entity_id,
            to_entity_id=row.to_entity_id,
            kind=row.kind,
            properties=properties,
            protection=ProtectionLevel.PUBLIC,
        )

    @staticmethod
    def _decode_private_entity(
        entity: ScopedEntity,
    ) -> tuple[str, str, dict[str, Any]]:
        try:
            values = entity.properties
            if (
                not isinstance(values, Mapping)
                or frozenset(values) != _ENTITY_WRAPPER_FIELDS
            ):
                raise IntegrityViolation()
            graph_id = values["graph_id"]
            kind = values["kind"]
            properties = values["properties"]
            _validate_id(graph_id, "Invalid encrypted graph identifier.")
            _validate_kind(kind)
            return graph_id, kind, _copy_json_properties(properties)
        except (KeyError, TypeError, ValidationError):
            raise IntegrityViolation() from None

    @staticmethod
    def _decode_public_anchor(
        entity: ScopedEntity,
    ) -> tuple[str, str]:
        try:
            values = entity.properties
            if (
                not isinstance(values, Mapping)
                or frozenset(values) != _PUBLIC_ANCHOR_FIELDS
            ):
                raise IntegrityViolation()
            graph_id = values["graph_id"]
            public_entity_id = values["public_entity_id"]
            _validate_id(graph_id, "Invalid encrypted graph identifier.")
            _validate_id(
                public_entity_id,
                "Invalid encrypted public anchor.",
            )
            return graph_id, public_entity_id
        except (KeyError, TypeError, ValidationError):
            raise IntegrityViolation() from None

    @staticmethod
    def _decode_private_relationship(
        relationship: ScopedRelationship,
    ) -> tuple[str, str, dict[str, Any]]:
        try:
            values = relationship.properties
            if (
                not isinstance(values, Mapping)
                or frozenset(values) != _RELATIONSHIP_WRAPPER_FIELDS
            ):
                raise IntegrityViolation()
            graph_id = values["graph_id"]
            kind = values["kind"]
            properties = values["properties"]
            _validate_id(graph_id, "Invalid encrypted graph identifier.")
            _validate_kind(kind)
            return graph_id, kind, _copy_json_properties(properties)
        except (KeyError, TypeError, ValidationError):
            raise IntegrityViolation() from None
