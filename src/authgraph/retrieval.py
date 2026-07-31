"""Bounded, chatbot-safe retrieval over a session-visible layered graph.

The model-facing boundary in this module never accepts a principal ID, vault
ID, session token, protection choice, result limit, or Cypher.  A trusted host
binds a :class:`SessionVisibleGraphGateway` to one graph and one disclosure
policy, then attaches an optional :class:`~authgraph.models.AccessContext` out
of band when it executes a retrieval request.

This is an isolated first GraphRAG slice whose cryptographic boundary depends
on the trusted view provider. The legacy
:class:`~authgraph.layered_service.LayeredGraphService` decrypts one bounded
*complete vault snapshot* before filtering it by ``graph_id``. In contrast,
:class:`~authgraph.scoped_retrieval.ScopedGraphViewAdapter` obtains a snapshot
from :class:`~authgraph.scoped_service.ScopedAuthGraphService`, which decrypts
only the protection scopes granted to that session. In either case this
gateway additionally minimizes what is returned to a caller or model.

``SessionVisibleGraphGateway.build_vector_index`` creates a policy- and
context-bound in-memory index from the same allowlisted projection used for
retrieval. Raw ``EphemeralVectorIndex`` instances are deliberately rejected by
the gateway. The helper does not persist embeddings or make encrypted Neo4j
vectors searchable.
"""

from __future__ import annotations

import json
import math
import re
import threading
import unicodedata
from array import array
from collections import Counter, deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from numbers import Real
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from .errors import (
    ConflictError,
    IntegrityViolation,
    SessionUnavailable,
    ValidationError,
)
from .layered_service import LayeredGraphService
from .models import (
    AccessContext,
    LayeredGraphView,
)


MAX_QUERY_CHARS = 8 * 1024
HARD_MAX_CANDIDATES = 100
HARD_MAX_NODES = 100
HARD_MAX_EDGES = 200
HARD_MAX_HOPS = 4
HARD_MAX_PLAINTEXT_BYTES = 256 * 1024
HARD_MAX_TOKEN_ESTIMATE = 64 * 1024

HARD_MAX_VECTOR_ITEMS = 10_000
HARD_MAX_VECTOR_DIMENSIONS = 4_096
HARD_MAX_VECTOR_VALUES = 4_000_000

_MAX_ID_CHARS = 256
_MAX_KIND_CHARS = 128
_MAX_PROPERTY_NAME_CHARS = 256
_TOKEN_PATTERN = re.compile(r"[^\W_]+", re.UNICODE)
_WILDCARD = "*"


def _validate_text_identifier(
    value: str,
    *,
    description: str,
    maximum: int,
    allow_wildcard: bool = False,
) -> None:
    if allow_wildcard and value == _WILDCARD:
        return
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(unicodedata.category(char).startswith("C") for char in value)
    ):
        raise ValidationError(description)


def _normalize_names(
    value: object,
    *,
    description: str,
    maximum: int,
    allow_wildcard: bool,
) -> frozenset[str]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(
        value,
        (set, frozenset, tuple, list),
    ):
        raise ValidationError(description)
    normalized: set[str] = set()
    for name in value:
        _validate_text_identifier(
            name,
            description=description,
            maximum=maximum,
            allow_wildcard=allow_wildcard,
        )
        normalized.add(name)
    return frozenset(normalized)


def _normalize_property_policy(
    value: object,
    *,
    description: str,
) -> Mapping[str, frozenset[str]]:
    if not isinstance(value, Mapping):
        raise ValidationError(description)
    normalized: dict[str, frozenset[str]] = {}
    for kind, property_names in value.items():
        _validate_text_identifier(
            kind,
            description=description,
            maximum=_MAX_KIND_CHARS,
            allow_wildcard=True,
        )
        normalized[kind] = _normalize_names(
            property_names,
            description=description,
            maximum=_MAX_PROPERTY_NAME_CHARS,
            allow_wildcard=True,
        )
    return MappingProxyType(dict(sorted(normalized.items())))


def _validate_bound(
    value: object,
    *,
    description: str,
    minimum: int,
    maximum: int,
) -> None:
    if type(value) is not int or value < minimum or value > maximum:
        raise ValidationError(description)


def _validate_query(value: object) -> None:
    if not isinstance(value, str) or len(value) > MAX_QUERY_CHARS:
        raise ValidationError("Retrieval query must be bounded text.")


def _freeze_json_value(value: object) -> object:
    """Return a detached, deeply immutable representation of JSON data."""

    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for key, nested in value.items():
            if type(key) is not str:
                raise IntegrityViolation()
            frozen[key] = _freeze_json_value(nested)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json_value(nested) for nested in value)
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float and math.isfinite(value):
        return value
    raise IntegrityViolation()


def _freeze_json_properties(value: object) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise IntegrityViolation()
    try:
        frozen = _freeze_json_value(value)
    except (RecursionError, RuntimeError):
        raise IntegrityViolation() from None
    assert isinstance(frozen, Mapping)
    return frozen


def _json_compatible_value(value: object) -> object:
    """Thaw immutable result data into fresh containers for serialization."""

    if isinstance(value, Mapping):
        return {
            key: _json_compatible_value(nested)
            for key, nested in value.items()
        }
    if isinstance(value, tuple):
        return [_json_compatible_value(nested) for nested in value]
    if value is None or type(value) in (str, bool, int, float):
        return value
    raise IntegrityViolation()


@dataclass(frozen=True, slots=True)
class DisclosurePolicy:
    """Server-owned allowlists and hard bounds for one retrieval gateway.

    Kind allowlists are deny-by-default.  Include ``"*"`` only when every kind
    is deliberately allowed.  Property allowlists are keyed by semantic kind;
    an exact rule takes precedence over a ``"*"`` rule, and a missing rule
    reveals no properties.  A property rule containing ``"*"`` reveals every
    property for that allowed kind.

    ``max_token_estimate`` bounds the deterministic UTF-8-byte heuristic used
    by this retriever. It is not a model tokenizer limit; the trusted host must
    independently bound the final prompt with the selected model's tokenizer.
    """

    allowed_entity_kinds: frozenset[str] = field(default_factory=frozenset)
    allowed_relationship_kinds: frozenset[str] = field(
        default_factory=frozenset
    )
    entity_property_allowlist: Mapping[str, frozenset[str]] = field(
        default_factory=dict
    )
    relationship_property_allowlist: Mapping[str, frozenset[str]] = field(
        default_factory=dict
    )
    max_candidates: int = 20
    max_nodes: int = 20
    max_edges: int = 30
    max_hops: int = 1
    max_plaintext_bytes: int = 32 * 1024
    max_token_estimate: int = 4 * 1024

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "allowed_entity_kinds",
            _normalize_names(
                self.allowed_entity_kinds,
                description="Invalid allowed entity kind policy.",
                maximum=_MAX_KIND_CHARS,
                allow_wildcard=True,
            ),
        )
        object.__setattr__(
            self,
            "allowed_relationship_kinds",
            _normalize_names(
                self.allowed_relationship_kinds,
                description="Invalid allowed relationship kind policy.",
                maximum=_MAX_KIND_CHARS,
                allow_wildcard=True,
            ),
        )
        object.__setattr__(
            self,
            "entity_property_allowlist",
            _normalize_property_policy(
                self.entity_property_allowlist,
                description="Invalid entity property allowlist.",
            ),
        )
        object.__setattr__(
            self,
            "relationship_property_allowlist",
            _normalize_property_policy(
                self.relationship_property_allowlist,
                description="Invalid relationship property allowlist.",
            ),
        )
        _validate_bound(
            self.max_candidates,
            description="max_candidates exceeds the supported safety bounds.",
            minimum=1,
            maximum=HARD_MAX_CANDIDATES,
        )
        _validate_bound(
            self.max_nodes,
            description="max_nodes exceeds the supported safety bounds.",
            minimum=1,
            maximum=HARD_MAX_NODES,
        )
        _validate_bound(
            self.max_edges,
            description="max_edges exceeds the supported safety bounds.",
            minimum=0,
            maximum=HARD_MAX_EDGES,
        )
        _validate_bound(
            self.max_hops,
            description="max_hops exceeds the supported safety bounds.",
            minimum=0,
            maximum=HARD_MAX_HOPS,
        )
        _validate_bound(
            self.max_plaintext_bytes,
            description=(
                "max_plaintext_bytes exceeds the supported safety bounds."
            ),
            minimum=1,
            maximum=HARD_MAX_PLAINTEXT_BYTES,
        )
        _validate_bound(
            self.max_token_estimate,
            description=(
                "max_token_estimate exceeds the supported safety bounds."
            ),
            minimum=1,
            maximum=HARD_MAX_TOKEN_ESTIMATE,
        )


class RetrievalSource(StrEnum):
    LEXICAL = "lexical"
    VECTOR = "vector"
    TRAVERSAL = "traversal"


class RetrievalLimit(StrEnum):
    CANDIDATES = "candidates"
    NODES = "nodes"
    EDGES = "edges"
    HOPS = "hops"
    PLAINTEXT_BYTES = "plaintext_bytes"
    TOKEN_ESTIMATE = "token_estimate"


@dataclass(frozen=True, slots=True)
class RetrievalProvenance:
    """Why one visible record was selected."""

    sources: tuple[RetrievalSource, ...]
    hop: int
    seed_entity_id: str
    via_relationship_id: str | None = None
    lexical_score: int | None = None
    vector_score: float | None = None


@dataclass(frozen=True, slots=True)
class RetrievedEntity:
    entity_id: str
    kind: str
    properties: Mapping[str, Any]
    provenance: RetrievalProvenance

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "properties",
            _freeze_json_properties(self.properties),
        )


@dataclass(frozen=True, slots=True)
class RetrievedRelationship:
    relationship_id: str
    from_entity_id: str
    to_entity_id: str
    kind: str
    properties: Mapping[str, Any]
    provenance: RetrievalProvenance

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "properties",
            _freeze_json_properties(self.properties),
        )


@dataclass(frozen=True, slots=True)
class RetrievedSubgraph:
    """A bounded subgraph with one exact canonical JSON representation.

    ``plaintext_bytes`` is the exact length of :meth:`canonical_json_bytes`.
    ``token_estimate`` is only ``ceil(canonical UTF-8 bytes / 4)``. It is a
    deterministic retrieval heuristic, not a model-token count or tokenizer
    ceiling. A host must run the selected model's tokenizer and enforce its own
    final prompt limit before sending this data to a model.
    """

    graph_id: str
    entities: tuple[RetrievedEntity, ...]
    relationships: tuple[RetrievedRelationship, ...]
    plaintext_bytes: int
    token_estimate: int
    limits_reached: tuple[RetrievalLimit, ...]

    @property
    def truncated(self) -> bool:
        return bool(self.limits_reached)

    def canonical_json_bytes(self) -> bytes:
        """Return the complete deterministic payload covered by the byte count."""

        return _canonical_json_bytes(_subgraph_json(self))


def _provenance_json(provenance: RetrievalProvenance) -> dict[str, Any]:
    return {
        "sources": [source.value for source in provenance.sources],
        "hop": provenance.hop,
        "seed_entity_id": provenance.seed_entity_id,
        "via_relationship_id": provenance.via_relationship_id,
        "lexical_score": provenance.lexical_score,
        "vector_score": provenance.vector_score,
    }


def _retrieved_entity_json(entity: RetrievedEntity) -> dict[str, Any]:
    return {
        "entity_id": entity.entity_id,
        "kind": entity.kind,
        "properties": _json_compatible_value(entity.properties),
        "provenance": _provenance_json(entity.provenance),
    }


def _retrieved_relationship_json(
    relationship: RetrievedRelationship,
) -> dict[str, Any]:
    return {
        "relationship_id": relationship.relationship_id,
        "from_entity_id": relationship.from_entity_id,
        "to_entity_id": relationship.to_entity_id,
        "kind": relationship.kind,
        "properties": _json_compatible_value(relationship.properties),
        "provenance": _provenance_json(relationship.provenance),
    }


def _subgraph_json(result: RetrievedSubgraph) -> dict[str, Any]:
    return {
        "graph_id": result.graph_id,
        "entities": [
            _retrieved_entity_json(entity) for entity in result.entities
        ],
        "relationships": [
            _retrieved_relationship_json(relationship)
            for relationship in result.relationships
        ],
        "plaintext_bytes": result.plaintext_bytes,
        "token_estimate": result.token_estimate,
        "limits_reached": [
            limit.value for limit in result.limits_reached
        ],
    }


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
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
    ):
        raise IntegrityViolation() from None


def _token_estimate(plaintext_bytes: int) -> int:
    return (plaintext_bytes + 3) // 4


def _finalize_subgraph(
    *,
    graph_id: str,
    entities: tuple[RetrievedEntity, ...],
    relationships: tuple[RetrievedRelationship, ...],
    limits_reached: tuple[RetrievalLimit, ...],
) -> RetrievedSubgraph:
    """Resolve byte-count metadata against its own canonical serialization."""

    plaintext_bytes = 0
    token_estimate = 0
    for _ in range(16):
        result = RetrievedSubgraph(
            graph_id=graph_id,
            entities=entities,
            relationships=relationships,
            plaintext_bytes=plaintext_bytes,
            token_estimate=token_estimate,
            limits_reached=limits_reached,
        )
        next_plaintext_bytes = len(result.canonical_json_bytes())
        next_token_estimate = _token_estimate(next_plaintext_bytes)
        if (
            next_plaintext_bytes == plaintext_bytes
            and next_token_estimate == token_estimate
        ):
            return result
        plaintext_bytes = next_plaintext_bytes
        token_estimate = next_token_estimate
    raise IntegrityViolation()


def _maximum_envelope_size(
    graph_id: str,
    policy: DisclosurePolicy,
) -> int:
    """Reserve metadata space even if every truncation reason is reported."""

    result = RetrievedSubgraph(
        graph_id=graph_id,
        entities=(),
        relationships=(),
        plaintext_bytes=policy.max_plaintext_bytes,
        token_estimate=policy.max_token_estimate,
        limits_reached=tuple(RetrievalLimit),
    )
    return len(result.canonical_json_bytes())


@dataclass(frozen=True, slots=True)
class VectorMatch:
    entity_id: str
    score: float


class EphemeralVectorIndex:
    """Bounded pure-Python cosine index.

    Directly constructed instances are useful as standalone indexes, but a
    retrieval gateway accepts only an index it built and sealed itself from
    policy-projected entity data. ``close()`` overwrites the mutable arrays and
    drops every reference best-effort. As with all managed runtimes, complete
    memory zeroization cannot be guaranteed.
    """

    def __init__(self, dimension: int, *, max_items: int = 1_000) -> None:
        _validate_bound(
            dimension,
            description="Vector dimension exceeds the supported safety bounds.",
            minimum=1,
            maximum=HARD_MAX_VECTOR_DIMENSIONS,
        )
        _validate_bound(
            max_items,
            description="Vector item limit exceeds the supported safety bounds.",
            minimum=1,
            maximum=HARD_MAX_VECTOR_ITEMS,
        )
        if dimension * max_items > HARD_MAX_VECTOR_VALUES:
            raise ValidationError(
                "Vector index capacity exceeds the supported safety bounds."
            )
        self._dimension = dimension
        self._max_items = max_items
        self._vectors: dict[str, array[float]] = {}
        self._closed = False
        self._sealed = False
        self._gateway_binding: object | None = None
        self._binding_context: AccessContext | None = None
        self._lock = threading.RLock()

    @property
    def dimension(self) -> int:
        return self._dimension

    @property
    def max_items(self) -> int:
        return self._max_items

    @property
    def item_count(self) -> int:
        with self._lock:
            return len(self._vectors)

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def __enter__(self) -> EphemeralVectorIndex:
        with self._lock:
            if self._closed:
                raise SessionUnavailable()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()

    @staticmethod
    def _clear_vector(vector: array[float]) -> None:
        for index in range(len(vector)):
            vector[index] = 0.0

    def _normalized_vector(
        self,
        embedding: Sequence[float],
    ) -> array[float]:
        if isinstance(embedding, (str, bytes, bytearray)) or not isinstance(
            embedding,
            Sequence,
        ):
            raise ValidationError("Embedding must be a numeric sequence.")
        try:
            length = len(embedding)
        except (OverflowError, TypeError):
            raise ValidationError("Embedding must be a numeric sequence.") from None
        if length != self._dimension:
            raise ValidationError("Embedding dimension does not match the index.")

        normalized = array("d")
        try:
            for value in embedding:
                if isinstance(value, bool) or not isinstance(value, Real):
                    raise ValidationError(
                        "Embedding values must be finite real numbers."
                    )
                try:
                    number = float(value)
                except (OverflowError, TypeError, ValueError):
                    raise ValidationError(
                        "Embedding values must be finite real numbers."
                    ) from None
                if not math.isfinite(number):
                    raise ValidationError(
                        "Embedding values must be finite real numbers."
                    )
                normalized.append(number)
            try:
                norm_squared = math.fsum(
                    number * number for number in normalized
                )
            except OverflowError:
                raise ValidationError(
                    "Embedding must have a finite non-zero magnitude."
                ) from None
            if not math.isfinite(norm_squared) or norm_squared <= 0.0:
                raise ValidationError(
                    "Embedding must have a finite non-zero magnitude."
                )
            norm = math.sqrt(norm_squared)
            for index in range(len(normalized)):
                normalized[index] /= norm
            return normalized
        except Exception:
            self._clear_vector(normalized)
            raise

    def add(self, entity_id: str, embedding: Sequence[float]) -> None:
        _validate_text_identifier(
            entity_id,
            description="Invalid opaque vector entity identifier.",
            maximum=_MAX_ID_CHARS,
        )
        with self._lock:
            if self._closed:
                raise SessionUnavailable()
            if self._sealed:
                raise ConflictError(
                    "A gateway-bound vector index cannot be modified."
                )
            if entity_id in self._vectors:
                raise ConflictError(
                    "The vector index already contains this entity."
                )
            if len(self._vectors) >= self._max_items:
                raise ValidationError(
                    "The vector index item limit has been reached."
                )
            normalized = self._normalized_vector(embedding)
            self._vectors[entity_id] = normalized

    def _seal_for_gateway(
        self,
        gateway_binding: object,
        context: AccessContext | None,
    ) -> None:
        with self._lock:
            if self._closed:
                raise SessionUnavailable()
            if self._sealed:
                raise ConflictError("The vector index is already bound.")
            self._gateway_binding = gateway_binding
            self._binding_context = context
            self._sealed = True

    def _is_bound_to(
        self,
        gateway_binding: object,
        context: AccessContext | None,
    ) -> bool:
        with self._lock:
            return (
                not self._closed
                and self._sealed
                and self._gateway_binding is gateway_binding
                and self._binding_context == context
            )

    def search(
        self,
        query_embedding: Sequence[float],
        *,
        top_k: int,
    ) -> tuple[VectorMatch, ...]:
        _validate_bound(
            top_k,
            description="Vector top_k exceeds the supported safety bounds.",
            minimum=1,
            maximum=HARD_MAX_VECTOR_ITEMS,
        )
        with self._lock:
            if self._closed:
                raise SessionUnavailable()
            query = self._normalized_vector(query_embedding)
            try:
                matches: list[VectorMatch] = []
                for entity_id, candidate in self._vectors.items():
                    score = math.fsum(
                        left * right
                        for left, right in zip(
                            query,
                            candidate,
                            strict=True,
                        )
                    )
                    score = max(-1.0, min(1.0, score))
                    matches.append(
                        VectorMatch(
                            entity_id=entity_id,
                            score=score,
                        )
                    )
                matches.sort(key=lambda match: (-match.score, match.entity_id))
                return tuple(matches[:top_k])
            finally:
                self._clear_vector(query)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for vector in self._vectors.values():
                self._clear_vector(vector)
            self._vectors.clear()
            self._gateway_binding = None
            self._binding_context = None


@dataclass(frozen=True, slots=True)
class _ProjectedEntity:
    entity_id: str
    kind: str
    properties: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _ProjectedRelationship:
    relationship_id: str
    from_entity_id: str
    to_entity_id: str
    kind: str
    properties: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _Seed:
    entity_id: str
    sources: tuple[RetrievalSource, ...]
    lexical_score: int | None
    vector_score: float | None
    combined_score: float
    lexical_component: float
    vector_component: float


class _Budget:
    def __init__(
        self,
        policy: DisclosurePolicy,
        *,
        envelope_reserve: int,
    ) -> None:
        self._policy = policy
        self._accounted_bytes = envelope_reserve
        self._entity_count = 0
        self._relationship_count = 0
        self.limits: set[RetrievalLimit] = set()

    def try_add(
        self,
        *,
        entity_cost: int | None = None,
        relationship_cost: int | None = None,
    ) -> bool:
        additional_bytes = 0
        if entity_cost is not None:
            additional_bytes += entity_cost
            if self._entity_count:
                additional_bytes += 1
        if relationship_cost is not None:
            additional_bytes += relationship_cost
            if self._relationship_count:
                additional_bytes += 1

        next_bytes = self._accounted_bytes + additional_bytes
        next_tokens = _token_estimate(next_bytes)
        allowed = True
        if next_bytes > self._policy.max_plaintext_bytes:
            self.limits.add(RetrievalLimit.PLAINTEXT_BYTES)
            allowed = False
        if next_tokens > self._policy.max_token_estimate:
            self.limits.add(RetrievalLimit.TOKEN_ESTIMATE)
            allowed = False
        if allowed:
            self._accounted_bytes = next_bytes
            if entity_cost is not None:
                self._entity_count += 1
            if relationship_cost is not None:
                self._relationship_count += 1
        return allowed


@runtime_checkable
class LayeredGraphViewProvider(Protocol):
    """Minimal trusted graph-view boundary used by the retriever."""

    def get_public_view(self, graph_id: str) -> LayeredGraphView: ...

    def get_unlocked_view(
        self,
        graph_id: str,
        context: AccessContext,
    ) -> LayeredGraphView: ...


class SessionVisibleGraphGateway:
    """Retrieve a policy-filtered subgraph from one server-bound graph.

    ``context`` is an out-of-band capability supplied by the trusted tool
    executor, not a model argument. Without it, retrieval uses the public-only
    view. With it, the provider decides the cryptographic boundary: the legacy
    layered service decrypts a bounded full-vault snapshot, while the scoped
    adapter decrypts only the scopes granted to the session. This gateway then
    filters, ranks, and bounds either provider's returned view.
    """

    def __init__(
        self,
        layered: LayeredGraphViewProvider,
        *,
        graph_id: str,
        policy: DisclosurePolicy,
    ) -> None:
        if not isinstance(layered, LayeredGraphViewProvider):
            raise TypeError("layered must provide public and unlocked views.")
        _validate_text_identifier(
            graph_id,
            description="Invalid opaque public graph identifier.",
            maximum=_MAX_ID_CHARS,
        )
        if not isinstance(policy, DisclosurePolicy):
            raise TypeError("policy must be a DisclosurePolicy.")
        envelope_reserve = _maximum_envelope_size(graph_id, policy)
        if (
            envelope_reserve > policy.max_plaintext_bytes
            or _token_estimate(envelope_reserve) > policy.max_token_estimate
        ):
            raise ValidationError(
                "Retrieval output budgets cannot fit the canonical response "
                "envelope."
            )
        self._layered = layered
        self._graph_id = graph_id
        self._policy = policy
        self._envelope_reserve = envelope_reserve
        self._vector_binding = object()

    @property
    def graph_id(self) -> str:
        return self._graph_id

    @property
    def policy(self) -> DisclosurePolicy:
        return self._policy

    def build_vector_index(
        self,
        *,
        dimension: int,
        entity_embedder: Callable[[str], Sequence[float]],
        context: AccessContext | None = None,
        max_items: int = 1_000,
    ) -> EphemeralVectorIndex:
        """Build a sealed index from only this gateway's visible projection.

        The embedder receives canonical JSON containing an allowed entity's
        kind and policy-allowlisted properties. It never receives hidden
        properties, relationship data, scope IDs, or the entity ID. The
        returned index is accepted only by this gateway with the same bound
        context.
        """

        if context is not None and not isinstance(context, AccessContext):
            raise TypeError("context must be an AccessContext.")
        if not callable(entity_embedder):
            raise TypeError("entity_embedder must be callable.")
        index = EphemeralVectorIndex(
            dimension=dimension,
            max_items=max_items,
        )
        try:
            if context is None:
                view = self._layered.get_public_view(self._graph_id)
            else:
                view = self._layered.get_unlocked_view(
                    self._graph_id,
                    context,
                )
            entities, _ = self._project_view(view)
            if len(entities) > max_items:
                raise ValidationError(
                    "Visible entity count exceeds the vector index item limit."
                )
            for entity_id in sorted(entities):
                entity = entities[entity_id]
                document = _canonical_json_bytes(
                    {
                        "kind": entity.kind,
                        "properties": entity.properties,
                    }
                ).decode("utf-8")
                index.add(entity_id, entity_embedder(document))
            index._seal_for_gateway(self._vector_binding, context)
            return index
        except Exception:
            index.close()
            raise

    def _require_bound_vector_index(
        self,
        vector_index: EphemeralVectorIndex,
        context: AccessContext | None,
    ) -> None:
        if vector_index.closed:
            raise SessionUnavailable()
        if not vector_index._is_bound_to(self._vector_binding, context):
            raise ValidationError(
                "Vector index is not bound to this gateway and context."
            )

    @staticmethod
    def _kind_allowed(kind: str, allowed: frozenset[str]) -> bool:
        return _WILDCARD in allowed or kind in allowed

    @staticmethod
    def _copy_allowed_properties(
        kind: str,
        properties: Mapping[str, Any],
        rules: Mapping[str, frozenset[str]],
    ) -> dict[str, Any]:
        if not isinstance(properties, Mapping):
            raise IntegrityViolation()
        allowed = rules.get(kind)
        if allowed is None:
            allowed = rules.get(_WILDCARD, frozenset())
        try:
            if _WILDCARD in allowed:
                selected = dict(properties)
            else:
                selected = {
                    key: properties[key]
                    for key in sorted(properties)
                    if key in allowed
                }
            encoded = json.dumps(
                selected,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            return json.loads(encoded)
        except (
            TypeError,
            ValueError,
            RecursionError,
            UnicodeEncodeError,
        ):
            raise IntegrityViolation() from None

    def _project_view(
        self,
        view: LayeredGraphView,
    ) -> tuple[
        dict[str, _ProjectedEntity],
        dict[str, _ProjectedRelationship],
    ]:
        if not isinstance(view, LayeredGraphView) or view.graph_id != self._graph_id:
            raise IntegrityViolation()
        entities: dict[str, _ProjectedEntity] = {}
        for entity in view.entities:
            _validate_text_identifier(
                entity.entity_id,
                description="Invalid retrieved entity identifier.",
                maximum=_MAX_ID_CHARS,
            )
            _validate_text_identifier(
                entity.kind,
                description="Invalid retrieved entity kind.",
                maximum=_MAX_KIND_CHARS,
            )
            if not self._kind_allowed(
                entity.kind,
                self._policy.allowed_entity_kinds,
            ):
                continue
            if entity.entity_id in entities:
                raise IntegrityViolation()
            entities[entity.entity_id] = _ProjectedEntity(
                entity_id=entity.entity_id,
                kind=entity.kind,
                properties=self._copy_allowed_properties(
                    entity.kind,
                    entity.properties,
                    self._policy.entity_property_allowlist,
                ),
            )

        relationships: dict[str, _ProjectedRelationship] = {}
        for relationship in view.relationships:
            _validate_text_identifier(
                relationship.relationship_id,
                description="Invalid retrieved relationship identifier.",
                maximum=_MAX_ID_CHARS,
            )
            _validate_text_identifier(
                relationship.kind,
                description="Invalid retrieved relationship kind.",
                maximum=_MAX_KIND_CHARS,
            )
            if not self._kind_allowed(
                relationship.kind,
                self._policy.allowed_relationship_kinds,
            ):
                continue
            if (
                relationship.from_entity_id not in entities
                or relationship.to_entity_id not in entities
            ):
                # Relationships with a policy-hidden endpoint are invisible.
                continue
            if relationship.relationship_id in relationships:
                raise IntegrityViolation()
            relationships[relationship.relationship_id] = _ProjectedRelationship(
                relationship_id=relationship.relationship_id,
                from_entity_id=relationship.from_entity_id,
                to_entity_id=relationship.to_entity_id,
                kind=relationship.kind,
                properties=self._copy_allowed_properties(
                    relationship.kind,
                    relationship.properties,
                    self._policy.relationship_property_allowlist,
                ),
            )
        return entities, relationships

    @staticmethod
    def _tokens(value: str) -> Counter[str]:
        return Counter(_TOKEN_PATTERN.findall(value.casefold()))

    @classmethod
    def _lexical_scores(
        cls,
        query: str,
        entities: Mapping[str, _ProjectedEntity],
    ) -> dict[str, int]:
        query_tokens = cls._tokens(query)
        if not query_tokens:
            return {}
        scores: dict[str, int] = {}
        for entity_id, entity in entities.items():
            searchable = (
                entity.kind
                + " "
                + json.dumps(
                    entity.properties,
                    ensure_ascii=False,
                    allow_nan=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
            )
            document_tokens = cls._tokens(searchable)
            score = sum(
                min(query_count, document_tokens.get(token, 0))
                for token, query_count in query_tokens.items()
            )
            if score > 0:
                scores[entity_id] = score
        return scores

    @staticmethod
    def _entity_json(entity: RetrievedEntity) -> dict[str, Any]:
        return _retrieved_entity_json(entity)

    @staticmethod
    def _relationship_json(
        relationship: RetrievedRelationship,
    ) -> dict[str, Any]:
        return _retrieved_relationship_json(relationship)

    @staticmethod
    def _json_cost(value: Mapping[str, Any]) -> int:
        return len(_canonical_json_bytes(value))

    def _rank_seeds(
        self,
        query: str,
        entities: Mapping[str, _ProjectedEntity],
        *,
        vector_index: EphemeralVectorIndex | None,
        query_embedding: Sequence[float] | None,
        limits: set[RetrievalLimit],
    ) -> tuple[_Seed, ...]:
        lexical_scores = self._lexical_scores(query, entities)
        vector_scores: dict[str, float] = {}
        if vector_index is not None:
            assert query_embedding is not None
            matches = vector_index.search(
                query_embedding,
                top_k=max(1, vector_index.item_count),
            )
            vector_scores = {
                match.entity_id: match.score
                for match in matches
                if match.entity_id in entities
            }

        candidate_ids = set(lexical_scores) | set(vector_scores)
        if len(candidate_ids) > self._policy.max_candidates:
            limits.add(RetrievalLimit.CANDIDATES)
        maximum_lexical = max(lexical_scores.values(), default=0)
        seeds: list[_Seed] = []
        for entity_id in candidate_ids:
            lexical_score = lexical_scores.get(entity_id)
            vector_score = vector_scores.get(entity_id)
            lexical_component = (
                0.0
                if lexical_score is None or maximum_lexical == 0
                else lexical_score / maximum_lexical
            )
            vector_component = (
                0.0
                if vector_score is None
                else (vector_score + 1.0) / 2.0
            )
            sources: list[RetrievalSource] = []
            if lexical_score is not None:
                sources.append(RetrievalSource.LEXICAL)
            if vector_score is not None:
                sources.append(RetrievalSource.VECTOR)
            seeds.append(
                _Seed(
                    entity_id=entity_id,
                    sources=tuple(sources),
                    lexical_score=lexical_score,
                    vector_score=(
                        None
                        if vector_score is None
                        else round(vector_score, 12)
                    ),
                    combined_score=lexical_component + vector_component,
                    lexical_component=lexical_component,
                    vector_component=vector_component,
                )
            )
        seeds.sort(
            key=lambda seed: (
                -seed.combined_score,
                -seed.lexical_component,
                -seed.vector_component,
                seed.entity_id,
            )
        )
        return tuple(seeds[: self._policy.max_candidates])

    @staticmethod
    def _relationship_result(
        relationship: _ProjectedRelationship,
        *,
        hop: int,
        seed_entity_id: str,
    ) -> RetrievedRelationship:
        return RetrievedRelationship(
            relationship_id=relationship.relationship_id,
            from_entity_id=relationship.from_entity_id,
            to_entity_id=relationship.to_entity_id,
            kind=relationship.kind,
            properties=dict(relationship.properties),
            provenance=RetrievalProvenance(
                sources=(RetrievalSource.TRAVERSAL,),
                hop=hop,
                seed_entity_id=seed_entity_id,
                via_relationship_id=relationship.relationship_id,
            ),
        )

    def retrieve(
        self,
        query: str,
        *,
        context: AccessContext | None = None,
        vector_index: EphemeralVectorIndex | None = None,
        query_embedding: Sequence[float] | None = None,
    ) -> RetrievedSubgraph:
        """Return a deterministic, bounded public or session-unlocked subgraph.

        Query text is used only for in-process lexical ranking; it is never
        interpreted as Cypher.  ``vector_index`` and ``query_embedding`` are
        optional trusted-executor inputs and must be supplied together.
        """

        _validate_query(query)
        if (vector_index is None) != (query_embedding is None):
            raise ValidationError(
                "Vector retrieval requires both an index and query embedding."
            )
        if vector_index is not None and not isinstance(
            vector_index,
            EphemeralVectorIndex,
        ):
            raise TypeError("vector_index must be an EphemeralVectorIndex.")
        if vector_index is not None:
            # Fail before an unlocked view performs the current bounded
            # full-vault decryption path.
            self._require_bound_vector_index(vector_index, context)

        if context is None:
            view = self._layered.get_public_view(self._graph_id)
        else:
            view = self._layered.get_unlocked_view(self._graph_id, context)
        entities, relationships = self._project_view(view)

        budget = _Budget(
            self._policy,
            envelope_reserve=self._envelope_reserve,
        )
        seeds = self._rank_seeds(
            query,
            entities,
            vector_index=vector_index,
            query_embedding=query_embedding,
            limits=budget.limits,
        )

        selected_entities: dict[str, RetrievedEntity] = {}
        selected_relationships: dict[str, RetrievedRelationship] = {}
        queue: deque[str] = deque()

        for seed in seeds:
            if len(selected_entities) >= self._policy.max_nodes:
                budget.limits.add(RetrievalLimit.NODES)
                continue
            projected = entities[seed.entity_id]
            retrieved = RetrievedEntity(
                entity_id=projected.entity_id,
                kind=projected.kind,
                properties=dict(projected.properties),
                provenance=RetrievalProvenance(
                    sources=seed.sources,
                    hop=0,
                    seed_entity_id=seed.entity_id,
                    lexical_score=seed.lexical_score,
                    vector_score=seed.vector_score,
                ),
            )
            if not budget.try_add(
                entity_cost=self._json_cost(self._entity_json(retrieved))
            ):
                continue
            selected_entities[seed.entity_id] = retrieved
            queue.append(seed.entity_id)

        adjacency: dict[
            str,
            list[tuple[_ProjectedRelationship, str]],
        ] = {entity_id: [] for entity_id in entities}
        for relationship in relationships.values():
            adjacency[relationship.from_entity_id].append(
                (relationship, relationship.to_entity_id)
            )
            if relationship.to_entity_id != relationship.from_entity_id:
                adjacency[relationship.to_entity_id].append(
                    (relationship, relationship.from_entity_id)
                )
        for incident in adjacency.values():
            incident.sort(
                key=lambda item: (
                    item[0].relationship_id,
                    item[1],
                )
            )

        while queue:
            current_id = queue.popleft()
            current = selected_entities[current_id]
            current_hop = current.provenance.hop
            incident = adjacency.get(current_id, ())
            if current_hop >= self._policy.max_hops:
                if any(
                    relationship.relationship_id
                    not in selected_relationships
                    for relationship, _ in incident
                ):
                    budget.limits.add(RetrievalLimit.HOPS)
                continue

            for relationship, neighbor_id in incident:
                if relationship.relationship_id in selected_relationships:
                    continue
                next_hop = current_hop + 1
                neighbor = selected_entities.get(neighbor_id)
                retrieved_relationship = self._relationship_result(
                    relationship,
                    hop=next_hop,
                    seed_entity_id=current.provenance.seed_entity_id,
                )
                relationship_cost = self._json_cost(
                    self._relationship_json(retrieved_relationship)
                )

                if neighbor is None:
                    if len(selected_entities) >= self._policy.max_nodes:
                        budget.limits.add(RetrievalLimit.NODES)
                        continue
                    if len(selected_relationships) >= self._policy.max_edges:
                        budget.limits.add(RetrievalLimit.EDGES)
                        continue
                    projected_neighbor = entities[neighbor_id]
                    retrieved_neighbor = RetrievedEntity(
                        entity_id=projected_neighbor.entity_id,
                        kind=projected_neighbor.kind,
                        properties=dict(projected_neighbor.properties),
                        provenance=RetrievalProvenance(
                            sources=(RetrievalSource.TRAVERSAL,),
                            hop=next_hop,
                            seed_entity_id=current.provenance.seed_entity_id,
                            via_relationship_id=relationship.relationship_id,
                        ),
                    )
                    neighbor_cost = self._json_cost(
                        self._entity_json(retrieved_neighbor)
                    )
                    if not budget.try_add(
                        entity_cost=neighbor_cost,
                        relationship_cost=relationship_cost,
                    ):
                        continue
                    selected_relationships[
                        relationship.relationship_id
                    ] = retrieved_relationship
                    selected_entities[neighbor_id] = retrieved_neighbor
                    queue.append(neighbor_id)
                    continue

                if len(selected_relationships) >= self._policy.max_edges:
                    budget.limits.add(RetrievalLimit.EDGES)
                    continue
                if not budget.try_add(
                    relationship_cost=relationship_cost
                ):
                    continue
                selected_relationships[
                    relationship.relationship_id
                ] = retrieved_relationship

        ordered_limits = tuple(
            limit
            for limit in RetrievalLimit
            if limit in budget.limits
        )
        result = _finalize_subgraph(
            graph_id=self._graph_id,
            entities=tuple(selected_entities.values()),
            relationships=tuple(selected_relationships.values()),
            limits_reached=ordered_limits,
        )
        if (
            result.plaintext_bytes > self._policy.max_plaintext_bytes
            or result.token_estimate > self._policy.max_token_estimate
        ):
            raise IntegrityViolation()
        return result


class SessionBoundRetrievalTool:
    """Question-only model tool with all authority bound by a trusted host.

    The host may bind a secure ``context`` and an optional per-session vector
    index plus query embedder when constructing this wrapper. The model-facing
    :meth:`search` method accepts only question text, so a model cannot select
    a principal, vault, scope, session token, Cypher statement, or limit.

    Vector-index lifecycle remains caller-owned. The trusted host must create
    it with :meth:`SessionVisibleGraphGateway.build_vector_index`, keep it
    session-local, and close it when that secure session locks or expires.
    """

    def __init__(
        self,
        gateway: SessionVisibleGraphGateway,
        *,
        context: AccessContext | None = None,
        vector_index: EphemeralVectorIndex | None = None,
        query_embedder: Callable[[str], Sequence[float]] | None = None,
    ) -> None:
        if not isinstance(gateway, SessionVisibleGraphGateway):
            raise TypeError("gateway must be a SessionVisibleGraphGateway.")
        if context is not None and not isinstance(context, AccessContext):
            raise TypeError("context must be an AccessContext.")
        if (vector_index is None) != (query_embedder is None):
            raise ValidationError(
                "Vector retrieval requires both an index and query embedder."
            )
        if vector_index is not None and not isinstance(
            vector_index,
            EphemeralVectorIndex,
        ):
            raise TypeError("vector_index must be an EphemeralVectorIndex.")
        if query_embedder is not None and not callable(query_embedder):
            raise TypeError("query_embedder must be callable.")
        if vector_index is not None:
            gateway._require_bound_vector_index(vector_index, context)
        self._gateway = gateway
        self._context = context
        self._vector_index = vector_index
        self._query_embedder = query_embedder

    def search(self, question: str) -> RetrievedSubgraph:
        """Retrieve the session-visible subgraph relevant to ``question``."""

        _validate_query(question)
        if self._vector_index is None:
            return self._gateway.retrieve(
                question,
                context=self._context,
            )
        assert self._query_embedder is not None
        query_embedding = self._query_embedder(question)
        return self._gateway.retrieve(
            question,
            context=self._context,
            vector_index=self._vector_index,
            query_embedding=query_embedding,
        )
