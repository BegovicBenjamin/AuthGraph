"""Adapter from scoped-vault snapshots to the bounded GraphRAG gateway."""

from __future__ import annotations

from .errors import IntegrityViolation, ValidationError
from .models import (
    AccessContext,
    LayeredEntity,
    LayeredGraphView,
    LayeredRelationship,
    LockedDisclosure,
    ProtectionLevel,
)
from .retrieval import LayeredGraphViewProvider
from .scoped_service import ScopedAuthGraphService


def _is_valid_record_id(value: object) -> bool:
    return isinstance(value, str) and bool(value) and len(value) <= 256


class ScopedGraphViewAdapter:
    """Treat one granted scoped-vault snapshot as one logical private graph.

    Scope IDs remain inside the trusted scoped service and are deliberately not
    copied into the returned graph view. An optional provider may contribute a
    normal public base graph.
    """

    def __init__(
        self,
        protected: ScopedAuthGraphService,
        *,
        graph_id: str,
        public_provider: LayeredGraphViewProvider | None = None,
    ) -> None:
        if not isinstance(protected, ScopedAuthGraphService):
            raise TypeError("protected must be a ScopedAuthGraphService.")
        if not isinstance(graph_id, str) or not graph_id or len(graph_id) > 256:
            raise ValidationError("Invalid opaque graph identifier.")
        if (
            public_provider is not None
            and not isinstance(public_provider, LayeredGraphViewProvider)
        ):
            raise TypeError("public_provider must expose layered graph views.")
        self._protected = protected
        self._graph_id = graph_id
        self._public_provider = public_provider

    def _require_graph(self, graph_id: str) -> None:
        if graph_id != self._graph_id:
            raise ValidationError("Invalid opaque graph identifier.")

    def get_public_view(self, graph_id: str) -> LayeredGraphView:
        self._require_graph(graph_id)
        if self._public_provider is None:
            return LayeredGraphView(
                graph_id=graph_id,
                entities=(),
                relationships=(),
                private_overlay_included=False,
                locked_disclosure=LockedDisclosure.HIDDEN,
            )
        view = self._public_provider.get_public_view(graph_id)
        if not isinstance(view, LayeredGraphView) or view.graph_id != graph_id:
            raise IntegrityViolation()
        if (
            view.private_overlay_included is not False
            or type(view.locked_disclosure) is not LockedDisclosure
        ):
            raise IntegrityViolation()

        entity_ids: set[str] = set()
        for entity in view.entities:
            if (
                not isinstance(entity, LayeredEntity)
                or entity.protection is not ProtectionLevel.PUBLIC
                or not _is_valid_record_id(entity.entity_id)
                or entity.entity_id in entity_ids
            ):
                raise IntegrityViolation()
            entity_ids.add(entity.entity_id)

        relationship_ids: set[str] = set()
        for relationship in view.relationships:
            if (
                not isinstance(relationship, LayeredRelationship)
                or relationship.protection is not ProtectionLevel.PUBLIC
                or not _is_valid_record_id(relationship.relationship_id)
                or not _is_valid_record_id(relationship.from_entity_id)
                or not _is_valid_record_id(relationship.to_entity_id)
                or relationship.relationship_id in relationship_ids
                or relationship.from_entity_id not in entity_ids
                or relationship.to_entity_id not in entity_ids
            ):
                raise IntegrityViolation()
            relationship_ids.add(relationship.relationship_id)
        return view

    def get_unlocked_view(
        self,
        graph_id: str,
        context: AccessContext,
    ) -> LayeredGraphView:
        self._require_graph(graph_id)
        public = self.get_public_view(graph_id)
        snapshot = self._protected.get_vault_snapshot(context)
        entities = {entity.entity_id: entity for entity in public.entities}
        for entity in snapshot.entities:
            if entity.entity_id in entities:
                raise IntegrityViolation()
            entities[entity.entity_id] = LayeredEntity(
                entity_id=entity.entity_id,
                kind=entity.kind,
                properties=dict(entity.properties),
                protection=ProtectionLevel.PRIVATE,
            )

        relationships = {
            relationship.relationship_id: relationship
            for relationship in public.relationships
        }
        for relationship in snapshot.relationships:
            if (
                relationship.relationship_id in relationships
                or relationship.from_entity_id not in entities
                or relationship.to_entity_id not in entities
            ):
                raise IntegrityViolation()
            relationships[relationship.relationship_id] = LayeredRelationship(
                relationship_id=relationship.relationship_id,
                from_entity_id=relationship.from_entity_id,
                to_entity_id=relationship.to_entity_id,
                kind=relationship.kind,
                properties=dict(relationship.properties),
                protection=ProtectionLevel.PRIVATE,
            )
        return LayeredGraphView(
            graph_id=graph_id,
            entities=tuple(
                sorted(
                    entities.values(),
                    key=lambda entity: entity.entity_id,
                )
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

    def get_targeted_unlocked_view(
        self,
        graph_id: str,
        context: AccessContext,
        *,
        entity_ids: tuple[str, ...],
        relationship_ids: tuple[str, ...],
    ) -> LayeredGraphView:
        """Compose only selected public rows and current scoped ciphertext."""

        self._require_graph(graph_id)
        snapshot = self._protected.get_targeted_snapshot(
            context,
            entity_ids,
            relationship_ids,
        )
        # The secure read above intentionally happens before public work, so a
        # locked or expired capability cannot become a public-only fallback.
        public = self.get_public_view(graph_id)
        requested_entities = frozenset(entity_ids)
        requested_relationships = frozenset(relationship_ids)
        selected_public_relationships = {
            relationship.relationship_id: relationship
            for relationship in public.relationships
            if relationship.relationship_id in requested_relationships
        }
        public_endpoint_ids = {
            endpoint_id
            for relationship in selected_public_relationships.values()
            for endpoint_id in (
                relationship.from_entity_id,
                relationship.to_entity_id,
            )
        }
        selected_public_entity_ids = requested_entities | public_endpoint_ids
        entities = {
            entity.entity_id: entity
            for entity in public.entities
            if entity.entity_id in selected_public_entity_ids
        }
        for entity in snapshot.entities:
            if entity.entity_id in entities:
                raise IntegrityViolation()
            entities[entity.entity_id] = LayeredEntity(
                entity_id=entity.entity_id,
                kind=entity.kind,
                properties=dict(entity.properties),
                protection=ProtectionLevel.PRIVATE,
            )

        relationships = dict(selected_public_relationships)
        for relationship in snapshot.relationships:
            if (
                relationship.relationship_id in relationships
                or relationship.from_entity_id not in entities
                or relationship.to_entity_id not in entities
            ):
                raise IntegrityViolation()
            relationships[relationship.relationship_id] = LayeredRelationship(
                relationship_id=relationship.relationship_id,
                from_entity_id=relationship.from_entity_id,
                to_entity_id=relationship.to_entity_id,
                kind=relationship.kind,
                properties=dict(relationship.properties),
                protection=ProtectionLevel.PRIVATE,
            )
        return LayeredGraphView(
            graph_id=graph_id,
            entities=tuple(
                sorted(
                    entities.values(),
                    key=lambda entity: entity.entity_id,
                )
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
