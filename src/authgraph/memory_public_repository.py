"""Thread-safe public graph repository for tests and local development."""

from __future__ import annotations

import copy
import threading
from dataclasses import replace

from .models import (
    PublicEntityRow,
    PublicGraphSnapshotRow,
    PublicRelationshipRow,
)


class InMemoryPublicGraphRepository:
    """Stores only records explicitly classified as public."""

    def __init__(self) -> None:
        self._entities: dict[tuple[str, str], PublicEntityRow] = {}
        self._relationships: dict[
            tuple[str, str], PublicRelationshipRow
        ] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _copy_entity(row: PublicEntityRow) -> PublicEntityRow:
        return replace(row, properties=copy.deepcopy(dict(row.properties)))

    @staticmethod
    def _copy_relationship(
        row: PublicRelationshipRow,
    ) -> PublicRelationshipRow:
        return replace(row, properties=copy.deepcopy(dict(row.properties)))

    def put_public_entity(self, row: PublicEntityRow) -> bool:
        with self._lock:
            key = (row.graph_id, row.entity_id)
            if key in self._entities or any(
                entity_id == row.entity_id
                for _, entity_id in self._entities
            ):
                return False
            self._entities[key] = self._copy_entity(row)
            return True

    def get_public_entity(
        self,
        graph_id: str,
        entity_id: str,
    ) -> PublicEntityRow | None:
        with self._lock:
            row = self._entities.get((graph_id, entity_id))
            return None if row is None else self._copy_entity(row)

    def put_public_relationship(self, row: PublicRelationshipRow) -> bool:
        with self._lock:
            key = (row.graph_id, row.relationship_id)
            endpoints_exist = (
                (row.graph_id, row.from_entity_id) in self._entities
                and (row.graph_id, row.to_entity_id) in self._entities
            )
            if (
                key in self._relationships
                or any(
                    relationship_id == row.relationship_id
                    for _, relationship_id in self._relationships
                )
                or not endpoints_exist
            ):
                return False
            self._relationships[key] = self._copy_relationship(row)
            return True

    def get_public_graph_snapshot(
        self,
        graph_id: str,
        *,
        entity_limit: int,
        relationship_limit: int,
    ) -> PublicGraphSnapshotRow:
        if (
            type(entity_limit) is not int
            or entity_limit <= 0
            or type(relationship_limit) is not int
            or relationship_limit <= 0
        ):
            raise ValueError("Public snapshot limits must be positive integers.")
        with self._lock:
            entities = tuple(
                self._copy_entity(row)
                for (row_graph, _), row in sorted(self._entities.items())
                if row_graph == graph_id
            )[: entity_limit + 1]
            relationships = tuple(
                self._copy_relationship(row)
                for (row_graph, _), row in sorted(
                    self._relationships.items()
                )
                if row_graph == graph_id
            )[: relationship_limit + 1]
            return PublicGraphSnapshotRow(
                entities=entities,
                relationships=relationships,
            )

    def plaintext_snapshot(self) -> PublicGraphSnapshotRow:
        """Return all public records for explicit storage-shape assertions."""

        with self._lock:
            return PublicGraphSnapshotRow(
                entities=tuple(
                    self._copy_entity(row)
                    for _, row in sorted(self._entities.items())
                ),
                relationships=tuple(
                    self._copy_relationship(row)
                    for _, row in sorted(self._relationships.items())
                ),
            )
