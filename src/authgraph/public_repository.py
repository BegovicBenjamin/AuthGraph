"""Storage boundary for AuthGraph's intentionally public base graph."""

from __future__ import annotations

from typing import Protocol

from .models import (
    PublicEntityRow,
    PublicGraphSnapshotRow,
    PublicRelationshipRow,
)


class PublicGraphRepository(Protocol):
    """Only fixed, graph-scoped public operations are exposed."""

    def put_public_entity(self, row: PublicEntityRow) -> bool: ...

    def get_public_entity(
        self,
        graph_id: str,
        entity_id: str,
    ) -> PublicEntityRow | None: ...

    def replace_public_entity(
        self,
        graph_id: str,
        entity_id: str,
        expected_revision: int,
        row: PublicEntityRow,
    ) -> bool: ...

    def delete_public_entity(
        self,
        graph_id: str,
        entity_id: str,
        expected_revision: int,
    ) -> bool:
        """Delete only when the revision matches and no public edge exists."""

        ...

    def put_public_relationship(self, row: PublicRelationshipRow) -> bool: ...

    def get_public_relationship(
        self,
        graph_id: str,
        relationship_id: str,
    ) -> PublicRelationshipRow | None: ...

    def replace_public_relationship(
        self,
        graph_id: str,
        relationship_id: str,
        expected_revision: int,
        row: PublicRelationshipRow,
    ) -> bool: ...

    def delete_public_relationship(
        self,
        graph_id: str,
        relationship_id: str,
        expected_revision: int,
    ) -> bool: ...

    def get_public_graph_snapshot(
        self,
        graph_id: str,
        *,
        entity_limit: int,
        relationship_limit: int,
    ) -> PublicGraphSnapshotRow:
        """Fetch at most each limit plus one row to detect truncation."""

        ...
