"""Fixed-query Neo4j adapter for the intentionally public graph layer."""

from __future__ import annotations

import json
from typing import Any, Iterable, Mapping

from .errors import IntegrityViolation, ValidationError
from .models import (
    PublicEntityRow,
    PublicGraphSnapshotRow,
    PublicRelationshipRow,
)

try:
    from neo4j.exceptions import IncompleteCommit
except ImportError:  # Unit tests do not require the runtime driver.
    class IncompleteCommit(Exception):
        """Fallback type used only when the Neo4j driver is not installed."""


MAX_PUBLIC_JSON_BYTES = 64 * 1024


class Neo4jPublicGraphRepository:
    """Neo4j storage for data explicitly classified as application-public.

    "Public" means plaintext at AuthGraph's application-encryption layer. The
    Neo4j connection must still use TLS and the database must still enforce
    authentication, authorization, backups, and operational encryption.
    """

    _PUT_PUBLIC_ENTITY = """
    MERGE (graph:AGPublicGraph {graph_id: $graph_id})
    SET graph._authgraph_lock = true
    REMOVE graph._authgraph_lock
    WITH graph
    WHERE NOT EXISTS {
        MATCH (:AGPublicEntity {entity_id: $entity_id})
    }
    CREATE (entity:AGPublicEntity {
        graph_id: $graph_id,
        entity_id: $entity_id,
        kind: $kind,
        properties_json: $properties_json
    })
    CREATE (graph)-[:AG_PUBLIC_OWNS]->(entity)
    RETURN count(entity) AS created
    """

    _GET_PUBLIC_ENTITY = """
    MATCH (graph:AGPublicGraph {
        graph_id: $graph_id
    })-[:AG_PUBLIC_OWNS]->(entity:AGPublicEntity {
        graph_id: $graph_id,
        entity_id: $entity_id
    })
    RETURN
        entity.kind AS kind,
        entity.properties_json AS properties_json
    LIMIT 1
    """

    _PUT_PUBLIC_RELATIONSHIP = """
    MATCH (graph:AGPublicGraph {graph_id: $graph_id})
    SET graph._authgraph_lock = true
    REMOVE graph._authgraph_lock
    WITH graph
    MATCH (graph)-[:AG_PUBLIC_OWNS]->(source:AGPublicEntity {
        graph_id: $graph_id,
        entity_id: $from_entity_id
    })
    MATCH (graph)-[:AG_PUBLIC_OWNS]->(target:AGPublicEntity {
        graph_id: $graph_id,
        entity_id: $to_entity_id
    })
    WHERE NOT EXISTS {
        MATCH ()-[existing:AG_PUBLIC_LINK {
            relationship_id: $relationship_id
        }]->()
    }
    CREATE (source)-[link:AG_PUBLIC_LINK {
        graph_id: $graph_id,
        relationship_id: $relationship_id,
        kind: $kind,
        properties_json: $properties_json
    }]->(target)
    RETURN count(link) AS created
    """

    _GET_PUBLIC_RELATIONSHIP = """
    MATCH (graph:AGPublicGraph {
        graph_id: $graph_id
    })-[:AG_PUBLIC_OWNS]->(source:AGPublicEntity {
        graph_id: $graph_id,
        entity_id: $from_entity_id
    })
    MATCH (graph)-[:AG_PUBLIC_OWNS]->(target:AGPublicEntity {
        graph_id: $graph_id,
        entity_id: $to_entity_id
    })
    MATCH (source)-[link:AG_PUBLIC_LINK {
        graph_id: $graph_id,
        relationship_id: $relationship_id
    }]->(target)
    RETURN
        link.kind AS kind,
        link.properties_json AS properties_json
    LIMIT 1
    """

    _GET_PUBLIC_GRAPH_SNAPSHOT = """
    MATCH (graph:AGPublicGraph {graph_id: $graph_id})
    SET graph._authgraph_lock = true
    REMOVE graph._authgraph_lock
    WITH graph
    RETURN
        COLLECT {
            MATCH (graph)-[:AG_PUBLIC_OWNS]->(entity:AGPublicEntity {
                graph_id: $graph_id
            })
            WITH entity
            ORDER BY entity.entity_id
            LIMIT $entity_fetch_limit
            RETURN {
                entity_id: entity.entity_id,
                kind: entity.kind,
                properties_json: entity.properties_json
            } AS entity_row
        } AS entities,
        COLLECT {
            MATCH (graph)-[:AG_PUBLIC_OWNS]->(source:AGPublicEntity {
                graph_id: $graph_id
            })-[link:AG_PUBLIC_LINK {
                graph_id: $graph_id
            }]->(target:AGPublicEntity {
                graph_id: $graph_id
            })
            WHERE EXISTS {
                MATCH (graph)-[:AG_PUBLIC_OWNS]->(target)
            }
            WITH source, link, target
            ORDER BY link.relationship_id
            LIMIT $relationship_fetch_limit
            RETURN {
                relationship_id: link.relationship_id,
                from_entity_id: source.entity_id,
                to_entity_id: target.entity_id,
                kind: link.kind,
                properties_json: link.properties_json
            } AS relationship_row
        } AS relationships
    """

    def __init__(self, driver: Any, *, database: str) -> None:
        if not database:
            raise ValueError("An explicit Neo4j database name is required.")
        if getattr(driver, "encrypted", None) is not True:
            raise ValueError(
                "AuthGraph requires a Neo4j driver with encrypted transport."
            )
        self._driver = driver
        self._database = database

    def _execute(self, query: str, **parameters: object) -> list[Any]:
        result = self._driver.execute_query(
            query,
            parameters_=parameters,
            database_=self._database,
        )
        records = getattr(result, "records", None)
        if records is not None:
            return list(records)
        return list(result[0])

    @staticmethod
    def _first(records: Iterable[Any]) -> Any | None:
        return next(iter(records), None)

    @staticmethod
    def _record_value(record: Any, name: str) -> object:
        try:
            return record[name]
        except (KeyError, TypeError, IndexError):
            raise IntegrityViolation() from None

    @classmethod
    def _record_text(cls, record: Any, name: str) -> str:
        value = cls._record_value(record, name)
        if not isinstance(value, str):
            raise IntegrityViolation()
        return value

    @classmethod
    def _record_integer(cls, record: Any, name: str) -> int:
        value = cls._record_value(record, name)
        if type(value) is not int:
            raise IntegrityViolation()
        return value

    @classmethod
    def _record_list(cls, record: Any, name: str) -> list[Any]:
        value = cls._record_value(record, name)
        if not isinstance(value, list):
            raise IntegrityViolation()
        return value

    @staticmethod
    def _encode_properties(properties: Mapping[str, Any]) -> str:
        try:
            encoded = json.dumps(
                properties,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValidationError(
                "Public properties must be a valid JSON object."
            ) from exc
        try:
            encoded_size = len(encoded.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValidationError(
                "Public properties must be valid UTF-8 JSON."
            ) from exc
        if encoded_size > MAX_PUBLIC_JSON_BYTES:
            raise ValidationError(
                f"Public properties may contain at most "
                f"{MAX_PUBLIC_JSON_BYTES} bytes."
            )
        return encoded

    @staticmethod
    def _decode_properties(encoded: str) -> dict[str, Any]:
        if not isinstance(encoded, str):
            raise IntegrityViolation()
        try:
            encoded_size = len(encoded.encode("utf-8"))
        except UnicodeEncodeError:
            raise IntegrityViolation() from None
        if encoded_size > MAX_PUBLIC_JSON_BYTES:
            raise IntegrityViolation()
        try:
            decoded = json.loads(encoded)
        except (json.JSONDecodeError, RecursionError):
            raise IntegrityViolation() from None
        if not isinstance(decoded, dict):
            raise IntegrityViolation()
        return decoded

    @classmethod
    def _entity_from_record(
        cls,
        graph_id: str,
        entity_id: str,
        record: Any,
    ) -> PublicEntityRow:
        return PublicEntityRow(
            graph_id=graph_id,
            entity_id=entity_id,
            kind=cls._record_text(record, "kind"),
            properties=cls._decode_properties(
                cls._record_text(record, "properties_json")
            ),
        )

    def put_public_entity(self, row: PublicEntityRow) -> bool:
        parameters = {
            "graph_id": row.graph_id,
            "entity_id": row.entity_id,
            "kind": row.kind,
            "properties_json": self._encode_properties(row.properties),
        }
        try:
            first = self._first(
                self._execute(self._PUT_PUBLIC_ENTITY, **parameters)
            )
        except IncompleteCommit:
            if self.get_public_entity(row.graph_id, row.entity_id) == row:
                return True
            raise
        if first is not None and self._record_integer(first, "created") == 1:
            return True
        return self.get_public_entity(row.graph_id, row.entity_id) == row

    def get_public_entity(
        self,
        graph_id: str,
        entity_id: str,
    ) -> PublicEntityRow | None:
        first = self._first(
            self._execute(
                self._GET_PUBLIC_ENTITY,
                graph_id=graph_id,
                entity_id=entity_id,
            )
        )
        if first is None:
            return None
        return self._entity_from_record(graph_id, entity_id, first)

    @classmethod
    def _relationship_from_record(
        cls,
        graph_id: str,
        relationship_id: str,
        from_entity_id: str,
        to_entity_id: str,
        record: Any,
    ) -> PublicRelationshipRow:
        return PublicRelationshipRow(
            graph_id=graph_id,
            relationship_id=relationship_id,
            from_entity_id=from_entity_id,
            to_entity_id=to_entity_id,
            kind=cls._record_text(record, "kind"),
            properties=cls._decode_properties(
                cls._record_text(record, "properties_json")
            ),
        )

    def put_public_relationship(self, row: PublicRelationshipRow) -> bool:
        parameters = {
            "graph_id": row.graph_id,
            "relationship_id": row.relationship_id,
            "from_entity_id": row.from_entity_id,
            "to_entity_id": row.to_entity_id,
            "kind": row.kind,
            "properties_json": self._encode_properties(row.properties),
        }
        try:
            first = self._first(
                self._execute(self._PUT_PUBLIC_RELATIONSHIP, **parameters)
            )
        except IncompleteCommit:
            if self._get_public_relationship(row) == row:
                return True
            raise
        if first is not None and self._record_integer(first, "created") == 1:
            return True
        return self._get_public_relationship(row) == row

    def _get_public_relationship(
        self,
        row: PublicRelationshipRow,
    ) -> PublicRelationshipRow | None:
        first = self._first(
            self._execute(
                self._GET_PUBLIC_RELATIONSHIP,
                graph_id=row.graph_id,
                relationship_id=row.relationship_id,
                from_entity_id=row.from_entity_id,
                to_entity_id=row.to_entity_id,
            )
        )
        if first is None:
            return None
        return self._relationship_from_record(
            row.graph_id,
            row.relationship_id,
            row.from_entity_id,
            row.to_entity_id,
            first,
        )

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
        first = self._first(
            self._execute(
                self._GET_PUBLIC_GRAPH_SNAPSHOT,
                graph_id=graph_id,
                entity_fetch_limit=entity_limit + 1,
                relationship_fetch_limit=relationship_limit + 1,
            )
        )
        if first is None:
            return PublicGraphSnapshotRow(entities=(), relationships=())
        entities = tuple(
            self._entity_from_record(
                graph_id,
                self._record_text(record, "entity_id"),
                record,
            )
            for record in self._record_list(first, "entities")
        )
        relationships = tuple(
            self._relationship_from_record(
                graph_id,
                self._record_text(record, "relationship_id"),
                self._record_text(record, "from_entity_id"),
                self._record_text(record, "to_entity_id"),
                record,
            )
            for record in self._record_list(first, "relationships")
        )
        return PublicGraphSnapshotRow(
            entities=entities,
            relationships=relationships,
        )
