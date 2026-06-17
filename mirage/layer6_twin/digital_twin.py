"""Digital Twin V1 service for event-driven MIRAGE topology state."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Iterable

from mirage.domain.schemas import (
    Asset,
    Identity,
    Relationship,
    SecurityEvent,
    TwinSnapshot,
    TwinUpdateResult,
    TwinUpdateSummary,
    utc_now,
)
from mirage.layer6_twin.entity_resolution import EntityResolver

LOGGER = logging.getLogger(__name__)


DEFAULT_RELATIONSHIP_TTLS = {
    "connects_to": 3600,
    "authenticated_to": 86400,
    "auth_failed_to": 3600,
    "uses_credential_on": 86400,
    "accessed_file_on": 3600,
    "ran_process_on": 3600,
    "has_vulnerability": 604800,
    "interacted_with_decoy": 604800,
    "resolved_dns_to": 3600,
}


class DigitalTwin:
    """In-memory event-driven asset, identity, and relationship registry."""

    def __init__(
        self,
        *,
        relationship_ttls: dict[str, int] | None = None,
        allow_provisional_entities: bool = True,
    ) -> None:
        self.assets: dict[str, Asset] = {}
        self.identities: dict[str, Identity] = {}
        self.relationships: dict[str, Relationship] = {}
        self.version = 0
        self.processed_event_ids: set[str] = set()
        self.warnings: list[str] = []
        self.source_position: str | None = None
        self.last_event_time: datetime | None = None
        self.relationship_ttls = {
            **DEFAULT_RELATIONSHIP_TTLS,
            **(relationship_ttls or {}),
        }
        self.resolver = EntityResolver(
            allow_provisional=allow_provisional_entities
        )

    def apply_event(self, event: SecurityEvent) -> TwinUpdateResult:
        """Apply one canonical event to the twin state."""
        if event.event_id in self.processed_event_ids:
            result = TwinUpdateResult(
                event_id=event.event_id,
                event_type=event.event_type,
                duplicate=True,
                warnings=[f"Duplicate event ignored: {event.event_id}"],
                twin_version=self.version,
            )
            self._log_event(event, result)
            return result

        expired = self.expire_relationships(event.event_time)
        result = TwinUpdateResult(
            event_id=event.event_id,
            event_type=event.event_type,
            expired_relationships=expired,
            twin_version=self.version + 1,
        )

        src_asset_id = None
        dst_asset_id = None
        if event.event_type in {
            "network_connection",
            "dns_query",
            "credential_use",
            "deception_interaction",
        }:
            src_asset_id = self._resolve_asset(event, "source", result)
        if event.event_type in {"network_connection", "dns_query"}:
            dst_asset_id = self._resolve_asset(event, "destination", result)

        main_asset_id = None
        if event.asset_id or event.event_type not in {
            "network_connection",
            "dns_query",
        }:
            main_asset_id = self._resolve_asset(event, "asset", result)
        if (
            main_asset_id is None
            and event.dst_ip
            and event.event_type in {
                "authentication_success",
                "authentication_failure",
                "credential_use",
                "deception_interaction",
            }
        ):
            main_asset_id = self._resolve_asset(event, "destination", result)
        main_asset_id = main_asset_id or dst_asset_id
        identity_id = self._resolve_identity(event, result)
        if identity_id and main_asset_id:
            identity = self.identities[identity_id]
            if main_asset_id not in identity.associated_assets:
                identity.associated_assets.append(main_asset_id)

        self._apply_relationships(
            event,
            result,
            src_asset_id=src_asset_id,
            dst_asset_id=dst_asset_id,
            main_asset_id=main_asset_id,
            identity_id=identity_id,
        )

        self.processed_event_ids.add(event.event_id)
        self.version += 1
        self.last_event_time = max(
            self.last_event_time or event.event_time,
            event.event_time,
        )
        result.twin_version = self.version
        self.warnings.extend(result.warnings)
        self._log_event(event, result)
        return result

    def apply_events(
        self,
        events: Iterable[SecurityEvent],
    ) -> TwinUpdateSummary:
        """Apply a deterministic iterable of canonical events."""
        summary = TwinUpdateSummary(final_twin_version=self.version)
        for event in events:
            result = self.apply_event(event)
            summary.processed += 1
            summary.duplicates += int(result.duplicate)
            summary.assets_created += len(result.assets_created)
            summary.assets_updated += len(result.assets_updated)
            summary.identities_created += len(result.identities_created)
            summary.identities_updated += len(result.identities_updated)
            summary.relationships_created += len(result.relationships_created)
            summary.relationships_updated += len(result.relationships_updated)
            summary.expired_relationships += len(result.expired_relationships)
            summary.warnings.extend(result.warnings)
            summary.final_twin_version = self.version
        return summary

    def create_snapshot(self) -> TwinSnapshot:
        """Create a deterministic JSON-serializable snapshot."""
        timestamp = self.last_event_time or utc_now()
        return TwinSnapshot(
            twin_version=self.version,
            timestamp=timestamp,
            assets={key: self.assets[key] for key in sorted(self.assets)},
            identities={
                key: self.identities[key] for key in sorted(self.identities)
            },
            relationships={
                key: self.relationships[key]
                for key in sorted(self.relationships)
            },
            graph_metadata=self.health(),
            source_position=self.source_position,
            coverage_score=self.coverage_score(),
            freshness_score=self.freshness_score(timestamp),
            warnings=sorted(set(self.warnings)),
        )

    def load_snapshot(self, snapshot: TwinSnapshot) -> None:
        """Replace current twin state with a snapshot."""
        self.version = snapshot.twin_version
        self.assets = dict(snapshot.assets)
        self.identities = dict(snapshot.identities)
        self.relationships = dict(snapshot.relationships)
        event_ids: set[str] = set()
        for relationship in self.relationships.values():
            event_ids.update(relationship.source_event_ids)
        self.processed_event_ids = event_ids
        self.source_position = snapshot.source_position
        self.warnings = list(snapshot.warnings)
        self.last_event_time = snapshot.timestamp

    def get_asset(self, asset_id: str) -> Asset | None:
        """Return one asset by canonical ID."""
        return self.assets.get(asset_id)

    def get_identity(self, identity_id: str) -> Identity | None:
        """Return one identity by canonical ID."""
        return self.identities.get(identity_id)

    def get_subgraph(
        self,
        entity_ids: list[str],
        hops: int = 2,
    ) -> dict[str, object]:
        """Return a small relationship neighborhood around entity IDs."""
        frontier = set(entity_ids)
        visited = set(frontier)
        active_relationships = self.active_relationships()
        for _ in range(max(0, hops)):
            next_frontier: set[str] = set()
            for relationship in active_relationships.values():
                if (
                    relationship.source_entity_id in frontier
                    or relationship.target_entity_id in frontier
                ):
                    next_frontier.add(relationship.source_entity_id)
                    next_frontier.add(relationship.target_entity_id)
            next_frontier -= visited
            visited |= next_frontier
            frontier = next_frontier
            if not frontier:
                break
        return {
            "entities": sorted(visited),
            "assets": {
                key: self.assets[key]
                for key in sorted(visited.intersection(self.assets))
            },
            "identities": {
                key: self.identities[key]
                for key in sorted(visited.intersection(self.identities))
            },
            "relationships": [
                relationship
                for relationship in active_relationships.values()
                if relationship.source_entity_id in visited
                and relationship.target_entity_id in visited
            ],
        }

    def active_relationships(
        self,
        *,
        at_time: datetime | None = None,
    ) -> dict[str, Relationship]:
        """Return relationships that are active and not expired."""
        now = at_time or self.last_event_time or utc_now()
        return {
            rel_id: relationship
            for rel_id, relationship in self.relationships.items()
            if relationship.active
            and (
                relationship.expiry_time is None
                or relationship.expiry_time > now
            )
        }

    def expire_relationships(self, at_time: datetime | None = None) -> list[str]:
        """Mark expired relationships inactive."""
        now = at_time or utc_now()
        expired: list[str] = []
        for rel_id, relationship in self.relationships.items():
            if (
                relationship.active
                and relationship.expiry_time is not None
                and relationship.expiry_time <= now
            ):
                relationship.active = False
                expired.append(rel_id)
        return sorted(expired)

    def export_attack_graph(self):
        """Export active twin state to the current MIRAGEAttackGraph type."""
        from mirage.layer6_twin.graph_adapter import attack_graph_from_twin_snapshot

        return attack_graph_from_twin_snapshot(self.create_snapshot())

    def health(self) -> dict[str, object]:
        """Return health and metadata for API status checks."""
        active_relationship_count = len(self.active_relationships())
        return {
            "version": self.version,
            "asset_count": len(self.assets),
            "identity_count": len(self.identities),
            "relationship_count": len(self.relationships),
            "active_relationship_count": active_relationship_count,
            "processed_event_count": len(self.processed_event_ids),
            "last_event_time": (
                self.last_event_time.isoformat()
                if self.last_event_time
                else None
            ),
        }

    def coverage_score(self) -> float:
        """Estimate registry coverage from relationship-connected assets."""
        if not self.assets:
            return 0.0
        connected = set()
        for relationship in self.active_relationships().values():
            for entity_id in (
                relationship.source_entity_id,
                relationship.target_entity_id,
            ):
                if entity_id in self.assets:
                    connected.add(entity_id)
        return round(len(connected) / len(self.assets), 4)

    def freshness_score(self, now: datetime | None = None) -> float:
        """Estimate freshness from last-seen timestamps."""
        if not self.assets:
            return 0.0
        reference = now or utc_now()
        fresh = 0
        for asset in self.assets.values():
            age = reference - asset.last_seen
            if age <= timedelta(days=1):
                fresh += 1
        return round(fresh / len(self.assets), 4)

    def _resolve_asset(
        self,
        event: SecurityEvent,
        role: str,
        result: TwinUpdateResult,
    ) -> str | None:
        observation = self.resolver.asset_observation_from_event(event, role=role)
        if observation is None:
            return None
        outcome = self.resolver.resolve_asset(
            observation,
            self.assets,
            event=event,
        )
        result.warnings.extend(outcome.warnings)
        if outcome.entity_id is None:
            return None
        if outcome.created:
            result.assets_created.append(outcome.entity_id)
        elif outcome.updated:
            result.assets_updated.append(outcome.entity_id)
        return outcome.entity_id

    def _resolve_identity(
        self,
        event: SecurityEvent,
        result: TwinUpdateResult,
    ) -> str | None:
        observation = self.resolver.identity_observation_from_event(event)
        if observation is None:
            return None
        outcome = self.resolver.resolve_identity(
            observation,
            self.identities,
            event=event,
        )
        result.warnings.extend(outcome.warnings)
        if outcome.entity_id is None:
            return None
        if outcome.created:
            result.identities_created.append(outcome.entity_id)
        elif outcome.updated:
            result.identities_updated.append(outcome.entity_id)
        return outcome.entity_id

    def _apply_relationships(
        self,
        event: SecurityEvent,
        result: TwinUpdateResult,
        *,
        src_asset_id: str | None,
        dst_asset_id: str | None,
        main_asset_id: str | None,
        identity_id: str | None,
    ) -> None:
        if event.event_type == "network_connection" and src_asset_id and dst_asset_id:
            self._upsert_relationship(
                result,
                event,
                source_entity_id=src_asset_id,
                target_entity_id=dst_asset_id,
                relationship_type="connects_to",
                protocol=str(event.attributes.get("protocol") or "")
                or None,
                port=event.dst_port,
            )
        elif event.event_type in {
            "authentication_success",
            "authentication_failure",
        } and identity_id and main_asset_id:
            rel_type = (
                "authenticated_to"
                if event.event_type == "authentication_success"
                else "auth_failed_to"
            )
            self._upsert_relationship(
                result,
                event,
                source_entity_id=identity_id,
                target_entity_id=main_asset_id,
                relationship_type=rel_type,
            )
        elif event.event_type == "credential_use":
            credential_entity = (
                f"credential:{event.credential_id}"
                if event.credential_id
                else None
            )
            if identity_id and credential_entity:
                self._upsert_relationship(
                    result,
                    event,
                    source_entity_id=identity_id,
                    target_entity_id=credential_entity,
                    relationship_type="uses_credential",
                )
            if credential_entity and (main_asset_id or dst_asset_id):
                self._upsert_relationship(
                    result,
                    event,
                    source_entity_id=credential_entity,
                    target_entity_id=main_asset_id or dst_asset_id,
                    relationship_type="uses_credential_on",
                )
        elif event.event_type == "deception_interaction" and main_asset_id:
            asset = self.assets[main_asset_id]
            asset.is_decoy = True
            asset.attributes["last_deception_event_id"] = event.event_id
            actor = identity_id or src_asset_id or "unknown_actor"
            self._upsert_relationship(
                result,
                event,
                source_entity_id=actor,
                target_entity_id=main_asset_id,
                relationship_type="interacted_with_decoy",
            )
        elif event.event_type == "vulnerability_observed" and main_asset_id:
            vuln_id = str(event.attributes.get("vulnerability_id") or "unknown")
            asset = self.assets[main_asset_id]
            vulnerabilities = asset.attributes.setdefault("vulnerabilities", [])
            if vuln_id not in vulnerabilities:
                vulnerabilities.append(vuln_id)
            self._upsert_relationship(
                result,
                event,
                source_entity_id=main_asset_id,
                target_entity_id=f"vulnerability:{vuln_id}",
                relationship_type="has_vulnerability",
            )
        elif event.event_type == "process_start" and main_asset_id:
            process_entity = f"process:{event.process_name or 'unknown'}"
            self._upsert_relationship(
                result,
                event,
                source_entity_id=main_asset_id,
                target_entity_id=process_entity,
                relationship_type="ran_process_on",
            )
        elif event.event_type == "file_access" and main_asset_id:
            actor = identity_id or src_asset_id or "unknown_actor"
            self._upsert_relationship(
                result,
                event,
                source_entity_id=actor,
                target_entity_id=main_asset_id,
                relationship_type="accessed_file_on",
            )
        elif event.event_type == "dns_query" and src_asset_id and dst_asset_id:
            self._upsert_relationship(
                result,
                event,
                source_entity_id=src_asset_id,
                target_entity_id=dst_asset_id,
                relationship_type="resolved_dns_to",
            )

    def _upsert_relationship(
        self,
        result: TwinUpdateResult,
        event: SecurityEvent,
        *,
        source_entity_id: str,
        target_entity_id: str,
        relationship_type: str,
        protocol: str | None = None,
        port: int | None = None,
        privilege_requirement: str | None = None,
    ) -> str:
        rel_id = self._relationship_id(
            source_entity_id,
            target_entity_id,
            relationship_type,
            protocol,
            port,
            privilege_requirement,
        )
        ttl_seconds = self.relationship_ttls.get(relationship_type)
        expiry = (
            event.event_time + timedelta(seconds=ttl_seconds)
            if ttl_seconds
            else None
        )
        if rel_id not in self.relationships:
            self.relationships[rel_id] = Relationship(
                relationship_id=rel_id,
                source_entity_id=source_entity_id,
                target_entity_id=target_entity_id,
                relationship_type=relationship_type,
                protocol=protocol,
                port=port,
                privilege_requirement=privilege_requirement,
                confidence=event.confidence,
                first_seen=event.event_time,
                last_seen=event.event_time,
                expiry_time=expiry,
                source_event_ids=[event.event_id],
                active=True,
            )
            result.relationships_created.append(rel_id)
            return rel_id

        relationship = self.relationships[rel_id]
        relationship.last_seen = max(relationship.last_seen, event.event_time)
        relationship.confidence = max(relationship.confidence, event.confidence)
        relationship.expiry_time = max(
            relationship.expiry_time or expiry or event.event_time,
            expiry or relationship.expiry_time or event.event_time,
        )
        relationship.active = True
        if event.event_id not in relationship.source_event_ids:
            relationship.source_event_ids.append(event.event_id)
        result.relationships_updated.append(rel_id)
        return rel_id

    def _relationship_id(
        self,
        source_entity_id: str,
        target_entity_id: str,
        relationship_type: str,
        protocol: str | None,
        port: int | None,
        privilege_requirement: str | None,
    ) -> str:
        payload = "|".join(
            [
                source_entity_id,
                target_entity_id,
                relationship_type,
                protocol or "",
                str(port or ""),
                privilege_requirement or "",
            ]
        )
        digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]
        return f"rel:{digest}"

    def _log_event(
        self,
        event: SecurityEvent,
        result: TwinUpdateResult,
    ) -> None:
        LOGGER.info(
            "digital_twin_event_applied",
            extra={
                "event_id": event.event_id,
                "event_type": event.event_type,
                "assets_created": result.assets_created,
                "assets_updated": result.assets_updated,
                "identities_created": result.identities_created,
                "identities_updated": result.identities_updated,
                "relationships_created": result.relationships_created,
                "relationships_updated": result.relationships_updated,
                "warnings": result.warnings,
                "twin_version": result.twin_version,
            },
        )
