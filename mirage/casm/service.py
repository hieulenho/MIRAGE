"""CASM V1 asset reconciliation and Twin quality metrics."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from mirage.detection.utils import slug
from mirage.domain.schemas import (
    Asset,
    AssetConflict,
    CASMExpirySummary,
    CASMUpdateResult,
    DiscoveryObservation,
    TwinQualityReport,
)
from mirage.execution.utils import deterministic_id, ensure_utc
from mirage.layer6_twin.digital_twin import DigitalTwin


class CASMService:
    """Reconcile continuous asset, identity, service, and vulnerability observations."""

    def __init__(
        self,
        twin: DigitalTwin,
        *,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.twin = twin
        self.config = config or {}
        self.source_precedence = self.config.get(
            "source_precedence",
            {
                "authoritative_inventory": 100,
                "active_directory": 90,
                "iam": 90,
                "edr": 80,
                "sysmon": 75,
                "vulnerability_scanner": 70,
                "asset_inventory": 70,
                "zeek": 50,
                "netflow": 45,
                "generic_jsonl": 40,
            },
        )
        self.asset_ttl_seconds = int(self.config.get("asset_ttl_seconds", 86400))
        self.conflicts: dict[str, AssetConflict] = {}
        self.duplicate_candidates: set[str] = set()

    def apply_observation(
        self,
        observation: DiscoveryObservation,
    ) -> CASMUpdateResult:
        """Apply one observation and preserve provenance/conflicts."""
        asset_id = self._resolve_asset_id(observation)
        created = False
        updated = False
        warnings: list[str] = []
        if asset_id not in self.twin.assets:
            self.twin.assets[asset_id] = Asset(
                asset_id=asset_id,
                hostname=observation.hostname,
                ip_addresses=list(observation.ip_addresses),
                asset_type=str(observation.attributes.get("asset_type") or "unknown"),
                operating_system=observation.operating_system,
                environment=observation.attributes.get("environment"),
                subnet=observation.subnet,
                business_criticality=float(
                    observation.attributes.get("business_criticality") or 0.0
                ),
                owner=observation.attributes.get("owner"),
                first_seen=observation.event_time,
                last_seen=observation.event_time,
                confidence=observation.confidence,
                data_sources=[observation.source],
                active=True,
                aliases=[],
                is_decoy=bool(observation.attributes.get("is_decoy", False)),
                attributes={
                    "casm_state": "ACTIVE",
                    "provenance": {},
                    "services": observation.services,
                    "ports": observation.ports,
                    "software": observation.software,
                    "vulnerabilities": observation.vulnerabilities,
                },
            )
            created = True
            self.twin.version += 1
        asset = self.twin.assets[asset_id]
        conflicts = self._update_asset(asset, observation)
        if conflicts:
            for conflict in conflicts:
                self.conflicts[conflict.conflict_id] = conflict
        updated = not created
        asset.last_seen = max(asset.last_seen, observation.event_time)
        asset.active = True
        asset.attributes["casm_state"] = (
            "CONFLICTED" if conflicts else "ACTIVE"
        )
        self.twin.version += int(updated)
        return CASMUpdateResult(
            observation_id=observation.observation_id,
            canonical_entity_id=asset_id,
            created=created,
            updated=updated,
            conflicts=conflicts,
            warnings=warnings,
        )

    def reconcile_asset(self, candidate) -> CASMUpdateResult:
        """Reconcile one candidate observation-like object."""
        if isinstance(candidate, DiscoveryObservation):
            return self.apply_observation(candidate)
        return self.apply_observation(DiscoveryObservation.model_validate(candidate))

    def find_conflicts(self) -> list[AssetConflict]:
        """Return current unresolved conflicts."""
        return sorted(self.conflicts.values(), key=lambda item: item.conflict_id)

    def expire_stale_entities(self, reference_time) -> CASMExpirySummary:
        """Mark stale assets without deleting historical data."""
        reference = ensure_utc(reference_time)
        stale_assets = 0
        for asset in self.twin.assets.values():
            if reference - asset.last_seen > timedelta(seconds=self.asset_ttl_seconds):
                if asset.attributes.get("casm_state") != "STALE":
                    asset.attributes["casm_state"] = "STALE"
                    stale_assets += 1
        expired_relationships = len(self.twin.expire_relationships(reference))
        if stale_assets or expired_relationships:
            self.twin.version += 1
        return CASMExpirySummary(
            stale_assets=stale_assets,
            expired_relationships=expired_relationships,
        )

    def quality_report(self) -> TwinQualityReport:
        """Return engineering quality metrics, not visibility guarantees."""
        snapshot = self.twin.create_snapshot()
        assets = list(snapshot.assets.values())
        total = len(assets)
        active = sum(1 for asset in assets if asset.active)
        stale = sum(1 for asset in assets if asset.attributes.get("casm_state") == "STALE")
        provisional = sum(1 for asset in assets if ":provisional:" in asset.asset_id)
        unresolved = sum(1 for asset in assets if asset.asset_type == "unknown")
        source_counts = [len(set(asset.data_sources)) for asset in assets]
        diversity = (
            sum(min(1.0, count / 3) for count in source_counts) / total
            if total
            else 0.0
        )
        conflict_rate = min(1.0, len(self.conflicts) / max(1, total))
        confidence = (
            sum(asset.confidence for asset in assets) / total if total else 0.0
        )
        confidence = max(0.0, min(1.0, confidence * (1.0 - 0.5 * conflict_rate)))
        return TwinQualityReport(
            twin_version=snapshot.twin_version,
            total_assets=total,
            active_assets=active,
            stale_assets=stale,
            provisional_assets=provisional,
            unresolved_assets=unresolved,
            duplicate_candidates=len(self.duplicate_candidates),
            conflicting_fields=len(self.conflicts),
            relationship_count=len(snapshot.relationships),
            expired_relationships=sum(
                1 for relationship in snapshot.relationships.values()
                if not relationship.active
            ),
            coverage_score=snapshot.coverage_score,
            freshness_score=snapshot.freshness_score,
            confidence_score=round(confidence, 4),
            source_diversity_score=round(diversity, 4),
            warnings=[
                "Twin quality metrics are engineering indicators, not proof of complete visibility."
            ],
            generated_at=snapshot.timestamp,
        )

    def _resolve_asset_id(self, observation: DiscoveryObservation) -> str:
        attrs = observation.attributes
        explicit = attrs.get("asset_id")
        if explicit:
            return str(explicit)
        for alias_field, prefix in (
            (observation.agent_id, "asset:agent"),
            (observation.cloud_instance_id, "asset:cloud"),
            (attrs.get("inventory_id"), "asset:inventory"),
        ):
            if alias_field:
                for asset in self.twin.assets.values():
                    if alias_field in asset.aliases:
                        return asset.asset_id
                return f"{prefix}:{slug(str(alias_field))}"
        if observation.hostname:
            normalized = slug(
                f"{observation.hostname}.{observation.domain}"
                if observation.domain
                else observation.hostname
            )
            matches = [
                asset.asset_id
                for asset in self.twin.assets.values()
                if normalized in asset.aliases
                or (asset.hostname and slug(asset.hostname) == slug(observation.hostname))
            ]
            if matches:
                if len(matches) > 1:
                    self.duplicate_candidates.add(normalized)
                return sorted(matches)[0]
            return f"asset:host:{normalized}"
        if observation.mac_address:
            return f"asset:mac:{slug(observation.mac_address)}"
        if observation.ip_addresses:
            return f"asset:ip:{slug(observation.ip_addresses[0])}"
        return f"asset:provisional:{slug(observation.observation_id)}"

    def _update_asset(
        self,
        asset: Asset,
        observation: DiscoveryObservation,
    ) -> list[AssetConflict]:
        conflicts: list[AssetConflict] = []
        for value in observation.ip_addresses:
            if value not in asset.ip_addresses:
                asset.ip_addresses.append(value)
        for alias in (
            observation.agent_id,
            observation.cloud_instance_id,
            observation.mac_address,
            slug(observation.hostname) if observation.hostname else None,
        ):
            if alias and alias not in asset.aliases:
                asset.aliases.append(alias)
        if observation.source not in asset.data_sources:
            asset.data_sources.append(observation.source)
        for field, value in {
            "hostname": observation.hostname,
            "operating_system": observation.operating_system,
            "subnet": observation.subnet,
            "environment": observation.attributes.get("environment"),
            "owner": observation.attributes.get("owner"),
            "asset_type": observation.attributes.get("asset_type"),
        }.items():
            if not value:
                continue
            current = getattr(asset, field)
            if field == "asset_type" and current == "unknown":
                current = None
            if current in (None, "", "unknown"):
                setattr(asset, field, value)
                self._provenance(asset, field, observation, value)
            elif str(current) != str(value):
                if self._should_replace(asset, field, observation):
                    setattr(asset, field, value)
                    self._provenance(asset, field, observation, value)
                else:
                    conflicts.append(
                        self._conflict(asset.asset_id, field, current, value, observation)
                    )
        reported_criticality = observation.attributes.get("business_criticality")
        if reported_criticality is not None:
            candidate = float(reported_criticality)
            if candidate >= asset.business_criticality:
                asset.business_criticality = candidate
                self._provenance(asset, "business_criticality", observation, candidate)
            elif observation.confidence >= 0.95 and self._precedence(observation.source) >= 90:
                asset.business_criticality = candidate
                self._provenance(asset, "business_criticality", observation, candidate)
            else:
                conflicts.append(
                    self._conflict(
                        asset.asset_id,
                        "business_criticality",
                        asset.business_criticality,
                        candidate,
                        observation,
                    )
                )
        asset.confidence = max(asset.confidence, observation.confidence)
        asset.attributes.setdefault("services", [])
        asset.attributes.setdefault("ports", [])
        asset.attributes.setdefault("software", [])
        asset.attributes.setdefault("vulnerabilities", [])
        for key, values in {
            "services": observation.services,
            "ports": observation.ports,
            "software": observation.software,
            "vulnerabilities": observation.vulnerabilities,
        }.items():
            existing = asset.attributes.setdefault(key, [])
            for value in values:
                if value not in existing:
                    existing.append(value)
        return conflicts

    def _provenance(
        self,
        asset: Asset,
        field: str,
        observation: DiscoveryObservation,
        value,
    ) -> None:
        asset.attributes.setdefault("provenance", {})[field] = {
            "value": value,
            "source": observation.source,
            "source_confidence": observation.confidence,
            "first_observed": observation.event_time.isoformat(),
            "last_observed": observation.event_time.isoformat(),
            "update_reason": "casm_observation",
        }

    def _should_replace(
        self,
        asset: Asset,
        field: str,
        observation: DiscoveryObservation,
    ) -> bool:
        provenance = asset.attributes.get("provenance", {}).get(field, {})
        current_source = provenance.get("source", "")
        return (
            self._precedence(observation.source) > self._precedence(current_source)
            and observation.confidence >= float(provenance.get("source_confidence", 0.0))
        )

    def _conflict(
        self,
        asset_id: str,
        field: str,
        current,
        candidate,
        observation: DiscoveryObservation,
    ) -> AssetConflict:
        now = observation.event_time
        return AssetConflict(
            conflict_id=deterministic_id(
                "conflict",
                asset_id,
                field,
                current,
                candidate,
                observation.source,
            ),
            canonical_entity_id=asset_id,
            conflicting_field=field,
            candidate_values=sorted({str(current), str(candidate)}),
            sources=sorted({observation.source}),
            source_confidence={observation.source: observation.confidence},
            created_at=now,
            updated_at=now,
        )

    def _precedence(self, source: str) -> int:
        return int(self.source_precedence.get(source, 0))
