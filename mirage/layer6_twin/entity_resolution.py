"""Deterministic entity resolution for Digital Twin V1."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from mirage.domain.schemas import Asset, Identity, SecurityEvent


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9_.:-]+", "-", value.strip().lower())
    return cleaned.strip("-") or "unknown"


def _append_unique(values: list[str], value: str | None) -> None:
    if value and value not in values:
        values.append(value)


@dataclass
class AssetObservation:
    """Observed asset identity attributes."""

    role: str
    asset_id: str | None = None
    agent_id: str | None = None
    cloud_instance_id: str | None = None
    hostname: str | None = None
    domain: str | None = None
    ip: str | None = None
    asset_type: str = "unknown"
    operating_system: str | None = None
    environment: str | None = None
    subnet: str | None = None
    business_criticality: float = 0.0
    owner: str | None = None
    is_decoy: bool = False


@dataclass
class IdentityObservation:
    """Observed identity attributes."""

    identity_id: str | None = None
    username: str | None = None
    domain: str | None = None
    email: str | None = None
    principal: str | None = None
    identity_type: str = "user"
    privilege_level: str = "unknown"
    groups: list[str] = field(default_factory=list)


@dataclass
class ResolutionOutcome:
    """Entity resolution result for one observation."""

    entity_id: str | None
    created: bool = False
    updated: bool = False
    warnings: list[str] = field(default_factory=list)


class EntityResolver:
    """Resolve raw observations to canonical asset and identity IDs."""

    def __init__(self, *, allow_provisional: bool = True) -> None:
        self.allow_provisional = allow_provisional

    def asset_observation_from_event(
        self,
        event: SecurityEvent,
        *,
        role: str,
    ) -> AssetObservation | None:
        """Extract a source or destination asset observation from an event."""
        attrs = event.attributes
        prefix = "src" if role == "source" else "dst"
        if role == "source":
            ip = event.src_ip
        elif role == "asset":
            ip = event.dst_ip or event.src_ip
        else:
            ip = event.dst_ip
        explicit_asset = event.asset_id if role in {"asset", "destination"} else None
        hostname = (
            attrs.get(f"{prefix}_hostname")
            or attrs.get(f"{prefix}_host")
            or (attrs.get("hostname") if role in {"asset", "destination"} else None)
        )
        if not any(
            (
                explicit_asset,
                attrs.get("agent_id"),
                attrs.get("cloud_instance_id"),
                hostname,
                ip,
            )
        ):
            return None
        return AssetObservation(
            role=role,
            asset_id=str(explicit_asset) if explicit_asset else None,
            agent_id=str(attrs.get("agent_id")) if attrs.get("agent_id") else None,
            cloud_instance_id=(
                str(attrs.get("cloud_instance_id"))
                if attrs.get("cloud_instance_id")
                else None
            ),
            hostname=str(hostname) if hostname else None,
            domain=str(attrs.get("domain")) if attrs.get("domain") else None,
            ip=str(ip) if ip else None,
            asset_type=str(attrs.get("asset_type") or "unknown"),
            operating_system=(
                str(attrs.get("operating_system"))
                if attrs.get("operating_system")
                else None
            ),
            environment=(
                str(attrs.get("environment")) if attrs.get("environment") else None
            ),
            subnet=str(attrs.get("subnet")) if attrs.get("subnet") else None,
            business_criticality=float(attrs.get("business_criticality") or 0.0),
            owner=str(attrs.get("owner")) if attrs.get("owner") else None,
            is_decoy=bool(
                role != "source"
                and (
                    attrs.get("is_decoy")
                    or event.event_type == "deception_interaction"
                    or str(attrs.get("asset_type", "")).startswith("decoy")
                )
            ),
        )

    def identity_observation_from_event(
        self,
        event: SecurityEvent,
    ) -> IdentityObservation | None:
        """Extract an identity observation from an event."""
        attrs = event.attributes
        username = (
            attrs.get("username")
            or attrs.get("user")
            or attrs.get("account")
        )
        if not any((event.user_id, username, attrs.get("email"), attrs.get("principal"))):
            return None
        return IdentityObservation(
            identity_id=event.user_id,
            username=str(username) if username else None,
            domain=str(attrs.get("user_domain") or attrs.get("domain") or "")
            or None,
            email=str(attrs.get("email")) if attrs.get("email") else None,
            principal=(
                str(attrs.get("principal")) if attrs.get("principal") else None
            ),
            identity_type=str(attrs.get("identity_type") or "user"),
            privilege_level=str(attrs.get("privilege_level") or "unknown"),
            groups=[str(group) for group in attrs.get("groups", [])]
            if isinstance(attrs.get("groups"), list)
            else [],
        )

    def resolve_asset(
        self,
        observation: AssetObservation,
        assets: dict[str, Asset],
        *,
        event: SecurityEvent,
    ) -> ResolutionOutcome:
        """Resolve or create a canonical asset record."""
        warnings: list[str] = []
        match_id = self._match_asset(observation, assets, warnings)
        created = False
        if match_id is None:
            if not self.allow_provisional:
                warnings.append(f"No asset match for {observation.role}")
                return ResolutionOutcome(None, warnings=warnings)
            match_id = self._new_asset_id(observation, event)
            assets[match_id] = Asset(
                asset_id=match_id,
                hostname=observation.hostname,
                ip_addresses=[],
                asset_type=observation.asset_type,
                operating_system=observation.operating_system,
                environment=observation.environment,
                subnet=observation.subnet,
                business_criticality=max(0.0, observation.business_criticality),
                owner=observation.owner,
                first_seen=event.event_time,
                last_seen=event.event_time,
                confidence=event.confidence,
                data_sources=[event.source],
                active=True,
                aliases=[],
                is_decoy=observation.is_decoy,
                attributes={},
            )
            created = True

        asset = assets[match_id]
        self._update_asset(asset, observation, event)
        return ResolutionOutcome(
            match_id,
            created=created,
            updated=not created,
            warnings=warnings,
        )

    def resolve_identity(
        self,
        observation: IdentityObservation,
        identities: dict[str, Identity],
        *,
        event: SecurityEvent,
    ) -> ResolutionOutcome:
        """Resolve or create a canonical identity record."""
        warnings: list[str] = []
        match_id = self._match_identity(observation, identities)
        created = False
        if match_id is None:
            if not self.allow_provisional:
                warnings.append("No identity match")
                return ResolutionOutcome(None, warnings=warnings)
            match_id = self._new_identity_id(observation, event)
            identities[match_id] = Identity(
                identity_id=match_id,
                username=observation.username,
                domain=observation.domain,
                identity_type=observation.identity_type,
                privilege_level=observation.privilege_level,
                groups=list(observation.groups),
                associated_assets=[],
                first_seen=event.event_time,
                last_seen=event.event_time,
                confidence=event.confidence,
                data_sources=[event.source],
                aliases=[],
                attributes={},
            )
            created = True

        identity = identities[match_id]
        self._update_identity(identity, observation, event)
        return ResolutionOutcome(
            match_id,
            created=created,
            updated=not created,
            warnings=warnings,
        )

    def _match_asset(
        self,
        observation: AssetObservation,
        assets: dict[str, Asset],
        warnings: list[str],
    ) -> str | None:
        if observation.asset_id and observation.asset_id in assets:
            return observation.asset_id
        if observation.asset_id:
            return None
        for alias in (observation.agent_id, observation.cloud_instance_id):
            if not alias:
                continue
            matches = [asset.asset_id for asset in assets.values() if alias in asset.aliases]
            if matches:
                return sorted(matches)[0]
        if observation.hostname:
            normalized = _slug(
                f"{observation.hostname}.{observation.domain}"
                if observation.domain
                else observation.hostname
            )
            matches = [
                asset.asset_id
                for asset in assets.values()
                if normalized in asset.aliases
                or (asset.hostname and _slug(asset.hostname) == _slug(observation.hostname))
            ]
            if matches:
                return sorted(matches)[0]
        if observation.ip:
            matches = [
                asset.asset_id
                for asset in assets.values()
                if observation.ip in asset.ip_addresses
            ]
            if len(matches) > 1:
                warnings.append(
                    f"Ambiguous asset resolution for IP {observation.ip}: "
                    f"{sorted(matches)}"
                )
            if matches:
                return sorted(matches)[0]
        return None

    def _match_identity(
        self,
        observation: IdentityObservation,
        identities: dict[str, Identity],
    ) -> str | None:
        if observation.identity_id and observation.identity_id in identities:
            return observation.identity_id
        if observation.identity_id:
            return None
        aliases = [
            observation.email,
            observation.principal,
            (
                f"{observation.domain}\\{observation.username}".lower()
                if observation.domain and observation.username
                else None
            ),
        ]
        for alias in aliases:
            if not alias:
                continue
            matches = [
                identity.identity_id
                for identity in identities.values()
                if alias in identity.aliases
            ]
            if matches:
                return sorted(matches)[0]
        return None

    def _new_asset_id(self, observation: AssetObservation, event: SecurityEvent) -> str:
        if observation.asset_id:
            return observation.asset_id
        if observation.agent_id:
            return f"asset:agent:{_slug(observation.agent_id)}"
        if observation.cloud_instance_id:
            return f"asset:cloud:{_slug(observation.cloud_instance_id)}"
        if observation.hostname:
            name = (
                f"{observation.hostname}.{observation.domain}"
                if observation.domain
                else observation.hostname
            )
            return f"asset:host:{_slug(name)}"
        if observation.ip:
            return f"asset:ip:{_slug(observation.ip)}"
        return f"asset:provisional:{_slug(event.event_id)}:{observation.role}"

    def _new_identity_id(
        self,
        observation: IdentityObservation,
        event: SecurityEvent,
    ) -> str:
        if observation.identity_id:
            return observation.identity_id
        if observation.domain and observation.username:
            return f"identity:{_slug(observation.domain)}:{_slug(observation.username)}"
        if observation.email:
            return f"identity:email:{_slug(observation.email)}"
        if observation.principal:
            return f"identity:principal:{_slug(observation.principal)}"
        return f"identity:provisional:{_slug(event.event_id)}"

    def _update_asset(
        self,
        asset: Asset,
        observation: AssetObservation,
        event: SecurityEvent,
    ) -> None:
        asset.last_seen = max(asset.last_seen, event.event_time)
        asset.confidence = max(asset.confidence, event.confidence)
        asset.business_criticality = max(
            asset.business_criticality,
            min(max(observation.business_criticality, 0.0), 1.0),
        )
        asset.active = True
        asset.is_decoy = asset.is_decoy or observation.is_decoy
        if observation.hostname and not asset.hostname:
            asset.hostname = observation.hostname
        if observation.ip:
            _append_unique(asset.ip_addresses, observation.ip)
        for alias in (
            observation.asset_id,
            observation.agent_id,
            observation.cloud_instance_id,
            _slug(observation.hostname) if observation.hostname else None,
        ):
            _append_unique(asset.aliases, alias)
        _append_unique(asset.data_sources, event.source)
        for name in ("asset_type", "operating_system", "environment", "subnet", "owner"):
            value = getattr(observation, name)
            if value and (name == "asset_type" and asset.asset_type == "unknown"):
                setattr(asset, name, value)
            elif value and name != "asset_type" and not getattr(asset, name):
                setattr(asset, name, value)

    def _update_identity(
        self,
        identity: Identity,
        observation: IdentityObservation,
        event: SecurityEvent,
    ) -> None:
        identity.last_seen = max(identity.last_seen, event.event_time)
        identity.confidence = max(identity.confidence, event.confidence)
        for name in ("username", "domain", "identity_type", "privilege_level"):
            value = getattr(observation, name)
            if value and not getattr(identity, name):
                setattr(identity, name, value)
        for group in observation.groups:
            _append_unique(identity.groups, group)
        for alias in (
            observation.identity_id,
            observation.email,
            observation.principal,
            (
                f"{observation.domain}\\{observation.username}".lower()
                if observation.domain and observation.username
                else None
            ),
        ):
            _append_unique(identity.aliases, alias)
        _append_unique(identity.data_sources, event.source)
