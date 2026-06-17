"""Explainable event and temporal feature extraction."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Iterable

from mirage.detection.timeline import TimelineStore
from mirage.detection.utils import event_entity_ids, is_internal_ip
from mirage.domain.schemas import FeatureRecord, SecurityEvent, TimelineEvent
from mirage.layer6_twin.digital_twin import DigitalTwin


SCRIPT_INTERPRETERS = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "python.exe",
    "bash",
    "sh",
}
REMOTE_PORTS = {22, 3389, 445, 5985, 5986}
DISCOVERY_PORTS = {22, 53, 80, 135, 139, 389, 443, 445, 3389, 5985, 5986}


class FeatureExtractor:
    """Convert canonical events and timelines into explainable features."""

    def __init__(
        self,
        *,
        windows: Iterable[int] = (60, 300, 900, 3600),
        maintenance_windows: list[dict] | None = None,
        critical_asset_threshold: float = 0.8,
    ) -> None:
        self.windows = tuple(sorted({int(window) for window in windows if window > 0}))
        self.maintenance_windows = maintenance_windows or []
        self.critical_asset_threshold = critical_asset_threshold

    def extract(
        self,
        event: SecurityEvent,
        timeline_store: TimelineStore,
        *,
        twin: DigitalTwin | None = None,
        reference_time: datetime | None = None,
    ) -> dict[str, FeatureRecord]:
        """Extract deterministic single-event, temporal, and baseline features."""
        reference = reference_time or event.event_time
        features: dict[str, FeatureRecord] = {}
        self._single_event_features(event, features, twin=twin)
        for window in self.windows:
            self._temporal_features(event, timeline_store, features, window, reference)
        self._baseline_features(event, timeline_store, features, twin=twin)
        return dict(sorted(features.items()))

    def _add(
        self,
        features: dict[str, FeatureRecord],
        name: str,
        value,
        *,
        source_event_ids: list[str],
        explanation: str,
        window_seconds: int | None = None,
    ) -> None:
        features[name] = FeatureRecord(
            name=name,
            value=value,
            window_seconds=window_seconds,
            source_event_ids=source_event_ids,
            explanation=explanation,
        )

    def _single_event_features(
        self,
        event: SecurityEvent,
        features: dict[str, FeatureRecord],
        *,
        twin: DigitalTwin | None,
    ) -> None:
        event_id = [event.event_id]
        event_type = event.event_type
        process = (event.process_name or "").lower()
        command = event.command_line or ""
        command_lower = command.lower()
        attrs = event.attributes
        self._add(
            features,
            "is_failed_authentication",
            event_type == "authentication_failure",
            source_event_ids=event_id,
            explanation="Event type is authentication_failure.",
        )
        self._add(
            features,
            "is_successful_authentication",
            event_type == "authentication_success",
            source_event_ids=event_id,
            explanation="Event type is authentication_success.",
        )
        self._add(
            features,
            "is_remote_execution_process",
            bool(event.dst_ip and event.dst_port in REMOTE_PORTS),
            source_event_ids=event_id,
            explanation="Event targets a common remote execution or admin port.",
        )
        self._add(
            features,
            "is_script_interpreter",
            process in SCRIPT_INTERPRETERS,
            source_event_ids=event_id,
            explanation="Process name is a known script interpreter.",
        )
        self._add(
            features,
            "contains_encoded_command",
            "-enc" in command_lower or "encodedcommand" in command_lower,
            source_event_ids=event_id,
            explanation="Command line contains an encoded-command indicator.",
        )
        self._add(
            features,
            "contains_download_behavior",
            any(token in command_lower for token in ("invoke-webrequest", "curl", "wget")),
            source_event_ids=event_id,
            explanation="Command line contains a generic download indicator.",
        )
        self._add(
            features,
            "uses_hidden_execution",
            any(token in command_lower for token in ("-w hidden", "windowstyle hidden")),
            source_event_ids=event_id,
            explanation="Command line indicates hidden execution.",
        )
        self._add(
            features,
            "is_internal_network_connection",
            is_internal_ip(event.src_ip) and is_internal_ip(event.dst_ip),
            source_event_ids=event_id,
            explanation="Source and destination IPs are private/internal.",
        )
        self._add(
            features,
            "is_smb_connection",
            event.dst_port == 445 or str(attrs.get("protocol", "")).lower() == "smb",
            source_event_ids=event_id,
            explanation="Destination port/protocol indicates SMB.",
        )
        self._add(
            features,
            "is_rdp_connection",
            event.dst_port == 3389 or str(attrs.get("protocol", "")).lower() == "rdp",
            source_event_ids=event_id,
            explanation="Destination port/protocol indicates RDP.",
        )
        self._add(
            features,
            "is_ssh_connection",
            event.dst_port == 22 or str(attrs.get("protocol", "")).lower() == "ssh",
            source_event_ids=event_id,
            explanation="Destination port/protocol indicates SSH.",
        )
        self._add(
            features,
            "is_dns_query",
            event_type == "dns_query" or event.dst_port == 53,
            source_event_ids=event_id,
            explanation="Event is a DNS query or targets port 53.",
        )
        self._add(
            features,
            "is_deception_interaction",
            event_type == "deception_interaction",
            source_event_ids=event_id,
            explanation="Event type is deception_interaction.",
        )
        self._add(
            features,
            "uses_honey_credential",
            bool(event.credential_id and "honey" in event.credential_id.lower()),
            source_event_ids=event_id,
            explanation="Credential identifier is marked as synthetic honey material.",
        )
        self._add(
            features,
            "targets_decoy",
            bool(attrs.get("is_decoy") or str(attrs.get("asset_type", "")).startswith("decoy")),
            source_event_ids=event_id,
            explanation="Event target is marked as a decoy.",
        )
        critical = False
        if event.asset_id and twin and event.asset_id in twin.assets:
            critical = (
                twin.assets[event.asset_id].business_criticality
                >= self.critical_asset_threshold
            )
        critical = critical or float(attrs.get("business_criticality") or 0.0) >= self.critical_asset_threshold
        self._add(
            features,
            "targets_critical_asset",
            critical,
            source_event_ids=event_id,
            explanation="Target asset criticality is above configured threshold.",
        )
        self._add(
            features,
            "outside_normal_working_hours",
            event.event_time.hour < 6 or event.event_time.hour >= 20,
            source_event_ids=event_id,
            explanation="Event occurs outside default 06:00-20:00 working hours.",
        )
        self._add(
            features,
            "event_confidence",
            round(event.confidence, 4),
            source_event_ids=event_id,
            explanation="Canonical event confidence.",
        )

    def _temporal_features(
        self,
        event: SecurityEvent,
        timeline_store: TimelineStore,
        features: dict[str, FeatureRecord],
        window: int,
        reference_time: datetime,
    ) -> None:
        recent_by_id: dict[str, TimelineEvent] = {}
        for entity_id in event_entity_ids(event):
            for item in timeline_store.get_recent_events(entity_id, window, reference_time):
                recent_by_id[item.event_id] = item
        recent = sorted(recent_by_id.values(), key=lambda item: (item.event_time, item.event_id))
        event_ids = [item.event_id for item in recent]
        type_counts = Counter(item.event_type for item in recent)
        unique_entities = {
            entity_id
            for item in recent
            for entity_id in item.entity_ids
            if entity_id.startswith("asset:")
        }
        destination_hosts = {
            entity_id
            for item in recent
            for entity_id in item.entity_ids
            if entity_id.startswith("asset:ip:") or entity_id.startswith("asset:host:")
        }
        technique_ids = {
            technique_id
            for item in recent
            for technique_id in item.technique_ids
        }
        self._add(
            features,
            f"unique_destination_hosts_{window}s",
            len(destination_hosts),
            source_event_ids=event_ids,
            explanation=f"Unique destination-like assets in the last {window}s.",
            window_seconds=window,
        )
        destination_ports = {
            int(item.feature_values["dst_port"])
            for item in recent
            if "dst_port" in item.feature_values
        }
        self._add(
            features,
            f"unique_destination_ports_{window}s",
            len(destination_ports),
            source_event_ids=event_ids,
            explanation=f"Unique destination ports observed in the last {window}s.",
            window_seconds=window,
        )
        self._add(
            features,
            f"failed_login_count_{window}s",
            type_counts.get("authentication_failure", 0),
            source_event_ids=event_ids,
            explanation=f"Failed authentication count in the last {window}s.",
            window_seconds=window,
        )
        self._add(
            features,
            f"successful_login_after_failures_{window}s",
            event.event_type == "authentication_success"
            and type_counts.get("authentication_failure", 0) >= 3,
            source_event_ids=event_ids,
            explanation="Successful authentication followed repeated failures.",
            window_seconds=window,
        )
        self._add(
            features,
            f"identity_or_asset_fanout_{window}s",
            len(unique_entities),
            source_event_ids=event_ids,
            explanation=f"Number of related asset entities in the last {window}s.",
            window_seconds=window,
        )
        self._add(
            features,
            f"smb_connection_burst_{window}s",
            sum(
                1
                for item in recent
                if item.event_type == "network_connection"
                and self._event_has_port_or_protocol(item, 445, "smb")
            ),
            source_event_ids=event_ids,
            explanation=f"SMB-like connection count in the last {window}s.",
            window_seconds=window,
        )
        self._add(
            features,
            f"rdp_connection_burst_{window}s",
            sum(
                1
                for item in recent
                if item.event_type == "network_connection"
                and self._event_has_port_or_protocol(item, 3389, "rdp")
            ),
            source_event_ids=event_ids,
            explanation=f"RDP-like connection count in the last {window}s.",
            window_seconds=window,
        )
        self._add(
            features,
            f"dns_query_burst_{window}s",
            type_counts.get("dns_query", 0),
            source_event_ids=event_ids,
            explanation=f"DNS query count in the last {window}s.",
            window_seconds=window,
        )
        self._add(
            features,
            f"process_then_network_activity_{window}s",
            type_counts.get("process_start", 0) > 0
            and type_counts.get("network_connection", 0) > 0,
            source_event_ids=event_ids,
            explanation="Process execution and network connection co-occurred.",
            window_seconds=window,
        )
        self._add(
            features,
            f"credential_then_lateral_activity_{window}s",
            type_counts.get("credential_use", 0) > 0
            and (
                type_counts.get("network_connection", 0) > 0
                or type_counts.get("authentication_success", 0) > 0
            ),
            source_event_ids=event_ids,
            explanation="Credential use and remote activity co-occurred.",
            window_seconds=window,
        )
        self._add(
            features,
            f"decoy_interactions_{window}s",
            type_counts.get("deception_interaction", 0),
            source_event_ids=event_ids,
            explanation=f"Decoy interaction count in the last {window}s.",
            window_seconds=window,
        )
        self._add(
            features,
            f"event_source_diversity_{window}s",
            len({item.source for item in recent}),
            source_event_ids=event_ids,
            explanation=f"Distinct telemetry sources in the last {window}s.",
            window_seconds=window,
        )
        self._add(
            features,
            f"technique_diversity_{window}s",
            len(technique_ids),
            source_event_ids=event_ids,
            explanation=f"Distinct ATT&CK technique IDs in the last {window}s.",
            window_seconds=window,
        )

    def _baseline_features(
        self,
        event: SecurityEvent,
        timeline_store: TimelineStore,
        features: dict[str, FeatureRecord],
        *,
        twin: DigitalTwin | None,
    ) -> None:
        event_ids = [event.event_id]
        source_asset = event.asset_id or (
            f"asset:ip:{event.src_ip}" if event.src_ip else None
        )
        destination_asset = f"asset:ip:{event.dst_ip}" if event.dst_ip else None
        relation_seen = False
        if twin and source_asset and destination_asset:
            relation_seen = any(
                rel.source_entity_id == source_asset
                and rel.target_entity_id == destination_asset
                for rel in twin.relationships.values()
            )
        previous_events = [
            item
            for entity_id in event_entity_ids(event)
            for item in timeline_store.get_timeline(entity_id)
            if item.event_id != event.event_id
        ]
        self._add(
            features,
            "new_host_to_host_communication",
            event.event_type == "network_connection"
            and not relation_seen
            and not any(item.event_type == "network_connection" for item in previous_events),
            source_event_ids=event_ids,
            explanation="No previous same-entity network connection appears in timeline.",
        )
        self._add(
            features,
            "unusual_login_hour",
            event.event_type.startswith("authentication")
            and (event.event_time.hour < 6 or event.event_time.hour >= 20),
            source_event_ids=event_ids,
            explanation="Authentication occurred outside default working hours.",
        )
        self._add(
            features,
            "unusually_high_connection_rate",
            max(
                int(features[f"smb_connection_burst_{window}s"].value)
                for window in self.windows
            )
            >= 5,
            source_event_ids=event_ids,
            explanation="Recent connection burst exceeds default threshold.",
        )

    def _event_has_port_or_protocol(
        self,
        item: TimelineEvent,
        port: int,
        protocol: str,
    ) -> bool:
        value = item.feature_values.get("dst_port")
        if value == port:
            return True
        return str(item.feature_values.get("protocol", "")).lower() == protocol
