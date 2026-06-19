"""Fixture-driven read-only connectors for Milestone 5."""

from __future__ import annotations

from mirage.connectors.base import BaseJSONLConnector
from mirage.domain.schemas import ConnectorConfig, ConnectorType, RawConnectorRecord


class GenericJSONLConnector(BaseJSONLConnector):
    """Generic connector for already-near-canonical JSONL events."""


class SysmonWindowsConnector(BaseJSONLConnector):
    """Read-only Sysmon/Windows-event fixture connector."""

    SYSMON_TYPES = {
        "1": "process_start",
        "3": "network_connection",
        "11": "file_access",
        "22": "dns_query",
        "4624": "authentication_success",
        "4625": "authentication_failure",
        "4720": "identity_change",
        "4732": "identity_change",
        "7045": "process_start",
        "4698": "process_start",
    }

    def map_record(self, record: RawConnectorRecord) -> dict:
        raw = dict(record.raw_payload)
        event_id = str(raw.get("event_id") or raw.get("EventID") or raw.get("event.code") or "")
        event_type = raw.get("event_type") or self.SYSMON_TYPES.get(event_id, "process_start")
        command = str(raw.get("CommandLine") or raw.get("command_line") or "")
        command_features = {
            "command_line_redacted": bool(command),
            "command_hash": record.payload_hash[:16] if command else None,
            "parent_process": raw.get("ParentImage") or raw.get("parent_process"),
        }
        return {
            "event_id": f"{record.connector_id}:{record.source_record_id}",
            "event_time": record.source_event_time.isoformat(),
            "ingest_time": record.ingestion_time.isoformat(),
            "source": record.connector_id,
            "event_type": event_type,
            "asset_id": raw.get("asset_id"),
            "hostname": raw.get("Computer") or raw.get("host") or raw.get("hostname"),
            "username": raw.get("User") or raw.get("TargetUserName") or raw.get("user"),
            "src_ip": raw.get("SourceIp") or raw.get("src_ip"),
            "dst_ip": raw.get("DestinationIp") or raw.get("dst_ip"),
            "dst_port": raw.get("DestinationPort") or raw.get("dst_port"),
            "process_name": raw.get("Image") or raw.get("ProcessName") or raw.get("process_name"),
            "command_line": None,
            "technique_ids": raw.get("technique_ids", []),
            "confidence": raw.get("confidence", 0.9),
            "raw_event_ref": record.source_record_id,
            "attributes": {
                "connector_type": "sysmon_windows",
                "asset_type": raw.get("asset_type", "workstation"),
                "environment": raw.get("environment", "lab"),
                **{k: v for k, v in command_features.items() if v is not None},
            },
        }


class ZeekNetFlowConnector(BaseJSONLConnector):
    """Read-only Zeek or generic NetFlow fixture connector."""

    def map_record(self, record: RawConnectorRecord) -> dict:
        raw = dict(record.raw_payload)
        path = str(raw.get("_path") or raw.get("record_type") or raw.get("event_type") or "conn")
        if path in {"dns", "dns_query"}:
            event_type = "dns_query"
        elif path in {"notice", "alert"}:
            event_type = "network_connection"
        elif path in {"files", "file"}:
            event_type = "file_access"
        else:
            event_type = "network_connection"
        return {
            "event_id": f"{record.connector_id}:{record.source_record_id}",
            "event_time": record.source_event_time.isoformat(),
            "ingest_time": record.ingestion_time.isoformat(),
            "source": record.connector_id,
            "event_type": event_type,
            "src_ip": raw.get("id.orig_h") or raw.get("src_ip") or raw.get("source_ip"),
            "dst_ip": raw.get("id.resp_h") or raw.get("dst_ip") or raw.get("destination_ip"),
            "dst_port": raw.get("id.resp_p") or raw.get("dst_port") or raw.get("destination_port"),
            "protocol": raw.get("proto") or raw.get("protocol"),
            "confidence": raw.get("confidence", 0.85),
            "raw_event_ref": record.source_record_id,
            "attributes": {
                "connector_type": "zeek_netflow",
                "uid": raw.get("uid") or raw.get("flow_id"),
                "duration": raw.get("duration"),
                "bytes": raw.get("orig_bytes") or raw.get("bytes"),
                "query": raw.get("query"),
                "connection_state": raw.get("conn_state"),
                "asset_type": raw.get("asset_type", "unknown"),
                "environment": raw.get("environment", "lab"),
            },
        }


class ActiveDirectoryIAMConnector(BaseJSONLConnector):
    """Read-only AD/IAM lab fixture connector."""

    def map_record(self, record: RawConnectorRecord) -> dict:
        raw = dict(record.raw_payload)
        event_type = raw.get("event_type") or (
            "authentication_failure"
            if str(raw.get("outcome", "")).lower() == "failure"
            else "authentication_success"
        )
        username = raw.get("username") or raw.get("sAMAccountName") or raw.get("principal")
        domain = raw.get("domain") or raw.get("tenant")
        identity_id = raw.get("identity_id") or (
            f"identity:{domain}:{username}".lower()
            if domain and username
            else None
        )
        return {
            "event_id": f"{record.connector_id}:{record.source_record_id}",
            "event_time": record.source_event_time.isoformat(),
            "ingest_time": record.ingestion_time.isoformat(),
            "source": record.connector_id,
            "event_type": event_type,
            "asset_id": raw.get("asset_id"),
            "user_id": identity_id,
            "username": username,
            "confidence": raw.get("confidence", 0.95),
            "raw_event_ref": record.source_record_id,
            "attributes": {
                "connector_type": "ad_iam",
                "domain": domain,
                "groups": raw.get("groups", []),
                "identity_type": raw.get("identity_type", "user"),
                "privilege_level": raw.get("privilege_level", "unknown"),
                "enabled": raw.get("enabled", True),
                "session_id": raw.get("session_id"),
                "hostname": raw.get("hostname"),
                "asset_type": raw.get("asset_type", "workstation"),
                "environment": raw.get("environment", "lab"),
            },
        }


class AssetVulnerabilityConnector(BaseJSONLConnector):
    """Read-only asset inventory and vulnerability fixture connector."""

    def map_record(self, record: RawConnectorRecord) -> dict:
        raw = dict(record.raw_payload)
        vulnerability_id = raw.get("vulnerability_id") or raw.get("cve")
        event_type = (
            "vulnerability_observed"
            if vulnerability_id or raw.get("event_type") == "vulnerability_observed"
            else "asset_discovered"
        )
        return {
            "event_id": f"{record.connector_id}:{record.source_record_id}",
            "event_time": record.source_event_time.isoformat(),
            "ingest_time": record.ingestion_time.isoformat(),
            "source": record.connector_id,
            "event_type": event_type,
            "asset_id": raw.get("asset_id"),
            "src_ip": raw.get("ip") or raw.get("src_ip"),
            "hostname": raw.get("hostname"),
            "confidence": raw.get("confidence", 0.9),
            "raw_event_ref": record.source_record_id,
            "attributes": {
                "connector_type": "asset_vulnerability",
                "hostname": raw.get("hostname"),
                "domain": raw.get("domain"),
                "agent_id": raw.get("agent_id"),
                "cloud_instance_id": raw.get("cloud_instance_id"),
                "asset_type": raw.get("asset_type", "unknown"),
                "operating_system": raw.get("operating_system"),
                "environment": raw.get("environment", "lab"),
                "subnet": raw.get("subnet"),
                "owner": raw.get("owner"),
                "business_criticality": raw.get("business_criticality", 0.0),
                "vulnerability_id": vulnerability_id,
                "severity": raw.get("severity"),
                "exploitability": raw.get("exploitability"),
                "services": raw.get("services", []),
                "ports": raw.get("ports", []),
                "software": raw.get("software", []),
            },
        }


def build_connector(config: ConnectorConfig):
    """Build a read-only connector from config."""
    mapping = {
        ConnectorType.GENERIC_JSONL: GenericJSONLConnector,
        ConnectorType.SYSMON: SysmonWindowsConnector,
        ConnectorType.WINDOWS_EVENT: SysmonWindowsConnector,
        ConnectorType.ZEEK: ZeekNetFlowConnector,
        ConnectorType.NETFLOW: ZeekNetFlowConnector,
        ConnectorType.ACTIVE_DIRECTORY: ActiveDirectoryIAMConnector,
        ConnectorType.IAM: ActiveDirectoryIAMConnector,
        ConnectorType.ASSET_INVENTORY: AssetVulnerabilityConnector,
        ConnectorType.VULNERABILITY_SCANNER: AssetVulnerabilityConnector,
    }
    return mapping[config.connector_type](config)
