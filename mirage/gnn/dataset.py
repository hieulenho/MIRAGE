"""GraphDatasetBuilder — converts MIRAGE snapshots into serialisable GNN samples.

Usage
-----
>>> builder = GraphDatasetBuilder(schema=GraphFeatureSchema())
>>> sample = builder.build_sample(
...     twin_snapshot=twin,
...     belief_snapshot=belief,
...     local_subgraph=subgraph,
...     reference_time=datetime.now(timezone.utc),
... )
>>> summary = builder.build_dataset(snapshot_sequence, output_path="artifacts/gnn_ds")

Serialisation format
--------------------
  <output_path>/
      manifest.json               — DatasetBuildSummary + SplitManifest
      samples/<sample_id>.json    — GraphSample (JSON)

Split strategy:  scenario / topology / time interval.
No neighboring snapshots from the same incident are split across train/test.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mirage.domain.schemas import (
    BeliefSnapshot,
    LocalOperationalSubgraph,
    TwinSnapshot,
)
from mirage.gnn.features import (
    EdgeFeatureExtractor,
    NodeFeatureExtractor,
    TopologyStatsComputer,
)
from mirage.gnn.hierarchy import HierarchicalGraphBuilder
from mirage.gnn.schema import (
    DatasetBuildSummary,
    GraphFeatureSchema,
    GraphSample,
    GraphSampleLabels,
    SplitManifest,
    SplitType,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _stable_sample_id(
    twin_version: str,
    graph_version: str,
    belief_version: str,
    subgraph_id: str,
) -> str:
    payload = f"{twin_version}|{graph_version}|{belief_version}|{subgraph_id}"
    return "sample_" + hashlib.sha256(payload.encode()).hexdigest()[:20]


def _replace_sensitive_ids(
    value: Any,
    node_map: dict[str, str],
    edge_map: dict[str, str],
    sample_id: str,
) -> Any:
    """Recursively replace raw node/edge IDs in exported metadata."""
    if isinstance(value, str):
        if value in node_map:
            return node_map[value]
        if value in edge_map:
            return edge_map[value]
        if value.startswith("agg:"):
            return "agg_" + hashlib.sha256(
                f"{sample_id}|hierarchy|{value}".encode()
            ).hexdigest()[:16]
        return value
    if isinstance(value, list):
        return [
            _replace_sensitive_ids(item, node_map, edge_map, sample_id)
            for item in value
        ]
    if isinstance(value, dict):
        return {
            key: _replace_sensitive_ids(item, node_map, edge_map, sample_id)
            for key, item in value.items()
        }
    return value


class GraphDatasetBuilder:
    """Build GNN-ready graph samples from MIRAGE Digital Twin snapshots.

    Parameters
    ----------
    schema:
        Versioned feature schema.
    include_enterprise_node:
        Pass through to HierarchicalGraphBuilder.
    """

    def __init__(
        self,
        schema: GraphFeatureSchema | None = None,
        include_enterprise_node: bool = False,
        pseudonymize_export_ids: bool = True,
    ) -> None:
        self.schema = schema or GraphFeatureSchema()
        self.include_enterprise_node = include_enterprise_node
        self.pseudonymize_export_ids = pseudonymize_export_ids
        self._topo_computer = TopologyStatsComputer()

    def build_sample(
        self,
        twin_snapshot: TwinSnapshot,
        belief_snapshot: BeliefSnapshot,
        local_subgraph: LocalOperationalSubgraph,
        reference_time: datetime,
        labels: GraphSampleLabels | None = None,
        scenario_id: str = "unknown",
        topology_id: str = "unknown",
        split: SplitType = SplitType.TRAIN,
    ) -> GraphSample:
        """Convert one snapshot + subgraph into a GraphSample.

        No raw identifiers (IPs, usernames, hostnames) are included.
        """
        warnings: list[str] = list(local_subgraph.warnings)
        if twin_snapshot.coverage_score < 0.25:
            warnings.append("low_twin_coverage")

        # Topology stats for graph-topology features
        topo_stats = self._topo_computer.compute(local_subgraph)

        # Hierarchy
        hierarchy_builder = HierarchicalGraphBuilder(
            schema=self.schema,
            twin_snapshot=twin_snapshot,
            include_enterprise_node=self.include_enterprise_node,
        )
        hier = hierarchy_builder.build(local_subgraph)
        warnings.extend(hier.warnings)

        # Feature extractors
        node_extractor = NodeFeatureExtractor(
            schema=self.schema,
            reference_time=reference_time,
            twin_snapshot=twin_snapshot,
            belief_snapshot=belief_snapshot,
            topology_stats=topo_stats,
        )
        edge_extractor = EdgeFeatureExtractor(
            schema=self.schema,
            reference_time=reference_time,
        )

        # Build ordered node list (deterministic: sort by node_id)
        nodes = sorted(local_subgraph.nodes, key=lambda n: n.node_id)
        node_id_to_idx: dict[str, int] = {n.node_id: i for i, n in enumerate(nodes)}
        node_ids = [n.node_id for n in nodes]
        node_types = [n.entity_type for n in nodes]

        node_feature_matrix: list[list[float]] = []
        node_mask_matrix: list[list[float]] = []
        for node in nodes:
            feats, mask = node_extractor.extract(node)
            node_feature_matrix.append(feats)
            node_mask_matrix.append(mask)

        # Build ordered edge list (deterministic: sort by edge_id)
        edges = sorted(local_subgraph.edges, key=lambda e: e.edge_id)
        edge_ids: list[str] = []
        edge_types: list[str] = []

        src_list: list[int] = []
        dst_list: list[int] = []
        edge_feature_matrix: list[list[float]] = []
        edge_mask_matrix: list[list[float]] = []
        for edge in edges:
            src_idx = node_id_to_idx.get(edge.source_entity_id)
            dst_idx = node_id_to_idx.get(edge.target_entity_id)
            if src_idx is None or dst_idx is None:
                warnings.append(
                    f"edge {edge.edge_id} references unknown node; skipped"
                )
                continue
            edge_ids.append(edge.edge_id)
            edge_types.append(edge.relationship_type)
            src_list.append(src_idx)
            dst_list.append(dst_idx)
            feats, mask = edge_extractor.extract(edge)
            edge_feature_matrix.append(feats)
            edge_mask_matrix.append(mask)

        sample_id = _stable_sample_id(
            str(twin_snapshot.twin_version),
            local_subgraph.graph_version,
            str(local_subgraph.belief_version),
            local_subgraph.subgraph_id,
        )

        return GraphSample(
            sample_id=sample_id,
            twin_version=str(twin_snapshot.twin_version),
            graph_version=local_subgraph.graph_version,
            belief_version=str(local_subgraph.belief_version),
            feature_schema_version=self.schema.schema_version,
            feature_schema_hash=self.schema.schema_hash(),
            node_ids=node_ids,
            node_types=node_types,
            edge_ids=edge_ids,
            edge_types=edge_types,
            node_feature_matrix=node_feature_matrix,
            edge_feature_matrix=edge_feature_matrix,
            edge_index=[src_list, dst_list],
            hierarchy_mappings=hier.hierarchy_mappings_dict(),
            node_feature_mask=node_mask_matrix,
            edge_feature_mask=edge_mask_matrix,
            labels=labels,
            split=split,
            scenario_id=scenario_id,
            topology_id=topology_id,
            reference_time=reference_time,
            created_at=reference_time,
            warnings=sorted(set(warnings)),
        )

    def build_dataset(
        self,
        snapshot_sequence: list[dict[str, Any]],
        output_path: str,
    ) -> DatasetBuildSummary:
        """Build and serialise a full dataset from a sequence of snapshots.

        Each entry in *snapshot_sequence* is a dict with keys:
          twin_snapshot, belief_snapshot, local_subgraph, reference_time,
          labels (optional), scenario_id (optional), topology_id (optional).

        Split strategy: scenario-based.  Scenarios listed first get TRAIN;
        middle get VALIDATION; last get TEST.  Temporal ordering is preserved.
        """
        out_dir = Path(output_path)
        samples_dir = out_dir / "samples"
        samples_dir.mkdir(parents=True, exist_ok=True)

        samples: list[GraphSample] = []
        all_scenarios: list[str] = []
        warnings: list[str] = []

        # Collect scenario ordering
        for entry in snapshot_sequence:
            scenario_id = entry.get("scenario_id", "unknown")
            if scenario_id not in all_scenarios:
                all_scenarios.append(scenario_id)

        # Assign splits by scenario (70 / 15 / 15)
        n = len(all_scenarios)
        if n == 1:
            train_cutoff = 1
            val_cutoff = 1
        elif n == 2:
            train_cutoff = 1
            val_cutoff = 1
        else:
            train_cutoff = max(1, int(n * 0.70))
            val_cutoff = min(n, max(train_cutoff + 1, int(n * 0.85)))
        scenario_splits: dict[str, SplitType] = {}
        for i, scenario in enumerate(all_scenarios):
            if i < train_cutoff:
                scenario_splits[scenario] = SplitType.TRAIN
            elif i < val_cutoff:
                scenario_splits[scenario] = SplitType.VALIDATION
            else:
                scenario_splits[scenario] = SplitType.TEST

        for entry in snapshot_sequence:
            try:
                twin_snapshot: TwinSnapshot = entry["twin_snapshot"]
                belief_snapshot: BeliefSnapshot = entry["belief_snapshot"]
                local_subgraph: LocalOperationalSubgraph = entry["local_subgraph"]
                reference_time: datetime = entry["reference_time"]
                labels: GraphSampleLabels | None = entry.get("labels")
                scenario_id: str = entry.get("scenario_id", "unknown")
                topology_id: str = entry.get("topology_id", "unknown")
                split = scenario_splits.get(scenario_id, SplitType.TRAIN)
                sample = self.build_sample(
                    twin_snapshot=twin_snapshot,
                    belief_snapshot=belief_snapshot,
                    local_subgraph=local_subgraph,
                    reference_time=reference_time,
                    labels=labels,
                    scenario_id=scenario_id,
                    topology_id=topology_id,
                    split=split,
                )
                samples.append(sample)
            except Exception as exc:  # noqa: BLE001
                warnings.append(f"skipped sample due to error: {exc}")

        # Serialise samples
        train_ids: list[str] = []
        val_ids: list[str] = []
        test_ids: list[str] = []
        node_type_counts: dict[str, int] = {}
        edge_type_counts: dict[str, int] = {}
        label_counts: dict[str, int] = {"node_compromised": 0, "node_clean": 0}

        export_samples: list[GraphSample] = []
        for sample in samples:
            export_sample = (
                self._pseudonymize_sample(sample)
                if self.pseudonymize_export_ids
                else sample
            )
            export_samples.append(export_sample)
            sample_path = samples_dir / f"{export_sample.sample_id}.json"
            sample_path.write_text(
                export_sample.model_dump_json(indent=2),
                encoding="utf-8",
            )
            if export_sample.split == SplitType.TRAIN:
                train_ids.append(export_sample.sample_id)
            elif export_sample.split == SplitType.VALIDATION:
                val_ids.append(export_sample.sample_id)
            else:
                test_ids.append(export_sample.sample_id)
            for nt in export_sample.node_types:
                node_type_counts[nt] = node_type_counts.get(nt, 0) + 1
            for et in export_sample.edge_types:
                edge_type_counts[et] = edge_type_counts.get(et, 0) + 1
            if export_sample.labels:
                for nl in export_sample.labels.node_labels.values():
                    key = "node_compromised" if nl.is_compromised else "node_clean"
                    label_counts[key] = label_counts.get(key, 0) + 1

        dataset_timestamp = max(
            (sample.reference_time for sample in export_samples),
            default=_utc_now(),
        )

        # Build and save split manifest
        manifest_id = "manifest_" + hashlib.sha256(
            json.dumps(sorted(train_ids + val_ids + test_ids)).encode()
        ).hexdigest()[:16]
        split_manifest = SplitManifest(
            manifest_id=manifest_id,
            feature_schema_hash=self.schema.schema_hash(),
            split_strategy="scenario_time",
            train_sample_ids=sorted(train_ids),
            validation_sample_ids=sorted(val_ids),
            test_sample_ids=sorted(test_ids),
            scenario_assignments={
                s: v.value for s, v in scenario_splits.items()
            },
            created_at=dataset_timestamp,
        )
        manifest_path = out_dir / "manifest.json"
        summary = DatasetBuildSummary(
            total_samples=len(samples),
            train_samples=len(train_ids),
            validation_samples=len(val_ids),
            test_samples=len(test_ids),
            feature_schema_version=self.schema.schema_version,
            feature_schema_hash=self.schema.schema_hash(),
            output_path=str(out_dir.resolve()),
            manifest_path=str(manifest_path.resolve()),
            node_type_counts=node_type_counts,
            edge_type_counts=edge_type_counts,
            label_counts=label_counts,
            warnings=warnings,
            created_at=dataset_timestamp,
        )
        manifest_data = {
            "summary": json.loads(summary.model_dump_json()),
            "split_manifest": json.loads(split_manifest.model_dump_json()),
        }
        manifest_path.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
        return summary

    def _pseudonymize_sample(self, sample: GraphSample) -> GraphSample:
        """Return a copy with stable pseudonymous node and edge IDs."""
        node_map = {
            node_id: "node_" + hashlib.sha256(
                f"{sample.sample_id}|node|{node_id}".encode()
            ).hexdigest()[:16]
            for node_id in sample.node_ids
        }
        edge_map = {
            edge_id: "edge_" + hashlib.sha256(
                f"{sample.sample_id}|edge|{edge_id}".encode()
            ).hexdigest()[:16]
            for edge_id in sample.edge_ids
        }

        labels = sample.labels
        if labels is not None:
            node_labels = {
                node_map[node_id]: label.model_copy(
                    update={"node_id": node_map[node_id]}
                )
                for node_id, label in labels.node_labels.items()
                if node_id in node_map
            }
            edge_labels = {
                edge_map[edge_id]: label.model_copy(
                    update={"edge_id": edge_map[edge_id]}
                )
                for edge_id, label in labels.edge_labels.items()
                if edge_id in edge_map
            }
            labels = labels.model_copy(
                update={
                    "node_labels": node_labels,
                    "edge_labels": edge_labels,
                }
            )

        return sample.model_copy(
            update={
                "node_ids": [node_map[node_id] for node_id in sample.node_ids],
                "edge_ids": [edge_map[edge_id] for edge_id in sample.edge_ids],
                "hierarchy_mappings": _replace_sensitive_ids(
                    sample.hierarchy_mappings,
                    node_map,
                    edge_map,
                    sample.sample_id,
                ),
                "labels": labels,
            }
        )

    # ------------------------------------------------------------------
    # Helper: load a sample from disk
    # ------------------------------------------------------------------

    @staticmethod
    def load_sample(path: str) -> GraphSample:
        data = Path(path).read_text(encoding="utf-8")
        return GraphSample.model_validate_json(data)

    @staticmethod
    def load_dataset(output_path: str) -> tuple[list[GraphSample], dict]:
        """Load all samples from a dataset directory.

        Returns (samples, manifest_dict).
        """
        out_dir = Path(output_path)
        manifest_path = out_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        samples_dir = out_dir / "samples"
        samples: list[GraphSample] = []
        for sample_file in sorted(samples_dir.glob("*.json")):
            samples.append(GraphDatasetBuilder.load_sample(str(sample_file)))
        return samples, manifest
