"""Validated project evidence packs. Evidence organisation only; no authority is granted."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from rhemascript.orchestration.creative_production import CreativeProductionOrchestrator, OrchestrationResult
from rhemascript.registry.system_registry import CAPABILITIES

class EvidencePackError(ValueError):
    pass

REQUIRED_FIELDS = {"manifest_id", "schema_version", "project_record", "artifacts", "evidence_records", "source_to_final_links"}
ARTIFACT_TYPES = {"BIBLICAL_SOURCE", "APPROVED_SCRIPT", "APPROVED_NARRATION", "STORYBOARD", "AUDIO_VISUAL_PLAN", "PROMPT", "ASSET", "EDITED_FILM", "YOUTUBE_VIDEO_VERIFICATION", "YOUTUBE_ANALYTICS_SNAPSHOT", "YOUTUBE_ANALYTICS_COMPARISON"}
CHAIN_ORDER = ("BIBLICAL_SOURCE", "APPROVED_SCRIPT", "APPROVED_NARRATION", "STORYBOARD", "AUDIO_VISUAL_PLAN", "PROMPT", "ASSET", "EDITED_FILM")
APPROVED_STATUSES = {"APPROVED", "VERIFIED", "ACCEPTED"}

@dataclass(frozen=True)
class ValidatedEvidencePack:
    manifest_id: str
    project_id: str
    project_version: str
    project_record: dict[str, Any]
    artifacts: tuple[dict[str, Any], ...]
    evidence_records: tuple[dict[str, Any], ...]
    source_to_final_links: tuple[dict[str, str], ...]
    capability_evidence: dict[str, dict[str, Any]]
    gate_records: tuple[dict[str, Any], ...]
    byte_verified_artifacts: tuple[Any, ...] = ()
    source_resolution_receipts: tuple[Any, ...] = ()
    evidence_integrity_mode: str = "STRUCTURAL_ONLY"

def _required_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidencePackError(f"{field} must be a non-empty string")
    return value

def _index(rows: list[dict[str, Any]], key: str, label: str) -> dict[str, dict[str, Any]]:
    result = {}
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise EvidencePackError(f"{label}[{i}] must be an object")
        ident = _required_string(row.get(key), f"{label}[{i}].{key}")
        if ident in result:
            raise EvidencePackError(f"duplicate {key}: {ident}")
        result[ident] = row
    return result

def _validate_graph(artifacts: dict[str, dict[str, Any]], links: list[dict[str, Any]]) -> None:
    graph = {key: set() for key in artifacts}
    for i, link in enumerate(links):
        if not isinstance(link, dict):
            raise EvidencePackError(f"source_to_final_links[{i}] must be an object")
        src = _required_string(link.get("from_artifact_id"), f"link[{i}].from_artifact_id")
        dst = _required_string(link.get("to_artifact_id"), f"link[{i}].to_artifact_id")
        _required_string(link.get("relationship"), f"link[{i}].relationship")
        if src not in artifacts or dst not in artifacts:
            raise EvidencePackError(f"link[{i}] references an unknown artifact")
        if src == dst:
            raise EvidencePackError(f"link[{i}] cannot reference itself")
        graph[src].add(dst)
    visiting, visited = set(), set()
    def visit(node):
        if node in visiting:
            raise EvidencePackError("source_to_final_links contains a provenance cycle")
        if node in visited:
            return
        visiting.add(node)
        for child in graph[node]:
            visit(child)
        visiting.remove(node)
        visited.add(node)
    for node in graph:
        visit(node)
    films = {ident for ident, artifact in artifacts.items()
             if artifact["artifact_type"] == "EDITED_FILM"}
    if not films:
        return
    by_type = {}
    for ident, artifact in artifacts.items():
        by_type.setdefault(artifact["artifact_type"], []).append(ident)
    missing = [kind for kind in CHAIN_ORDER if not by_type.get(kind)]
    if missing:
        raise EvidencePackError("EDITED_FILM requires complete source-to-final chain; missing: " + ", ".join(missing))

    # Validate one continuous, ordered path for every final film. Pairwise
    # reachability across arbitrary artifacts is insufficient: disconnected
    # branches must not be spliced together to fabricate a complete lineage.
    complete_films = set()
    for source_id in by_type["BIBLICAL_SOURCE"]:
        pending = [(source_id, 0)]
        visited_states = set()
        while pending:
            current, stage_index = pending.pop()
            state = (current, stage_index)
            if state in visited_states:
                continue
            visited_states.add(state)
            if stage_index == len(CHAIN_ORDER) - 1 and current in films:
                complete_films.add(current)
            for child in graph[current]:
                child_type = artifacts[child]["artifact_type"]
                next_stage = stage_index + 1
                if next_stage < len(CHAIN_ORDER) and child_type == CHAIN_ORDER[next_stage]:
                    pending.append((child, next_stage))
                else:
                    pending.append((child, stage_index))
    for film_id in sorted(films - complete_films):
        raise EvidencePackError(
            f"EDITED_FILM {film_id} lacks a complete ordered source-to-final chain"
        )

def validate_evidence_pack(pack: dict[str, Any]) -> ValidatedEvidencePack:
    if not isinstance(pack, dict):
        raise EvidencePackError("evidence pack must be an object")
    missing = REQUIRED_FIELDS - pack.keys()
    if missing:
        raise EvidencePackError("missing required fields: " + ", ".join(sorted(missing)))
    manifest_id = _required_string(pack["manifest_id"], "manifest_id")
    schema_version = _required_string(pack["schema_version"], "schema_version")
    if schema_version != "1.0":
        raise EvidencePackError(f"unsupported schema_version: {schema_version}")
    project = pack["project_record"]
    if not isinstance(project, dict):
        raise EvidencePackError("project_record must be an object")
    from rhemascript.core.envelope import validate_record, ContractError
    try:
        validate_record(project)
    except ContractError as exc:
        raise EvidencePackError(f"invalid project_record: {exc}") from exc
    artifacts_raw, evidence_raw, links_raw = pack["artifacts"], pack["evidence_records"], pack["source_to_final_links"]
    if not all(isinstance(x, list) for x in (artifacts_raw, evidence_raw, links_raw)):
        raise EvidencePackError("artifacts, evidence_records and source_to_final_links must be lists")
    artifacts = _index(artifacts_raw, "artifact_id", "artifacts")
    for ident, artifact in artifacts.items():
        if artifact.get("project_id") != project["project_id"]:
            raise EvidencePackError(f"artifact {ident} belongs to a different project")
        if artifact.get("project_version") != project["version"]:
            raise EvidencePackError(f"artifact {ident} is not bound to project version {project['version']}")
        artifact_type = artifact.get("artifact_type")
        if not isinstance(artifact_type, str) or artifact_type not in ARTIFACT_TYPES:
            raise EvidencePackError(f"artifact {ident} has unsupported artifact_type")
        _required_string(artifact.get("version"), f"artifact {ident}.version")
        _required_string(artifact.get("status"), f"artifact {ident}.status")
        if artifact["artifact_type"] in {"APPROVED_SCRIPT", "APPROVED_NARRATION"} and artifact["status"] not in APPROVED_STATUSES:
            raise EvidencePackError(f"{ident} approval status is not evidenced")
        if artifact_type in {"YOUTUBE_ANALYTICS_SNAPSHOT", "YOUTUBE_ANALYTICS_COMPARISON"}:
            digest_field = (
                "snapshot_sha256" if artifact_type == "YOUTUBE_ANALYTICS_SNAPSHOT"
                else "comparison_sha256"
            )
            digest = artifact.get(digest_field)
            if (not isinstance(digest, str) or len(digest) != 64
                    or any(char not in "0123456789abcdef" for char in digest)):
                raise EvidencePackError(
                    f"artifact {ident}.{digest_field} must be a lowercase SHA-256 digest"
                )
        if artifact_type == "YOUTUBE_ANALYTICS_COMPARISON":
            current_id = _required_string(
                artifact.get("current_snapshot_artifact_id"),
                f"artifact {ident}.current_snapshot_artifact_id",
            )
            previous_id = _required_string(
                artifact.get("previous_snapshot_artifact_id"),
                f"artifact {ident}.previous_snapshot_artifact_id",
            )
            if current_id == previous_id:
                raise EvidencePackError(
                    f"artifact {ident} must bind two distinct period snapshots"
                )
            for source_id in (current_id, previous_id):
                source = artifacts.get(source_id)
                if source is None or source.get("artifact_type") != "YOUTUBE_ANALYTICS_SNAPSHOT":
                    raise EvidencePackError(
                        f"artifact {ident} references a missing or non-snapshot Analytics source"
                    )
        refs = artifact.get("evidence_refs", [])
        if not isinstance(refs, list) or any(not isinstance(x, str) or not x.strip() for x in refs):
            raise EvidencePackError(f"artifact {ident}.evidence_refs must be non-empty strings")
    evidence = _index(evidence_raw, "evidence_id", "evidence_records")
    cap_evidence = {}
    for ident, item in evidence.items():
        cap = _required_string(item.get("capability_id"), f"evidence {ident}.capability_id")
        if cap not in CAPABILITIES:
            raise EvidencePackError(f"evidence {ident} references unknown capability: {cap}")
        payload = item.get("payload")
        if not isinstance(payload, dict):
            raise EvidencePackError(f"evidence {ident}.payload must be an object")
        if "evidence_refs" in payload:
            raise EvidencePackError(f"evidence {ident}.payload cannot override reserved evidence_refs")
        refs, artifact_refs = item.get("evidence_refs", []), item.get("artifact_refs", [])
        if not isinstance(refs, list) or any(not isinstance(x, str) or not x.strip() for x in refs):
            raise EvidencePackError(f"evidence {ident}.evidence_refs must contain non-empty strings")
        if not isinstance(artifact_refs, list) or any(not isinstance(x, str) or not x.strip() for x in artifact_refs):
            raise EvidencePackError(f"evidence {ident}.artifact_refs must contain non-empty strings")
        if any(x not in artifacts for x in artifact_refs):
            raise EvidencePackError(f"evidence {ident} contains an unknown artifact reference")
        target = cap_evidence.setdefault(cap, {})
        for key, value in payload.items():
            if key in target and target[key] != value:
                raise EvidencePackError(f"conflicting capability evidence for {cap}.{key}")
            target[key] = value
        target.setdefault("evidence_refs", []).extend(refs + [f"artifact:{x}" for x in artifact_refs])
    _validate_graph(artifacts, links_raw)
    gates = pack.get("gate_records", [])
    if not isinstance(gates, list) or any(not isinstance(x, dict) for x in gates):
        raise EvidencePackError("gate_records must be a list of objects")
    return ValidatedEvidencePack(manifest_id, project["project_id"], project["version"], project,
        tuple(artifacts.values()), tuple(evidence.values()), tuple(links_raw), cap_evidence, tuple(gates))

def run_evidence_pack(pack: dict[str, Any], *, actor_role: str, generation_authorisation: bool = False,
                      run_id: str | None = None, orchestrator: CreativeProductionOrchestrator | None = None,
                      evidence_root: str | Path | None = None, local_source_resolver: Any | None = None):
    """Assess a pack; evidence_root opts into mandatory byte verification.

    Without evidence_root this is legacy structural/provenance validation only.
    Status labels in that mode do not prove that local artifact bytes were checked.
    """
    validated = validate_evidence_pack(pack)
    versions = []
    receipts = []
    if evidence_root is not None:
        from .evidence_pack_integrity import verify_pack_artifacts
        versions.extend(verify_pack_artifacts(validated, evidence_root))
    if local_source_resolver is not None:
        from .local_source_resolver import LocalSourceResolver, LocalSourceResolutionError
        if not isinstance(local_source_resolver, LocalSourceResolver):
            raise EvidencePackError("local_source_resolver must be an approved LocalSourceResolver")
        for artifact in validated.artifacts:
            reference = artifact.get("local_source_reference")
            if reference is None:
                continue
            try:
                version, receipt = local_source_resolver.resolve(
                    reference, project_id=validated.project_id,
                    project_version=validated.project_version,
                )
            except LocalSourceResolutionError as exc:
                raise EvidencePackError(
                    f"artifact {artifact['artifact_id']} local source reference could not be verified"
                ) from exc
            if version.evidence_id != artifact["artifact_id"] or version.version != artifact["version"]:
                raise EvidencePackError(
                    f"artifact {artifact['artifact_id']} does not match the resolver's source identity/version"
                )
            declared_digest = artifact.get("sha256")
            if not isinstance(declared_digest, str) or declared_digest.lower() != version.sha256:
                raise EvidencePackError(
                    f"artifact {artifact['artifact_id']} SHA-256 does not match resolved local source"
                )
            versions.append(version)
            receipts.append(receipt)
    if versions or receipts:
        # One artifact ID must never acquire conflicting byte identities through
        # overlapping verification paths (evidence_root and local resolver).
        unique_versions = {}
        for version in versions:
            previous = unique_versions.get(version.evidence_id)
            if previous is not None and previous != version:
                raise EvidencePackError(
                    f"artifact {version.evidence_id} has conflicting byte-verification identities"
                )
            unique_versions[version.evidence_id] = version
        from dataclasses import replace
        validated = replace(validated, byte_verified_artifacts=tuple(unique_versions.values()),
                            source_resolution_receipts=tuple(receipts),
                            evidence_integrity_mode="BYTE_VERIFIED")
    result = (orchestrator or CreativeProductionOrchestrator()).run(
        validated.project_record, capability_evidence=validated.capability_evidence,
        actor_role=actor_role, gate_records=list(validated.gate_records),
        generation_authorisation=generation_authorisation,
        run_id=run_id or f"{validated.manifest_id}:{validated.project_version}")
    return validated, result
