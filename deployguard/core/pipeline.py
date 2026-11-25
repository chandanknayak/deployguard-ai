"""
core/pipeline.py — Shared Pull Request Analysis Orchestrator.

Single source of truth used by:
    - Webhook ingestion (``source="GITHUB_WEBHOOK"``)
    - User repository manual/resync scans (``source="MANUAL_SCAN"``)
    - Enterprise on-demand scans (``source="MANUAL_SCAN"``)
"""

from __future__ import annotations

import datetime
import logging
import time
import uuid
from typing import Any

from deployguard.agent.risk_agent import RiskAssessmentAgent, RiskLevel as AgentRiskLevel
from deployguard.config import settings
from deployguard.core.ast_analyzer import (
    ASTAnalyzer,
    build_cross_file_impact_graph,
    compare_ast_versions,
)
from deployguard.core.comment_renderer import render_pr_comment
from deployguard.core.diff_parser import DiffParser, FileDiff
from deployguard.core.github_client import GitHubClient
from deployguard.core.risk_engine import RiskEvaluationInput, compute_risk_assessment
from deployguard.db.client import MongoDBClient
from deployguard.db.db_operations import BlastRadiusResult, find_similar_incidents, get_blast_radius
from deployguard.exceptions import ASTAnalysisError, GitHubAPIError
from deployguard.models.analysis import AnalysisResult, FileAnalysis, RiskLevel

logger = logging.getLogger(__name__)

_PYTHON_EXTS = {".py", ".python"}


async def persist_or_update_assessment(
    db_client: MongoDBClient | None,
    doc: dict[str, Any],
) -> None:
    """Upsert an assessment record by assessment_id without failing caller."""
    if db_client is None:
        return
    try:
        doc["updated_at"] = datetime.datetime.now(datetime.timezone.utc)
        doc.setdefault("created_at", datetime.datetime.now(datetime.timezone.utc))
        await db_client.assessments.replace_one(
            {"assessment_id": doc["assessment_id"]},
            doc,
            upsert=True,
        )
    except Exception as exc:
        logger.warning("Failed to persist assessment %s: %s", doc.get("assessment_id"), exc)


async def run_pr_analysis(
    *,
    repo_full_name: str,
    pr_number: int,
    source: str = "MANUAL_SCAN",
    github_token: str | None = None,
    db_client: MongoDBClient | None = None,
    agent: RiskAssessmentAgent | None = None,
    owner_email: str | None = None,
    assessment_id: str | None = None,
    policy: dict[str, Any] | None = None,
    post_to_github: bool = True,
    pr_title_hint: str | None = None,
    pr_author_hint: str | None = None,
    head_sha_hint: str | None = None,
    base_sha_hint: str | None = None,
) -> AnalysisResult:
    """
    Execute the complete end-to-end PR analysis pipeline:
      Diff Parse -> Base/Head AST Diff -> Cross-File Dependency Graph ->
      MongoDB Blast Radius -> Deterministic 40/30/20/10 Risk Engine ->
      Optional AI Synthesis -> Persist -> GitHub Check Run & Comment.
    """
    aid = assessment_id or str(uuid.uuid4())
    log_prefix = f"[assessment={aid[:8]}] [{repo_full_name}#{pr_number}]"
    started = time.monotonic()

    result = AnalysisResult(
        assessment_id=aid,
        pr_number=pr_number,
        repo_full_name=repo_full_name,
        head_sha=head_sha_hint or "HEAD",
        source=source,
        status="RUNNING",
        owner_email=owner_email,
    )

    if db_client is not None:
        await persist_or_update_assessment(db_client, result.model_dump())

    try:
        async with GitHubClient(repo_full_name=repo_full_name, token=github_token) as github:
            pr_data = await github.get_pull_request(pr_number)
            pr_title = pr_data.get("title") or pr_title_hint or f"PR #{pr_number}"
            pr_author = (pr_data.get("user") or {}).get("login") or pr_author_hint or "developer"
            head_sha = (pr_data.get("head") or {}).get("sha") or head_sha_hint or "HEAD"
            base_sha = (pr_data.get("base") or {}).get("sha") or base_sha_hint
            additions = int(pr_data.get("additions") or 0)
            deletions = int(pr_data.get("deletions") or 0)

            result.head_sha = head_sha

            raw_diff = ""
            try:
                raw_diff = await github.get_pull_request_diff(pr_number)
            except GitHubAPIError as exc:
                logger.warning("%s Could not fetch diff: %s", log_prefix, exc)

            file_diffs: list[FileDiff] = DiffParser().parse(raw_diff)
            pr_files_meta: list[dict[str, Any]] = []
            if not file_diffs:
                try:
                    pr_files_meta = await github.get_pull_request_files(pr_number)
                except Exception:
                    pr_files_meta = []

            changed_filenames = [fd.filename for fd in file_diffs] or [
                f.get("filename", "") for f in pr_files_meta if f.get("filename")
            ]

            ast_analyzer = ASTAnalyzer()
            file_analyses: list[FileAnalysis] = []
            breaking_changes: list[dict[str, Any]] = []
            head_sources: dict[str, str] = {}
            changed_file_symbols: dict[str, list[str]] = {}
            diff_preview: list[dict[str, str]] = []

            for fd in file_diffs:
                filename = fd.filename
                ext = f".{filename.rsplit('.', 1)[-1].lower()}" if "." in filename else ""
                is_py = ext in _PYTHON_EXTS

                fa = FileAnalysis(
                    filename=filename,
                    language="python" if is_py else ext.lstrip(".") or "unknown",
                    is_ast_eligible=is_py and not fd.is_deleted_file,
                    total_modified_lines=fd.total_modified_lines,
                    modified_hunks=fd.hunks,
                )

                if is_py:
                    head_src: str | None = None
                    base_src: str | None = None

                    if not fd.is_deleted_file:
                        head_src = await github.try_get_file_content(filename, head_sha)
                        if head_src is not None:
                            head_sources[filename] = head_src
                            try:
                                syms = ast_analyzer.analyze(
                                    source_code=head_src,
                                    filename=filename,
                                    modified_lines=fd.all_modified_lines,
                                )
                                fa.affected_symbols = syms
                            except ASTAnalysisError as exc:
                                fa.is_ast_eligible = False
                                fa.parse_error = str(exc)

                    if base_sha and not fd.is_new_file:
                        base_src = await github.try_get_file_content(fd.old_filename, base_sha)

                    if base_src is not None:
                        cmp_res = compare_ast_versions(base_src, head_src, filename)
                        if cmp_res["breaking_changes"]:
                            breaking_changes.extend(cmp_res["breaking_changes"])

                    sym_names = [s.qualified_name for s in fa.affected_symbols] + [
                        bc["symbol"]
                        for bc in breaking_changes
                        if bc.get("file") == filename and bc.get("symbol")
                    ]
                    if sym_names:
                        changed_file_symbols[filename] = list(dict.fromkeys(sym_names))

                file_analyses.append(fa)

            # Extract concise diff preview lines from raw unified diff
            for raw_line in raw_diff.splitlines():
                if raw_line.startswith(("+++ ", "--- ", "diff --git", "index ")):
                    continue
                if raw_line.startswith("+"):
                    diff_preview.append({"type": "add", "text": raw_line[:120]})
                elif raw_line.startswith("-"):
                    diff_preview.append({"type": "del", "text": raw_line[:120]})
                if len(diff_preview) >= 6:
                    break

            # Cross-file dependency analysis across repo Python files (non-fatal)
            if changed_file_symbols and head_sha != "HEAD":
                sibling_paths = await github.get_repo_python_files(head_sha, max_files=8)
                for sp in sibling_paths:
                    if sp not in head_sources:
                        src = await github.try_get_file_content(sp, head_sha)
                        if src:
                            head_sources[sp] = src

            dep_graph = build_cross_file_impact_graph(head_sources, changed_file_symbols)
            ast_duration_ms = (time.monotonic() - started) * 1000

            total_symbols = sum(len(fa.affected_symbols) for fa in file_analyses)
            has_api_changes = any(fa.has_api_changes for fa in file_analyses) or any(
                bc.get("type") in ("REMOVED_ROUTE", "MODIFIED_ROUTE_CONTRACT")
                for bc in breaking_changes
            )

            result.files_analysed = file_analyses
            result.total_affected_symbols = total_symbols
            result.has_api_surface_changes = has_api_changes
            result.analysis_duration_ms = ast_duration_ms
            result.breaking_changes = breaking_changes
            result.dependency_edges = dep_graph["edges"]

            # MongoDB $graphLookup blast radius
            service_name = repo_full_name.split("/")[-1].lower()
            blast_radius = BlastRadiusResult(origin_service=service_name)
            if db_client is not None:
                try:
                    blast_radius = await get_blast_radius(db_client, service_name=service_name)
                except Exception as exc:
                    logger.warning("%s Blast radius lookup skipped: %s", log_prefix, exc)

            graph_svcs = [
                {
                    "service": s.service_name,
                    "service_name": s.service_name,
                    "sla_tier": s.sla_tier,
                    "hops": s.hops,
                    "team": s.owner_team,
                }
                for s in blast_radius.affected_nodes
            ]
            result.blast_radius_summary = {
                "origin_service": blast_radius.origin_service,
                "total_affected": blast_radius.total_affected or len(dep_graph["downstream_consumers"]),
                "has_p0_impact": blast_radius.has_p0_impact,
                "has_p1_impact": blast_radius.has_p1_impact,
                "critical_services": [
                    {
                        "service": s.service_name,
                        "sla_tier": s.sla_tier,
                        "hops": s.hops,
                        "team": s.owner_team,
                    }
                    for s in blast_radius.critical_services
                ],
                "affected_services": list(
                    dict.fromkeys(
                        [s["service_name"] for s in graph_svcs] + dep_graph["downstream_consumers"]
                    )
                )
                or [service_name],
                "max_sla_tier": "P0" if blast_radius.has_p0_impact else ("P1" if blast_radius.has_p1_impact else "P2"),
            }

            # Context bundle
            result.context_bundle = _build_context(
                pr_number=pr_number,
                pr_title=pr_title,
                pr_author=pr_author,
                head_sha=head_sha,
                additions=additions,
                deletions=deletions,
                changed_files=len(changed_filenames),
                file_analyses=file_analyses,
                duration_ms=ast_duration_ms,
                total_symbols=total_symbols,
                has_api_changes=has_api_changes,
            )

            # Historical incident vector search (only if agent & openai API key usable)
            similar_incidents = []
            openai_usable = (
                agent is not None
                and bool(settings.openai_api_key.get_secret_value().strip())
                and not settings.openai_api_key.get_secret_value().startswith("sk-proj-xxx")
            )
            if db_client is not None and openai_usable:
                try:
                    sym_desc = ", ".join(s.qualified_name for fa in file_analyses for s in fa.affected_symbols)
                    emb = await agent.get_embedding(f"PR: {pr_title}. Service: {service_name}. Symbols: {sym_desc}")
                    similar_incidents = await find_similar_incidents(
                        db_client=db_client,
                        query_embedding=emb,
                        affected_service=service_name,
                    )
                except Exception as exc:
                    logger.debug("%s Vector incident search skipped: %s", log_prefix, exc)

            # Resolve tenant policy if available
            active_policy = policy or {}
            if not active_policy and db_client is not None:
                try:
                    pol_query = {"owner_email": owner_email} if owner_email else {"_id": "active_policy"}
                    pdoc = await db_client.db["enterprise_policy"].find_one(pol_query)
                    if pdoc:
                        active_policy = pdoc
                except Exception:
                    pass

            # Deterministic 40/30/20/10 engine ALWAYS executes (eliminates UNKNOWN)
            det = compute_risk_assessment(
                RiskEvaluationInput(
                    repo_full_name=repo_full_name,
                    pr_title=pr_title,
                    changed_filenames=changed_filenames,
                    file_analyses=file_analyses,
                    additions=additions,
                    deletions=deletions,
                    breaking_changes=breaking_changes,
                    dependency_edges=dep_graph["edges"],
                    downstream_consumers=dep_graph["downstream_consumers"],
                    graph_services=graph_svcs,
                    has_p0_impact=blast_radius.has_p0_impact,
                    has_p1_impact=blast_radius.has_p1_impact,
                    similar_incidents=[
                        {"incident_id": i.incident_id, "title": i.title, "similarity_score": i.similarity_score}
                        for i in similar_incidents
                    ],
                    policy=active_policy,
                    diff_preview=diff_preview,
                )
            )

            result.risk_score = det["risk_score"]
            result.risk_level = RiskLevel(det["risk_level"])
            result.is_docs_or_config_only = det["is_docs_or_config_only"]
            result.signal_breakdown = det["signals"]
            result.diff_preview = det["diff_preview"]
            result.agent_assessment = {
                "risk_score": det["risk_score"],
                "risk_level": det["risk_level"],
                "confidence": 0.94,
                "executive_summary": det["plain_explanation"],
                "rationale": det["rationale"],
                "detailed_rationale": det["rationale"],
                "recommended_tests": det["recommended_tests"],
                "deployment_strategy": det["deployment_strategy"],
                "escalation_required": det["escalation_required"],
                "signals": det["signals"],
                "similar_incident_ids": [i.incident_id for i in similar_incidents[:3]],
            }

            # Optional LLM enrichment when OpenAI key is configured and NOT pure docs-only
            if openai_usable and not det["is_docs_or_config_only"]:
                try:
                    ai_res = await agent.assess(
                        pr_title=pr_title,
                        pr_author=pr_author,
                        changed_symbols=result.context_bundle.get("affected_symbols", []),
                        blast_radius=blast_radius,
                        similar_incidents=similar_incidents,
                    )
                    # Blend deterministically: never downgrade breaking removals!
                    blended_score = max(det["risk_score"], ai_res.risk_score) if breaking_changes else round(
                        (det["risk_score"] * 0.6) + (ai_res.risk_score * 0.4)
                    )
                    result.risk_score = max(0, min(100, blended_score))
                    if result.risk_score >= 70 or breaking_changes:
                        result.risk_level = RiskLevel.BLOCK
                    elif result.risk_score >= int(active_policy.get("max_auto_merge_score", 35)) + 1:
                        result.risk_level = RiskLevel.WARN
                    else:
                        result.risk_level = RiskLevel.PASS

                    result.agent_assessment.update({
                        "risk_score": result.risk_score,
                        "risk_level": result.risk_level.value,
                        "confidence": ai_res.confidence,
                        "rationale": ai_res.rationale,
                        "detailed_rationale": ai_res.rationale,
                        "recommended_tests": ai_res.recommended_tests,
                        "deployment_strategy": ai_res.deployment_strategy.value,
                        "escalation_required": ai_res.escalation_required or det["escalation_required"],
                        "similar_incident_ids": ai_res.similar_incident_ids,
                        "ai_enhanced": True,
                    })
                except Exception as exc:
                    logger.info("%s LLM synthesis fallback to deterministic engine: %s", log_prefix, exc)

            result.status = "COMPLETED"
            doc_to_save = result.model_dump()
            doc_to_save.update({
                "pr_title": pr_title,
                "pr_author": pr_author,
                "head_branch": (pr_data.get("head") or {}).get("ref", "feature"),
                "base_branch": (pr_data.get("base") or {}).get("ref", "main"),
                "total_lines_added": additions,
                "total_lines_deleted": deletions,
                "total_files_changed": len(changed_filenames),
                "breaking_changes_count": len(breaking_changes),
                "blast_radius": result.blast_radius_summary,
                "decision": result.risk_level.value,
            })
            await persist_or_update_assessment(db_client, doc_to_save)

            # Stage 9: GitHub Check Run (with status fallback) + Upsert PR Comment
            if post_to_github and head_sha and head_sha != "HEAD":
                conclusion_map = {
                    RiskLevel.PASS: "success",
                    RiskLevel.WARN: "neutral",
                    RiskLevel.BLOCK: "failure",
                }
                conclusion = conclusion_map.get(result.risk_level, "neutral")
                title = f"Risk Score: {result.risk_score}/100 — {result.risk_level.value}"
                comment_md = render_pr_comment(result)
                annotations = [
                    {
                        "path": bc["file"],
                        "start_line": int(bc.get("line") or 1),
                        "end_line": int(bc.get("line") or 1),
                        "annotation_level": "failure",
                        "message": bc.get("detail", "Breaking API/signature change"),
                    }
                    for bc in breaking_changes
                    if bc.get("file")
                ]
                details_url = f"{settings.public_url.rstrip('/')}"
                try:
                    await github.create_check_run(
                        sha=head_sha,
                        conclusion=conclusion,
                        title=title,
                        summary=comment_md,
                        details_url=details_url,
                        annotations=annotations or None,
                    )
                    await github.upsert_pr_comment(pr_number=pr_number, body=comment_md)
                except Exception as exc:
                    logger.warning("%s Non-fatal GitHub write-back skipped: %s", log_prefix, exc)

    except Exception as exc:
        logger.exception("%s Analysis pipeline failed: %s", log_prefix, exc)
        result.status = "FAILED"
        result.error = str(exc)
        await persist_or_update_assessment(db_client, result.model_dump())

    return result


def _build_context(
    *,
    pr_number: int,
    pr_title: str,
    pr_author: str,
    head_sha: str,
    additions: int,
    deletions: int,
    changed_files: int,
    file_analyses: list[FileAnalysis],
    duration_ms: float,
    total_symbols: int,
    has_api_changes: bool,
) -> dict[str, Any]:
    affected_symbols_summary = []
    for fa in file_analyses:
        for sym in fa.affected_symbols:
            entry = {
                "file": fa.filename,
                "symbol": sym.qualified_name,
                "kind": sym.kind.value if hasattr(sym.kind, "value") else str(sym.kind),
                "lines": f"{sym.start_line}-{sym.end_line}",
                "modified_line_count": len(sym.modified_lines_overlap),
            }
            if sym.route_path:
                entry["route"] = f"{','.join(sym.http_methods)} {sym.route_path}"
            affected_symbols_summary.append(entry)

    return {
        "pr": {
            "number": pr_number,
            "title": pr_title,
            "author": pr_author,
            "head_sha": head_sha,
            "additions": additions,
            "deletions": deletions,
            "changed_files": changed_files,
        },
        "analysis_summary": {
            "total_files": len(file_analyses),
            "ast_eligible_files": sum(1 for fa in file_analyses if fa.is_ast_eligible),
            "total_affected_symbols": total_symbols,
            "has_api_surface_changes": has_api_changes,
            "analysis_duration_ms": round(duration_ms, 2),
        },
        "affected_symbols": affected_symbols_summary,
    }
