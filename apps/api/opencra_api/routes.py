from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from opencra_shared.clocks import CaseStatus, CaseType, compute_clocks
from opencra_shared.vex import (
    VexStatus,
    can_dismiss_case,
    parse_openvex,
    serialize_openvex,
)
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from opencra_api.audit import append_event
from opencra_api.auth import Principal, get_principal, require_tier
from opencra_api.db import get_db
from opencra_api.notify import notify_deadline
from opencra_api.orm import (
    AuditEvent,
    CraCase,
    Organization,
    Product,
    Sbom,
    Subscription,
    VexRow,
    VulnMatchRow,
)
from opencra_api.pdf_audit import render_audit_pdf_or_html
from opencra_api.srp import build_packet, get_adapter

router = APIRouter()


class ProductIn(BaseModel):
    name: str
    version: str | None = None
    market_member_states: list[str] = Field(default_factory=list)


class CasePatch(BaseModel):
    acknowledge: bool = False
    awareness_at: datetime | None = None
    fix_available_at: datetime | None = None
    stage_submitted: str | None = None
    srp_reference_id: str | None = None
    exploit_nature: str | None = None
    sensitivity: str | None = None
    corrective_measures: str | None = None
    dismiss_override: bool = False


class IngestBody(BaseModel):
    target: str
    scanned_at: datetime | None = None
    sbom: dict[str, Any]
    matches: list[dict[str, Any]] = Field(default_factory=list)
    product_id: str | None = None
    product_name: str | None = None
    git_sha: str | None = None


@router.get("/health")
def health() -> dict:
    return {"ok": True, "service": "crashield"}


@router.get("/me")
def me(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> dict:
    org = db.get(Organization, principal.org_id)
    sub = db.query(Subscription).filter(Subscription.org_id == principal.org_id).one_or_none()
    return {
        "user_id": principal.user_id,
        "org_id": principal.org_id,
        "role": principal.role,
        "tier": principal.tier,
        "org": {"name": org.name if org else None, "sso_enabled": org.sso_enabled if org else False},
        "subscription": {
            "tier": sub.tier if sub else "community",
            "product_limit": sub.product_limit if sub else 1,
            "seat_limit": sub.seat_limit if sub else 1,
        },
    }


@router.get("/products")
def list_products(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(Product).filter(Product.org_id == principal.org_id).all()
    return [_product_out(p) for p in rows]


@router.post("/products")
def create_product(
    body: ProductIn,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> dict:
    sub = db.query(Subscription).filter(Subscription.org_id == principal.org_id).one_or_none()
    count = db.query(Product).filter(Product.org_id == principal.org_id).count()
    limit = sub.product_limit if sub else 1
    if count >= limit:
        raise HTTPException(402, f"Product limit ({limit}) reached for tier {principal.tier}")
    product = Product(
        org_id=principal.org_id,
        name=body.name,
        version=body.version,
        market_member_states=body.market_member_states,
    )
    db.add(product)
    db.commit()
    db.refresh(product)
    return _product_out(product)


@router.post("/v1/ingest")
def ingest(
    body: IngestBody,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> dict:
    product = None
    if body.product_id:
        product = (
            db.query(Product)
            .filter(Product.id == body.product_id, Product.org_id == principal.org_id)
            .one_or_none()
        )
    if product is None:
        name = body.product_name or (body.sbom.get("metadata") or {}).get("component", {}).get("name") or body.target
        product = (
            db.query(Product)
            .filter(Product.org_id == principal.org_id, Product.name == name)
            .one_or_none()
        )
        if product is None:
            product = Product(org_id=principal.org_id, name=name)
            db.add(product)
            db.flush()

    serial = body.sbom.get("serial_number") or body.sbom.get("serialNumber")
    sbom = Sbom(
        product_id=product.id,
        org_id=principal.org_id,
        document=body.sbom,
        git_sha=body.git_sha,
        source="cli",
        serial_number=serial,
    )
    db.add(sbom)
    db.flush()

    created_cases = 0
    candidate_ids: list[str] = []
    for raw in body.matches:
        match = VulnMatchRow(
            org_id=principal.org_id,
            product_id=product.id,
            purl=raw.get("purl") or "unknown",
            osv_id=raw.get("osv_id"),
            cve_id=raw.get("cve_id"),
            severity=raw.get("severity"),
            cvss_v3=raw.get("cvss_v3"),
            epss=raw.get("epss"),
            in_kev=bool(raw.get("in_kev")),
            summary=raw.get("summary"),
            vex_status=raw.get("vex_status"),
        )
        db.add(match)
        db.flush()
        if match.in_kev:
            case = CraCase(
                org_id=principal.org_id,
                product_id=product.id,
                match_id=match.id,
                case_type=CaseType.ACTIVELY_EXPLOITED_VULN.value,
                status=CaseStatus.CANDIDATE.value,
            )
            db.add(case)
            db.flush()
            candidate_ids.append(case.id)
            created_cases += 1
            notify_deadline(
                f"CRA candidate on {product.name}: {match.cve_id or match.osv_id}. "
                "Acknowledge awareness to start the 24-hour clock."
            )

    append_event(
        db,
        org_id=principal.org_id,
        actor_id=principal.user_id,
        action="ingest",
        payload={"product_id": product.id, "matches": len(body.matches), "cases": created_cases},
    )
    db.commit()
    return {
        "ok": True,
        "product_id": product.id,
        "sbom_id": sbom.id,
        "candidates": created_cases,
        "case_ids": candidate_ids,
    }


@router.get("/matches")
def list_matches(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> list[dict]:
    rows = (
        db.query(VulnMatchRow)
        .filter(VulnMatchRow.org_id == principal.org_id)
        .order_by(VulnMatchRow.created_at.desc())
        .all()
    )
    return [
        {
            "id": m.id,
            "purl": m.purl,
            "cve_id": m.cve_id,
            "osv_id": m.osv_id,
            "severity": m.severity,
            "in_kev": m.in_kev,
            "status": m.status,
            "vex_status": m.vex_status,
            "summary": m.summary,
            "product_id": m.product_id,
        }
        for m in rows
    ]


@router.get("/cases")
def list_cases(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.query(CraCase).filter(CraCase.org_id == principal.org_id).all()
    return [_case_out(c) for c in rows]


@router.patch("/cases/{case_id}")
def patch_case(
    case_id: str,
    body: CasePatch,
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> dict:
    case = (
        db.query(CraCase)
        .filter(CraCase.id == case_id, CraCase.org_id == principal.org_id)
        .one_or_none()
    )
    if case is None:
        raise HTTPException(404, "Case not found")

    if body.exploit_nature is not None:
        case.exploit_nature = body.exploit_nature
    if body.sensitivity is not None:
        case.sensitivity = body.sensitivity
    if body.corrective_measures is not None:
        case.corrective_measures = body.corrective_measures
    if body.srp_reference_id is not None:
        case.srp_reference_id = body.srp_reference_id
    if body.fix_available_at is not None:
        case.fix_available_at = body.fix_available_at
        if case.status == CaseStatus.NOTIFICATION_SUBMITTED.value:
            case.status = CaseStatus.AWAITING_FIX.value

    if body.acknowledge:
        if case.awareness_at is None:
            case.awareness_at = body.awareness_at or datetime.now(timezone.utc)
        case.status = CaseStatus.ACKNOWLEDGED.value
        append_event(
            db,
            org_id=principal.org_id,
            actor_id=principal.user_id,
            action="acknowledge",
            payload={"case_id": case.id, "awareness_at": case.awareness_at.isoformat()},
            case_id=case.id,
        )
        notify_deadline(f"Awareness set for case {case.id}. 24-hour early warning clock started.")

    if body.stage_submitted:
        now = datetime.now(timezone.utc)
        stage = body.stage_submitted
        if stage == "early_warning":
            case.early_warning_submitted_at = now
            case.status = CaseStatus.EARLY_WARNING_SUBMITTED.value
        elif stage == "notification":
            case.notification_submitted_at = now
            case.status = CaseStatus.NOTIFICATION_SUBMITTED.value
        elif stage == "final":
            case.final_submitted_at = now
            case.status = CaseStatus.FINAL_SUBMITTED.value
        else:
            raise HTTPException(400, "stage_submitted must be early_warning, notification, or final")
        append_event(
            db,
            org_id=principal.org_id,
            actor_id=principal.user_id,
            action=f"submit_{stage}",
            payload={"case_id": case.id, "srp_reference_id": case.srp_reference_id},
            case_id=case.id,
        )

    db.commit()
    db.refresh(case)
    return _case_out(case)


@router.get("/cases/{case_id}/srp/{stage}")
def srp_packet(
    case_id: str,
    stage: str,
    principal: Principal = Depends(require_tier("pro_plus", "enterprise")),
    db: Session = Depends(get_db),
) -> dict:
    case, product, org = _load_case(db, case_id, principal.org_id)
    packet = build_packet(org, product, case, stage)
    adapter = get_adapter()
    hint = adapter.submit(packet)
    return {**packet.model_dump(), "adapter": hint.model_dump()}


@router.get("/products/{product_id}/audit-report")
def audit_report(
    product_id: str,
    principal: Principal = Depends(require_tier("pro", "pro_plus", "enterprise")),
    db: Session = Depends(get_db),
) -> Response:
    product = (
        db.query(Product)
        .filter(Product.id == product_id, Product.org_id == principal.org_id)
        .one_or_none()
    )
    if product is None:
        raise HTTPException(404, "Product not found")
    org = db.get(Organization, principal.org_id)
    if org is None:
        raise HTTPException(404, "Organization not found")
    sboms = db.query(Sbom).filter(Sbom.product_id == product_id).all()
    matches = db.query(VulnMatchRow).filter(VulnMatchRow.product_id == product_id).all()
    cases = db.query(CraCase).filter(CraCase.product_id == product_id).all()
    events = (
        db.query(AuditEvent)
        .filter(AuditEvent.org_id == principal.org_id)
        .order_by(AuditEvent.created_at.asc())
        .limit(50)
        .all()
    )
    data, media = render_audit_pdf_or_html(org, product, sboms, matches, cases, events)
    filename = "cra-audit-report.pdf" if media == "application/pdf" else "cra-audit-report.html"
    return Response(
        content=data,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/audit")
def list_audit(
    principal: Principal = Depends(require_tier("pro", "pro_plus", "enterprise")),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = (
        db.query(AuditEvent)
        .filter(AuditEvent.org_id == principal.org_id)
        .order_by(AuditEvent.created_at.asc())
        .all()
    )
    return [
        {
            "id": e.id,
            "action": e.action,
            "actor_id": e.actor_id,
            "payload": e.payload,
            "prev_hash": e.prev_hash,
            "event_hash": e.event_hash,
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "case_id": e.case_id,
        }
        for e in rows
    ]


@router.get("/audit/export")
def export_audit(
    principal: Principal = Depends(require_tier("enterprise")),
    db: Session = Depends(get_db),
) -> dict:
    rows = (
        db.query(AuditEvent)
        .filter(AuditEvent.org_id == principal.org_id)
        .order_by(AuditEvent.created_at.asc())
        .all()
    )
    return {
        "org_id": principal.org_id,
        "events": [
            {
                "action": e.action,
                "actor_id": e.actor_id,
                "payload": e.payload,
                "prev_hash": e.prev_hash,
                "event_hash": e.event_hash,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in rows
        ],
    }


@router.post("/vex")
def import_vex(
    document: dict[str, Any],
    product_id: str | None = None,
    override: bool = False,
    principal: Principal = Depends(require_tier("pro_plus", "enterprise")),
    db: Session = Depends(get_db),
) -> dict:
    parsed = parse_openvex(document)
    row = VexRow(org_id=principal.org_id, product_id=product_id, document=serialize_openvex(parsed))
    db.add(row)

    applied = 0
    blocked = 0
    for statement in parsed.statements:
        if statement.status is not VexStatus.NOT_AFFECTED:
            continue
        vuln_name = statement.vulnerability.name
        matches = (
            db.query(VulnMatchRow)
            .filter(VulnMatchRow.org_id == principal.org_id, VulnMatchRow.cve_id == vuln_name)
            .all()
        )
        for match in matches:
            match.vex_status = statement.status.value
            match.status = "suppressed"
            cases = db.query(CraCase).filter(CraCase.match_id == match.id).all()
            for case in cases:
                result = can_dismiss_case(CaseStatus(case.status))
                if result.applied or (result.requires_override and override):
                    if result.requires_override and override and principal.role not in {
                        "owner",
                        "admin",
                        "compliance_officer",
                    }:
                        blocked += 1
                        continue
                    case.status = CaseStatus.DISMISSED.value
                    applied += 1
                    append_event(
                        db,
                        org_id=principal.org_id,
                        actor_id=principal.user_id,
                        action="vex_dismiss",
                        payload={"case_id": case.id, "override": override, "vulnerability": vuln_name},
                        case_id=case.id,
                    )
                else:
                    blocked += 1
    db.commit()
    return {"ok": True, "applied": applied, "blocked": blocked, "vex_id": row.id}


@router.get("/vex")
def list_vex(
    principal: Principal = Depends(require_tier("pro_plus", "enterprise")),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = db.query(VexRow).filter(VexRow.org_id == principal.org_id).all()
    return [{"id": r.id, "product_id": r.product_id, "document": r.document} for r in rows]


@router.get("/org/sso")
def sso_status(
    principal: Principal = Depends(require_tier("enterprise")),
    db: Session = Depends(get_db),
) -> dict:
    org = db.get(Organization, principal.org_id)
    return {
        "sso_enabled": bool(org and org.sso_enabled),
        "provider": "supabase_saml_oidc",
        "instructions": (
            "Configure SAML/OIDC on the Supabase project and set organizations.sso_enabled. "
            "CRA-Shield does not store IdP secrets in this API."
        ),
    }


@router.post("/org/sso")
def enable_sso(
    enabled: bool = True,
    principal: Principal = Depends(require_tier("enterprise")),
    db: Session = Depends(get_db),
) -> dict:
    if principal.role not in {"owner", "admin"}:
        raise HTTPException(403, "Only owner/admin can toggle SSO")
    org = db.get(Organization, principal.org_id)
    if org is None:
        raise HTTPException(404, "Organization not found")
    org.sso_enabled = enabled
    db.commit()
    return {"sso_enabled": org.sso_enabled}


def _load_case(db: Session, case_id: str, org_id: str) -> tuple[CraCase, Product, Organization]:
    case = db.query(CraCase).filter(CraCase.id == case_id, CraCase.org_id == org_id).one_or_none()
    if case is None:
        raise HTTPException(404, "Case not found")
    product = db.get(Product, case.product_id)
    org = db.get(Organization, org_id)
    if product is None or org is None:
        raise HTTPException(404, "Missing product or organization")
    return case, product, org


def _product_out(product: Product) -> dict:
    return {
        "id": product.id,
        "name": product.name,
        "version": product.version,
        "market_member_states": product.market_member_states,
    }


def _case_out(case: CraCase) -> dict:
    clocks = compute_clocks(
        CaseType(case.case_type),
        awareness_at=case.awareness_at,
        fix_available_at=case.fix_available_at,
        notification_submitted_at=case.notification_submitted_at,
        early_warning_submitted=case.early_warning_submitted_at is not None,
        notification_submitted=case.notification_submitted_at is not None,
        final_submitted=case.final_submitted_at is not None,
    )
    status = case.status
    if clocks.overdue:
        if "early_warning" in clocks.overdue and case.early_warning_submitted_at is None:
            status = CaseStatus.OVERDUE_EARLY_WARNING.value
        elif "notification" in clocks.overdue and case.notification_submitted_at is None:
            status = CaseStatus.OVERDUE_NOTIFICATION.value
        elif "final_report" in clocks.overdue and case.final_submitted_at is None:
            status = CaseStatus.OVERDUE_FINAL.value
    return {
        "id": case.id,
        "product_id": case.product_id,
        "match_id": case.match_id,
        "case_type": case.case_type,
        "status": status,
        "awareness_at": case.awareness_at.isoformat() if case.awareness_at else None,
        "fix_available_at": case.fix_available_at.isoformat() if case.fix_available_at else None,
        "early_warning_due_at": (
            clocks.early_warning_due_at.isoformat() if clocks.early_warning_due_at else None
        ),
        "notification_due_at": (
            clocks.notification_due_at.isoformat() if clocks.notification_due_at else None
        ),
        "final_report_due_at": (
            clocks.final_report_due_at.isoformat() if clocks.final_report_due_at else None
        ),
        "overdue": clocks.overdue,
        "srp_reference_id": case.srp_reference_id,
        "exploit_nature": case.exploit_nature,
        "sensitivity": case.sensitivity,
        "corrective_measures": case.corrective_measures,
    }
