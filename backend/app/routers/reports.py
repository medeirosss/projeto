from __future__ import annotations

import csv
import io
from typing import Any, Dict, List, Set

from fastapi import APIRouter, Body, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from app.repositories.reports_repository import (
    get_report_file_hostnames,
    list_report_files,
    save_report_file,
)
from app.services.dashboard_service import (
    build_active_users_rows,
    build_scan_compare,
    read_csv_hostnames_from_bytes,
)
from app.services.alert_service import report_mitre_map, report_nist_map

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("/active-users")
async def api_reports_active_users():
    return {
        "notice": "O usuário mostrado no relatório foi identificado no último contato do agente.",
        "latest_json": "PostgreSQL",
        "rows": build_active_users_rows(),
    }


@router.get("/scans/compare-files")
async def api_reports_scans_compare_files():
    """List CSV sources stored in PostgreSQL.

    The endpoint name is preserved for frontend compatibility. Clean v2 no longer
    treats the compare folder as official source for report inputs.
    """
    return {"files": list_report_files()}


@router.post("/scans/upload")
async def api_reports_scans_upload(
    files: List[UploadFile] = File(...),
    labels: List[str] = Form(...),
):
    if len(files) != len(labels):
        raise HTTPException(status_code=400, detail="A quantidade de arquivos e labels deve ser a mesma.")
    csv_sources: Dict[str, Set[str]] = {}
    for index, file in enumerate(files):
        label = labels[index].strip()
        if not label:
            raise HTTPException(status_code=400, detail="Todos os CSVs precisam de um nome de identificação.")
        content = await file.read()
        try:
            hostnames = read_csv_hostnames_from_bytes(content)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        save_report_file(file.filename or f"upload_{index + 1}.csv", label, content, hostnames)
        csv_sources[label] = hostnames
    rows = build_scan_compare(csv_sources)
    return {"report_name": "Scans", "total": len(rows), "rows": rows, "summary": "Compare concluído e salvo no PostgreSQL."}


@router.post("/scans/from-folder")
async def api_reports_scans_from_folder(payload: Dict[str, Any] = Body(...)):
    """Compare using CSV sources already stored in PostgreSQL.

    The route name remains /from-folder only to avoid changing the current frontend.
    """
    items = payload.get("files", [])
    if not items:
        raise HTTPException(status_code=400, detail="Nenhum arquivo informado.")
    csv_sources: Dict[str, Set[str]] = {}
    for item in items:
        file_name = str(item.get("file_name", "")).strip()
        label = str(item.get("label", "")).strip()
        if not file_name or not label:
            raise HTTPException(status_code=400, detail="Arquivo e label são obrigatórios.")
        try:
            csv_sources[label] = get_report_file_hostnames(file_name)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
    rows = build_scan_compare(csv_sources)
    return {"report_name": "Scans", "total": len(rows), "rows": rows, "summary": "Compare concluído a partir dos CSVs armazenados no PostgreSQL."}


@router.post("/scans/export")
async def api_reports_scans_export(rows: List[Dict[str, Any]] = Body(...)):
    if not rows:
        raise HTTPException(status_code=400, detail="Nenhum dado para exportar.")
    buffer = io.StringIO()
    writer = csv.DictWriter(
        buffer,
        fieldnames=["hostname", "presente_em", "ausente_em", "no_ad", "no_uem"],
    )
    writer.writeheader()
    for row in rows:
        writer.writerow({
            "hostname": row.get("hostname", ""),
            "presente_em": row.get("presente_em") or ", ".join(row.get("present_in") or []),
            "ausente_em": row.get("ausente_em") or ", ".join(row.get("missing_in") or []),
            "no_ad": row.get("no_ad", False),
            "no_uem": row.get("no_uem", False),
        })
    content = buffer.getvalue().encode("utf-8-sig")
    return StreamingResponse(
        io.BytesIO(content),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=scan_compare_result.csv"},
    )


@router.get("/mitre-map")
async def api_reports_mitre_map():
    rows = report_mitre_map()
    return {"rows": rows, "total": sum(int(r.get("count") or 0) for r in rows)}


@router.get("/nist-map")
async def api_reports_nist_map():
    rows = report_nist_map()
    return {"rows": rows, "total": sum(int(r.get("count") or 0) for r in rows)}
