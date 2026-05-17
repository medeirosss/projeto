from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Query

from app.services.common import write_text_log
from app.services.dashboard_service import build_dashboard_data
from app.services.data_service import get_ad_records, get_ec_records
from app.services.scanner_service import fetch_endpointcentral_all, run_ad_scan
from app.services.settings_service import get_settings_data

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard")
async def api_dashboard(page_size: int = Query(default=25)):
    settings = get_settings_data()
    data = build_dashboard_data(settings)
    data["summary"]["requested_page_size"] = page_size
    return data


@router.post("/scan/ad")
async def api_scan_ad():
    settings = get_settings_data()
    records, source = run_ad_scan(settings)
    log = write_text_log(
        "ADstatus",
        "\n".join(
            [
                "=== AD STATUS ===",
                f"Timestamp: {datetime.now().isoformat()}",
                f"Source: {source}",
                f"AD total: {len(records)}",
            ]
        ),
    )
    return {"success": True, "total": len(records), "source": source, "log_file": log.name}


@router.post("/scan/endpoint")
async def api_scan_endpoint():
    settings = get_settings_data()
    records, token_source, api_log_name, token_debug_log = fetch_endpointcentral_all(settings)
    return {
        "success": True,
        "total": len(records),
        "token_source": token_source,
        "log_file": api_log_name,
        "token_debug_log": token_debug_log,
    }


@router.post("/scan-now")
async def api_scan_now():
    settings = get_settings_data()
    ad_source = "cache"
    ec_source = "cache"
    token_source = "none"
    api_log_name = ""
    token_debug_log = None
    ad_error = None
    ec_error = None
    try:
        ad_records, ad_source = run_ad_scan(settings)
        ad_log = write_text_log(
            "ADstatus",
            "\n".join(
                [
                    "=== AD STATUS ===",
                    f"Timestamp: {datetime.now().isoformat()}",
                    f"Source: {ad_source}",
                    f"AD total: {len(ad_records)}",
                ]
            ),
        )
    except Exception as exc:
        ad_error = str(exc)
        ad_records = get_ad_records()
        ad_log = write_text_log(
            "ADstatus",
            "\n".join(
                [
                    "=== AD STATUS ERROR ===",
                    f"Timestamp: {datetime.now().isoformat()}",
                    f"Error: {ad_error}",
                    f"Fallback cache total: {len(ad_records)}",
                ]
            ),
        )
    try:
        ec_records, token_source, api_log_name, token_debug_log = fetch_endpointcentral_all(settings)
        ec_source = "api"
    except Exception as exc:
        ec_error = str(exc)
        ec_records = get_ec_records()
        api_log_name = write_text_log(
            "APIstatus",
            "\n".join(
                [
                    "=== ENDPOINT CENTRAL STATUS ERROR ===",
                    f"Timestamp: {datetime.now().isoformat()}",
                    f"Error: {ec_error}",
                    f"Fallback cache total: {len(ec_records)}",
                    "Storage: PostgreSQL scan_snapshots",
                ]
            ),
        ).name
    dashboard = build_dashboard_data(settings)
    dashboard["summary"]["log_file"] = api_log_name or ad_log.name
    if ad_error or ec_error:
        write_text_log(
            "SCANerror",
            "\n".join(
                [
                    f"timestamp={datetime.now().isoformat()}",
                    f"ad_error={ad_error or ''}",
                    f"ec_error={ec_error or ''}",
                    f"token_source={token_source}",
                    f"token_debug_log={token_debug_log or ''}",
                ]
            ),
        )
    return {
        "success": True,
        "message": "Scan executado com sucesso.",
        "ad_total": dashboard["summary"]["ad_count"],
        "ec_total": dashboard["summary"]["ec_count"],
        "log_file": dashboard["summary"]["log_file"],
        "json_file": dashboard["summary"]["json_file"],
        "token_source": token_source,
        "ad_log_file": ad_log.name,
        "token_debug_log": token_debug_log,
        "ad_source": ad_source,
        "ec_source": ec_source,
    }
