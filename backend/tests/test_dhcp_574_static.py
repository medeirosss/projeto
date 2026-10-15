from pathlib import Path
root=Path(__file__).resolve().parents[2]
def test_dhcp_scan_requires_authorization_and_verified_lease():
    s=(root/'backend/app/routers/settings.py').read_text()
    assert '/settings/dhcp/scan-now' in s
    assert 'payload.get("authorized") is not True' in s
    assert 'get_runner_job_result' in s
    assert 'address_state' in s
    assert '"leases":md.get("leases") or []' in s
def test_frontend_lease_listing_and_scan_now():
    s=(root/'frontend/settings.js').read_text()
    assert 'loadDhcpLeases' in s and 'scanDhcpLease' in s
    assert 'validation_job_id' in s and 'authorized:true' in s
