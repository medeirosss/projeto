from pathlib import Path

from magi_runner.core.scheduler import redact_sensitive_text
from magi_runner.executors.metasploit import _extract, _normalized_status, _cleanup_kerberos_loot

def test_kerberos_user_found_is_confirmed():
    out = '[+] 192.168.0.100 - User found: "administrator" with password ExampleSecret123. Hash: $krb5asrep$18$administrator@LAB.LOCAL:abc\n[*] Auxiliary module execution completed'
    ev = _extract(out, "MAGI-M-ATK-AD-001", "192.168.0.100")
    assert ev["authentication_confirmed"] is True
    assert _normalized_status("MAGI-M-ATK-AD-001", out, "", 0, ev) == ("success", "SUCCESS")

def test_kerberos_module_completion_without_confirmation_is_not_success():
    out = "[*] Auxiliary module execution completed"
    ev = _extract(out, "MAGI-M-ATK-AD-001", "192.168.0.100")
    assert ev["authentication_confirmed"] is False
    assert _normalized_status("MAGI-M-ATK-AD-001", out, "", 0, ev) == ("success", "AUTHENTICATION_FAILED")

def test_secret_redaction_before_persistence():
    job = {"payload":{"credential":{"secret":"ExampleSecret123"}}}
    raw = 'PASSWORD => ExampleSecret123\n[+] User found: "administrator" with password ExampleSecret123. Hash: $krb5asrep$18$administrator@LAB.LOCAL:abcdef\nCOMMUNITY => privateCommunity\n'
    safe = redact_sensitive_text(raw, job)
    assert "ExampleSecret123" not in safe
    assert "$krb5asrep$" not in safe
    assert "PASSWORD => ********" in safe
    assert "with password ********" in safe
    assert "[REDACTED_KERBEROS_MATERIAL]" in safe
    assert "privateCommunity" not in safe

def test_kerberos_loot_cleanup(tmp_path):
    loot = tmp_path / "ticket.bin"
    loot.write_bytes(b"credential material")
    out = f"[*] TGT MIT Credential Cache ticket saved to {loot}\n"
    result = _cleanup_kerberos_loot(out)
    assert result["required"] is True
    assert result["attempted"] is True
    assert result["success"] is True
    assert not loot.exists()
