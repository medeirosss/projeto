import pytest
from magi_runner.executors.metasploit import _application_url

def test_s3_website_url():
    u=_application_url("http://ad360centric.s3-website-us-east-1.amazonaws.com/")
    assert u["host"]=="ad360centric.s3-website-us-east-1.amazonaws.com"
    assert u["port"]==80
    assert u["path"]=="/"
    assert u["ssl"] is False
    assert u["scheme"]=="http"

def test_https_custom_port_and_path():
    u=_application_url("https://app.example.com:8443/admin/login?mode=test")
    assert u["host"]=="app.example.com"
    assert u["port"]==8443
    assert u["path"]=="/admin/login?mode=test"
    assert u["ssl"] is True

@pytest.mark.parametrize("value",[
    "ftp://example.com/",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "https://user:pass@example.com/",
    "https://example.com/path#fragment",
])
def test_unsupported_or_unsafe_url_rejected(value):
    with pytest.raises(ValueError):
        _application_url(value)
