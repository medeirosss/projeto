from app.services.security_monitoring_service import _ips, _interpret

def test_ips_filters_non_private_and_duplicates():
    snap={'assets':[{'address':'192.168.0.10'},{'address':'192.168.0.10'},{'address':'8.8.8.8'},{'address':'bad'}]}
    assert _ips(snap)==['192.168.0.10']

def test_failure_is_inconclusive():
    assert _interpret('failed',{'hosts':[{'state':'down'}]})=='inconclusive'

def test_host_status_requires_explicit_state():
    assert _interpret('completed',{'hosts':[{'state':'up'}]})=='up'
    assert _interpret('completed',{'hosts':[{'state':'down'}]})=='down'
    assert _interpret('completed',{'hosts':[]})=='inconclusive'
