from magi_runner.executors.service_discovery import _parse_nbtstat_name, _parse_smb_os_name

def test_parse_nbtstat_workstation_name():
    raw='''NetBIOS Remote Machine Name Table\n    WIN-TEST       <00>  UNIQUE      Registered\n    LAB            <00>  GROUP       Registered\n'''
    assert _parse_nbtstat_name(raw) == 'WIN-TEST'

def test_parse_smb_os_discovery_xml():
    xml='''<?xml version="1.0"?><nmaprun><host><hostscript><script id="smb-os-discovery" output="OS: Windows\nComputer name: PC153\nDomain name: lab.local\nFQDN: PC153.lab.local"><table><elem key="Computer name">PC153</elem><elem key="Domain name">lab.local</elem><elem key="FQDN">PC153.lab.local</elem></table></script></hostscript></host></nmaprun>'''
    out=_parse_smb_os_name(xml)
    assert out['hostname']=='PC153'
    assert out['fqdn']=='PC153.lab.local'
    assert out['domain']=='lab.local'
    assert out['source']=='smb_os_discovery'
