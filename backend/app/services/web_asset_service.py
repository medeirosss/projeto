from __future__ import annotations
import json, socket, ssl, uuid
from urllib.parse import urlsplit, urlunsplit
import requests
from sqlalchemy import text
from app.database.connection import SessionLocal

def normalize_url(raw:str):
    p=urlsplit((raw or '').strip())
    if p.scheme.lower() not in {'http','https'} or not p.hostname: raise ValueError('Informe uma URL HTTP ou HTTPS válida.')
    scheme=p.scheme.lower(); port=p.port or (443 if scheme=='https' else 80); path=p.path or '/'
    netloc=p.hostname.lower() + (f':{port}' if port not in {80,443} else '')
    return urlunsplit((scheme,netloc,path,p.query,'')),scheme,p.hostname.lower(),port,path

def probe(raw:str):
    normalized,scheme,host,port,path=normalize_url(raw)
    addresses=[]
    try:
        for x in socket.getaddrinfo(host,port,socket.AF_INET,socket.SOCK_STREAM):
            ip=x[4][0]
            if ip not in addresses: addresses.append(ip)
    except Exception as exc: return {'status':'dns_failed','normalized_url':normalized,'scheme':scheme,'hostname':host,'port':port,'base_path':path,'addresses':[],'details':{'error':str(exc)}}
    try:
        r=requests.get(normalized,timeout=(4,10),allow_redirects=True,stream=True,headers={'User-Agent':'MAGI-Web-Discovery/5.6.3'})
        headers={k:v for k,v in r.headers.items()}
        fp={'server':headers.get('Server'),'content_type':headers.get('Content-Type'),'final_url':r.url,'redirects':[{'status':h.status_code,'url':h.url} for h in r.history],
            'security_headers':{h:headers.get(h) for h in ['Strict-Transport-Security','Content-Security-Policy','X-Content-Type-Options','X-Frame-Options','Referrer-Policy','Permissions-Policy']}}
        return {'status':'reachable','http_status':r.status_code,'normalized_url':normalized,'scheme':scheme,'hostname':host,'port':port,'base_path':path,'addresses':addresses,'headers':headers,'fingerprint':fp,'details':{'reachable':True}}
    except requests.RequestException as exc:
        return {'status':'unreachable','normalized_url':normalized,'scheme':scheme,'hostname':host,'port':port,'base_path':path,'addresses':addresses,'details':{'error':str(exc)}}

def list_assets():
    with SessionLocal() as db:
        rows=db.execute(text('SELECT * FROM web_assets WHERE active=TRUE ORDER BY name')).mappings().all()
        return [dict(x) for x in rows]

def create_asset(name,url):
    p=probe(url); wid='WEB-'+uuid.uuid4().hex[:12].upper()
    with SessionLocal() as db:
        row=db.execute(text("""INSERT INTO web_assets(web_uuid,name,original_url,normalized_url,scheme,hostname,port,base_path,status,http_status,resolved_addresses,response_headers,fingerprint,last_seen_at,last_scan_at,last_scan_status,last_scan_details)
        VALUES(:w,:n,:o,:u,:s,:h,:p,:b,:st,:hs,CAST(:a AS jsonb),CAST(:rh AS jsonb),CAST(:f AS jsonb),CASE WHEN :st='reachable' THEN CURRENT_TIMESTAMP END,CURRENT_TIMESTAMP,:st,CAST(:d AS jsonb)) RETURNING *"""),
        {'w':wid,'n':name or p['hostname'],'o':url,'u':p['normalized_url'],'s':p['scheme'],'h':p['hostname'],'p':p['port'],'b':p['base_path'],'st':p['status'],'hs':p.get('http_status'),'a':json.dumps(p.get('addresses',[])),'rh':json.dumps(p.get('headers',{})),'f':json.dumps(p.get('fingerprint',{})),'d':json.dumps(p.get('details',{}))}).mappings().first(); db.commit(); return dict(row)

def rescan(web_uuid):
    with SessionLocal() as db:
        a=db.execute(text('SELECT * FROM web_assets WHERE web_uuid=:w AND active=TRUE'),{'w':web_uuid}).mappings().first()
        if not a: raise ValueError('Web Asset não encontrado.')
        p=probe(a['original_url'])
        db.execute(text("""UPDATE web_assets SET normalized_url=:u,scheme=:s,hostname=:h,port=:p,base_path=:b,status=:st,http_status=:hs,resolved_addresses=CAST(:a AS jsonb),response_headers=CAST(:rh AS jsonb),fingerprint=CAST(:f AS jsonb),last_seen_at=CASE WHEN :st='reachable' THEN CURRENT_TIMESTAMP ELSE last_seen_at END,last_scan_at=CURRENT_TIMESTAMP,last_scan_status=:st,last_scan_details=CAST(:d AS jsonb),updated_at=CURRENT_TIMESTAMP WHERE id=:id"""),{'id':a['id'],'u':p['normalized_url'],'s':p['scheme'],'h':p['hostname'],'p':p['port'],'b':p['base_path'],'st':p['status'],'hs':p.get('http_status'),'a':json.dumps(p.get('addresses',[])),'rh':json.dumps(p.get('headers',{})),'f':json.dumps(p.get('fingerprint',{})),'d':json.dumps(p.get('details',{}))})
        db.execute(text("INSERT INTO web_asset_scan_history(web_asset_id,status,http_status,resolved_addresses,response_headers,details) VALUES(:id,:st,:hs,CAST(:a AS jsonb),CAST(:rh AS jsonb),CAST(:d AS jsonb))"),{'id':a['id'],'st':p['status'],'hs':p.get('http_status'),'a':json.dumps(p.get('addresses',[])),'rh':json.dumps(p.get('headers',{})),'d':json.dumps(p)})
        db.commit(); return {'web_uuid':web_uuid,**p}
