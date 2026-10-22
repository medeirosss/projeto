"""MAGI 5.7 path telemetry envelope helpers.
No listener, beacon or persistence is created. Relay bundles travel back over the already-established execution channel.
"""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
ALLOWED={'ENTERED','ACTION_STARTED','ACTION_COMPLETED','EVIDENCE_CREATED','RELAY_STARTED','RELAY_RETURNED','EXITED','FAILED','RETURN_CONFIRMED'}
def event(path_uuid,node_address,event_type,*,parent_address=None,hop=0,technique_key=None,result=None,payload=None):
    kind=str(event_type).upper()
    if kind not in ALLOWED: raise ValueError('invalid path telemetry event')
    safe={k:v for k,v in (payload or {}).items() if k in {'message','reason','evidence_ref','runner_job_id','protocol','latency_ms'}}
    return {'path_uuid':path_uuid,'event_uuid':'EVT-'+uuid.uuid4().hex.upper(),'node_address':node_address,'parent_address':parent_address,'hop':int(hop),'event_type':kind,'technique_key':technique_key,'result':result,'transport':'relay','relay_depth':0,'payload':safe,'event_at':datetime.now(timezone.utc).isoformat()}
def relay(events):
    return {'events':[{**e,'transport':'relay','relay_depth':int(e.get('relay_depth') or 0)+1} for e in events]}
