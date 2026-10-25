"""Read-only incident evidence; authentication POSTs only, no configuration POSTs."""
from pathlib import Path
from contextlib import closing
from datetime import datetime
import sys, sqlite3, json
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from database import db
from response import router_quarantine as service
from router.mac_filter import FilterSnapshot

def main():
    root=Path(__file__).resolve().parents[1]
    evidence=root/'.test-work'/('identity-incident-'+datetime.now().strftime('%Y%m%d-%H%M%S'))
    evidence.mkdir(parents=True)
    source=Path(db.DB_PATH).resolve()
    with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as conn:
        conn.row_factory=sqlite3.Row
        with closing(sqlite3.connect(evidence/'production-backup.db')) as backup:conn.backup(backup)
        devices=[dict(r) for r in conn.execute('SELECT * FROM devices')]
        plans=[dict(r) for r in conn.execute('SELECT id,device_id,mac_address,action,before_xml,after_xml,ownership_json,expires_at,consumed,control_channel FROM router_quarantine_plans ORDER BY rowid')]
        audit=[dict(r) for r in conn.execute('SELECT device_id,mac_address,action,state,message,details_json,timestamp FROM router_quarantine_audit ORDER BY id')]
        managed=[dict(r) for r in conn.execute('SELECT device_id,mac_address,state,ownership_json,error_code,message FROM router_quarantines')]
    report=dict(devices=devices,plans=plans,audit=audit,managed=managed)
    client=service.new_client()
    request=client.session.request
    def read_only(method,url,**kwargs):
        from urllib.parse import urlsplit
        path=urlsplit(url).path
        if method.upper()!='GET' and not (method.upper()=='POST' and path in {'/api/user/challenge_login','/api/user/authentication_login'}):
            raise AssertionError('Read-only evidence collection forbids configuration writes')
        return request(method,url,**kwargs)
    client.session.request=read_only
    try:
        capabilities,snapshot=client.probe_quarantine_capabilities()
        report['router']=dict(capabilities=capabilities,clients=client.get_connected_wifi_devices())
        (evidence/'router-filters.xml').write_text(snapshot.xml(),encoding='utf-8')
    except Exception as error:
        report['router_error']=service._safe_error(error).code
    finally:client.close()
    (evidence/'evidence.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print('Evidence folder:',evidence)
    print('Devices:',json.dumps(devices))
    print('Managed:',json.dumps(managed))
    for p in plans:
        print('Plan:',json.dumps({k:p[k] for k in ('device_id','mac_address','action','consumed','control_channel')}),FilterSnapshot(p['after_xml']).summary())
    print('Audit:',json.dumps([{k:r[k] for k in ('device_id','mac_address','action','state','message','timestamp')} for r in audit]))
    print('Router:',json.dumps(report.get('router',report.get('router_error'))))

if __name__=='__main__':main()
