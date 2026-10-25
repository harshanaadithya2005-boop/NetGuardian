"""Bounded HTTP/hardware smoke check on a disposable copy of project data."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--hardware',action='store_true')
    parser.add_argument('--seconds',type=int,default=10)
    args=parser.parse_args()
    from database import db
    import config
    work=ROOT/'.test-work'
    work.mkdir(exist_ok=True)
    target=work/('validation_'+str(time.time_ns())+'.db')
    source=sqlite3.connect(f'file:{db.DB_PATH.as_posix()}?mode=ro',uri=True)
    dest=sqlite3.connect(target)
    try:
        tables=[r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'sqlite_sequence'")]
        source.backup(dest)
        before={t:dest.execute('SELECT COUNT(*) FROM "'+t+'"').fetchone()[0] for t in tables}
    finally:
        source.close();dest.close()
    db.DB_PATH=target
    config.DATABASE_PATH=target
    db.initialize_database()
    conn=db.get_connection()
    try:
        after={t:conn.execute('SELECT COUNT(*) FROM "'+t+'"').fetchone()[0] for t in tables}
        assert before==after, 'Migration changed existing row counts'
        assert conn.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        assert not conn.execute('PRAGMA foreign_key_check').fetchall()
    finally:
        conn.close()
    import app as web
    from werkzeug.serving import make_server
    import requests
    server=None
    thread=None
    result={'database_copy':str(target),'existing_row_counts_preserved':True,'tables_checked':len(tables),'http':{}}
    try:
        if args.hardware:
            web.startup_initialization()
            web.startup_initialization() # Must be idempotent.
        server=make_server('127.0.0.1',0,web.app,threaded=True)
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        session=requests.Session()
        session.trust_env=False
        base=f'http://127.0.0.1:{server.server_port}'
        for route in ['/', '/devices','/alerts','/analytics','/reports','/api/health','/api/analytics','/api/devices','/api/alerts','/api/traffic']:
            response=session.get(base+route,timeout=30)
            result['http'][route]=response.status_code
            assert response.status_code==200, route
        time.sleep(args.seconds)
        result['health']=session.get(base+'/api/health',timeout=10).json()
        result['devices_visible']=len(session.get(base+'/api/devices',timeout=10).json())
        session.close()
    finally:
        web.shutdown_engine()
        if server:
            server.shutdown();server.server_close()
        if thread:
            thread.join(timeout=3)
    result['capture_stopped']=not __import__('capture.packet_capture',fromlist=['is_capturing']).is_capturing()
    (work/'validation-result.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))

if __name__=='__main__':
    main()
