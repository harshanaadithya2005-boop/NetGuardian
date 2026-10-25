"""Bounded dashboard preview from a validation copy, without hardware workers."""
import os
from pathlib import Path
import sys
import threading
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
os.environ['TARGET_NETWORK']='192.168.8.0/24'
from database import db
db.DB_PATH=max((ROOT/'.test-work').glob('validation_*.db'),key=lambda p:p.stat().st_mtime)
import app
from werkzeug.serving import make_server
server=make_server('127.0.0.1',5052,app.app,threaded=True)
threading.Timer(180,server.shutdown).start()
print('Dashboard preview: http://127.0.0.1:5052',flush=True)
try:
    server.serve_forever()
finally:
    server.server_close()
