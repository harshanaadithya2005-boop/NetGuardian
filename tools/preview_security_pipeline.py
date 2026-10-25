"""Isolated browser validation; preserves the real incident lock, forbids router I/O."""
from pathlib import Path
from contextlib import closing
import sys,tempfile,threading,sqlite3,secrets
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import config
from database import db
from werkzeug.security import generate_password_hash
root=Path(__file__).resolve().parents[1]
work=root/'.test-work';work.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(dir=work) as temp:
    source=Path(db.DB_PATH).resolve();target=Path(temp)/'preview.db'
    with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as original,closing(sqlite3.connect(target)) as copy:original.backup(copy)
    db.DB_PATH=target;db.initialize_database()
    config.VIVA_DATABASE_PATH=Path(temp)/'viva.db'
    config.ADMIN_PASSWORD_HASH=generate_password_hash('ui-preview-only-password')
    config.SECRET_KEY=secrets.token_hex(32)
    import requests
    original_request=requests.sessions.Session.request
    def reject_router(session,method,url,**kwargs):
        from urllib.parse import urlsplit
        if urlsplit(url).hostname=='192.168.8.1':raise RuntimeError('Physical router I/O is forbidden in browser preview')
        return original_request(session,method,url,**kwargs)
    requests.sessions.Session.request=reject_router
    import app as web
    web.app.config['SESSION_COOKIE_NAME']='netguardian_security_preview'
    from risk.risk_engine import evaluate_all_devices
    evaluate_all_devices()
    @web.app.after_request
    def banner(response):
        if response.content_type.startswith('text/html'):
            response.set_data(response.get_data().replace(b'<main class="container">',b'<main class="container"><p>ISOLATED SECURITY PREVIEW: database copy, offline replay only, real router access forbidden.</p>'))
        return response
    from werkzeug.serving import make_server
    server=make_server('127.0.0.1',5058,web.app,threaded=True)
    timer=threading.Timer(1200,server.shutdown);timer.start()
    print('Isolated security preview: http://127.0.0.1:5058/',flush=True)
    try:server.serve_forever()
    finally:timer.cancel();server.server_close()
