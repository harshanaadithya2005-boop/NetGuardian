"""Isolated browser fixture. Only the fake router can receive control operations."""
from pathlib import Path
import sys
import tempfile
import threading
import secrets
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))
import config
from database import db,models
from werkzeug.security import generate_password_hash
config.PROTECTION_MODE='DEMO';config.ROUTER_WRITES_ENABLED=False;config.RECOVERY_CONFIRMED=False
config.AUTHORIZED_TEST_MACS=frozenset();config.TARGET_NETWORK='192.168.8.0/24'
config.ADMIN_PASSWORD_HASH=generate_password_hash('ui-preview-only-password')
config.SECRET_KEY=secrets.token_hex(32)
work=ROOT/'.test-work';work.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(dir=work) as temp:
    db.DB_PATH=Path(temp)/'preview.db';db.initialize_database()
    from router import write_safety
    # This override is confined to this disposable process. Physical router
    # requests are rejected below, regardless of this mock-only lock path.
    write_safety.LOCK_FILE=Path(temp)/'mock-lock'
    from test_quarantine_identity import ThreeDeviceRouter,A,B,C
    from router.mac_filter import plan_block
    device=models.add_or_update_device('192.168.8.101',A,hostname='mock-phone',device_name='MOCK Device A',device_type='Mobile')
    b=models.add_or_update_device('192.168.8.103',B,hostname='Device-B',device_name='MOCK Device B',device_type='Mobile')
    c=models.add_or_update_device('192.168.8.104',C,hostname='Device-C',device_name='MOCK Device C',device_type='Mobile')
    config.STABLE_WIFI_IDENTITY_BINDINGS={A:{'device_id':device,'ip':'192.168.8.101','hostname':'mock-phone','ssid_indices':['0']}}
    import app as web
    web.app.config['SESSION_COOKIE_NAME']='netguardian_router_preview'
    from response import router_quarantine as service
    from test_router_quarantine import FakeRouter,DESKTOP
    fake=ThreeDeviceRouter();service.new_client=lambda:fake
    fake.snapshot,_=plan_block(fake.snapshot,A,['0'],True) # Unrelated pre-existing rule must survive.
    import requests,time
    original_request=requests.sessions.Session.request
    def reject_physical_router(session,method,url,**kwargs):
        from urllib.parse import urlsplit
        if urlsplit(url).hostname=='192.168.8.1':raise RuntimeError('Physical router access forbidden in browser fixture')
        return original_request(session,method,url,**kwargs)
    requests.sessions.Session.request=reject_physical_router
    original_write=fake.write_mac_filter
    def delayed_fake_write(*args):
        time.sleep(1.5)
        result=original_write(*args)
        fake.no_apply=False
        return result
    fake.write_mac_filter=delayed_fake_write
    @web.app.post('/__fixture/fail-next')
    def fail_next():
        fake.no_apply=True
        return {'status':'success'}
    @web.app.get('/__fixture/result')
    def fixture_result():
        return {'writes':len(fake.writes),'filters':fake.snapshot.summary(),'wire_xml':fake.writes,'physical_router_writes':0,
                'identities':{'A':{'device_id':device,'mac':A},'B':{'device_id':b,'mac':B},'C':{'device_id':c,'mac':C}}}

    service.local_identities=lambda:({'192.168.8.102'},{DESKTOP})
    @web.app.after_request
    def mark_preview(response):
        if response.content_type.startswith('text/html'):
            response.set_data(response.get_data().replace(b'<main class="container">', b"""<main class="container"><p>ISOLATED MOCK ROUTER PREVIEW. Production data and router are untouched.</p><button type="button" id="fixture-fail-next" onclick="fetch('/__fixture/fail-next', {method: 'POST'}).then(() => this.textContent='Next mock write will fail verification')">Simulate mock verification failure</button>"""))
        return response
    from werkzeug.serving import make_server
    port=int(sys.argv[1]) if len(sys.argv)>1 else 5053
    server=make_server('127.0.0.1',port,web.app,threaded=True)
    timer=threading.Timer(900,server.shutdown);timer.start()
    print(f'Isolated mock preview: http://127.0.0.1:{port}/device/{device}',flush=True)
    try:server.serve_forever()
    finally:timer.cancel();server.server_close()
