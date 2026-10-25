"""Build the standalone phone tool without touching NetGuardian or SQLite.

Uses pinned Google AAPT2/R8/apksig and Eclipse ECJ in .test-work/android-toolchain.
The SDK android.jar must come from Google's verified platform-35_r02.zip.
Signing material remains local in .test-work and is not included in the APK.
"""
import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import secrets
import tempfile
import struct
import subprocess
import zipfile

PROJECT=Path(__file__).resolve().parents[2]
SOURCE=Path(__file__).resolve().parent
TOOLS=PROJECT/'.test-work/android-toolchain'
WORK=PROJECT/'.test-work/phone-dns-build'
JAVA=Path('C:/Program Files/Java/jre1.8.0_51/bin/java.exe')
RT=JAVA.parent.parent/'lib/rt.jar'

def run(*command):
    result=subprocess.run([str(x) for x in command],capture_output=True,text=True,encoding='utf-8',errors='replace')
    if result.returncode:
        raise RuntimeError('Build command failed: '+str(command[0])+'\n'+result.stdout+'\n'+result.stderr)
    return result.stdout

def compile_java(sources,output,classpath):
    output.mkdir(parents=True,exist_ok=True)
    return run(JAVA,'-cp',TOOLS/'ecj.jar','org.eclipse.jdt.internal.compiler.batch.Main',
               '-source','1.8','-target','1.8','-encoding','UTF-8','-bootclasspath',RT,
               '-classpath',classpath,'-d',output,*sources)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--desktop-ip',default='');args=parser.parse_args()
    WORK.mkdir(parents=True,exist_ok=True)
    sdk=TOOLS/'android-35.jar'
    if not sdk.exists():
        platform=TOOLS/'platform.zip'
        if hashlib.sha256(platform.read_bytes()).hexdigest()!='0988cacad01b38a18a47bac14a0695f246bc76c1b06c0eeb8eb0dc825ab0c8e0':raise RuntimeError('Official Android SDK archive checksum differs')
        with zipfile.ZipFile(platform) as archive:
            name=next(n for n in archive.namelist() if n.endswith('/android.jar'))
            sdk.write_bytes(archive.read(name))
    with zipfile.ZipFile(TOOLS/'aapt2.jar') as archive:archive.extractall(TOOLS/'aapt2')
    aapt=TOOLS/'aapt2/aapt2.exe'
    classes=WORK/'classes';test_classes=WORK/'test-classes'
    compile_java(list((SOURCE/'src').rglob('*.java')),classes,sdk)
    compile_java([SOURCE/'test/DnsProbeSelfTest.java',SOURCE/'test/CombinedProbeSelfTest.java'],test_classes,classes)
    output=run(JAVA,'-cp',str(classes)+os.pathsep+str(test_classes),'netguardian.dnstest.DnsProbeSelfTest')
    lines=output.strip().splitlines();packets=[base64.b64decode(line) for line in lines[1:]]
    # Run the exact Java-generated wire payloads through NetGuardian's detector.
    import sys
    sys.path.insert(0,str(PROJECT))
    from detection.dns_anomaly import check_dns_anomaly
    from scapy.layers.dns import DNS
    domains=[]
    for packet in packets:
        dns=DNS(packet)
        if dns.qr!=0 or dns.qdcount!=1 or dns.qd.qtype!=1:raise RuntimeError('Not a standard A query')
        domains.append(dns.qd.qname.decode().rstrip('.'))
    if len(set(domains))!=24 or not all(name.endswith('.invalid') and len(name)>45 for name in domains):raise RuntimeError('Invalid test names')
    result=check_dns_anomaly(domains)
    if not result.get('detected') or result.get('risk_weight')!=20:raise RuntimeError('Current NetGuardian detector did not detect app packets')
    mixed=run(JAVA,'-cp',str(classes)+os.pathsep+str(test_classes),'netguardian.dnstest.CombinedProbeSelfTest').strip().splitlines()
    events=[line.split('|') for line in mixed[1:]]
    from datetime import datetime,timedelta
    from database import db,models
    from risk.risk_engine import evaluate_device_risk
    from unittest.mock import patch
    # Java-generated event schedule -> real risk calculation in a NEW disposable
    # database. No synthetic traffic or scores enter production SQLite.
    with tempfile.TemporaryDirectory(dir=WORK) as temporary,db.isolated_database(Path(temporary)/'risk.db'):
        db.initialize_database()
        device=models.add_or_update_device('192.168.8.250','10:20:30:40:50:70',hostname='Offline phone app test')
        origin=datetime.now()-timedelta(milliseconds=max(int(e[1]) for e in events)+1000)
        rows=[]
        for _,milliseconds,protocol,port,payload in events:
            domain=DNS(base64.b64decode(payload)).qd.qname.decode().rstrip('.') if protocol=='DNS' else None
            rows.append((device,'192.168.8.250','192.168.8.109',protocol,int(port),170 if protocol=='UDP' else 100,
                         domain,(origin+timedelta(milliseconds=int(milliseconds))).isoformat(timespec='milliseconds'),
                         'S' if protocol=='TCP' else None))
        conn=db.get_connection()
        try:
            conn.executemany('INSERT INTO traffic (device_id,source_ip,destination_ip,protocol,destination_port,packet_size,dns_query,timestamp,tcp_flags) VALUES (?,?,?,?,?,?,?,?,?)',rows);conn.commit()
        finally:conn.close()
        with patch('response.router_quarantine.new_client',side_effect=AssertionError('Router access forbidden in app-build tests')):
            untrusted=evaluate_device_risk(device)
            models.set_device_trusted(device,True)
            trusted=evaluate_device_risk(device)
        if untrusted['risk_score']!=95 or trusted['risk_score']!=75:
            raise RuntimeError('Unexpected combined risk: '+json.dumps({'untrusted':untrusted['risk_score'],'trusted':trusted['risk_score'],'contributions':untrusted['contributions']}))
        combined_report=dict(tests=mixed[0],offline_packet_records=len(rows),untrusted_score=untrusted['risk_score'],
                             trusted_score=trusted['risk_score'],contributions=untrusted['contributions'],
                             source='ISOLATED_PACKET_REPLAY',physical_packets_sent=0)
    app_jar=WORK/'classes.jar'
    with zipfile.ZipFile(app_jar,'w',zipfile.ZIP_DEFLATED) as archive:
        for path in classes.rglob('*.class'):archive.write(path,path.relative_to(classes))
    dex=WORK/'dex';dex.mkdir(exist_ok=True)
    run(JAVA,'-cp',TOOLS/'r8.jar','com.android.tools.r8.D8','--min-api','26','--lib',sdk,'--output',dex,app_jar)
    assets=WORK/'assets';assets.mkdir(exist_ok=True);(assets/'desktop-ip.txt').write_text(args.desktop_ip,encoding='utf-8')
    resources=WORK/'resources.zip';base=WORK/'base.apk'
    run(aapt,'compile','--dir',SOURCE/'res','-o',resources)
    run(aapt,'link','--manifest',SOURCE/'AndroidManifest.xml','--min-sdk-version','26','--target-sdk-version','35',
        '-I',sdk,'-A',assets,'-o',base,resources)
    unsigned=WORK/'unsigned.apk'
    with zipfile.ZipFile(base) as source,zipfile.ZipFile(unsigned,'w') as target:
        for info in source.infolist():
            data=source.read(info.filename)
            if info.compress_type==zipfile.ZIP_STORED:
                pad=(-(target.fp.tell()+30+len(info.filename.encode('utf-8'))+len(info.extra)+4))%4
                info.extra+=struct.pack('<HH',0xd935,pad)+b'\0'*pad
            target.writestr(info,data)
        target.write(dex/'classes.dex','classes.dex',compress_type=zipfile.ZIP_DEFLATED)
    keys=TOOLS/'signing';keys.mkdir(exist_ok=True)
    key_file=keys/'local-phone-test.pk8';cert_file=keys/'local-phone-test.der'
    compile_java([SOURCE/'test/SignApk.java'],test_classes,TOOLS/'apksig.jar')
    if not key_file.exists():
        store=keys/'local-phone-test.p12';password_file=keys/'store-password.txt'
        if not store.exists():
            password=secrets.token_hex(24);password_file.write_text(password,encoding='utf-8')
            run(JAVA.with_name('keytool.exe'),'-genkeypair','-alias','netguardian','-keystore',store,
                '-storetype','PKCS12','-storepass',password,'-keypass',password,'-dname','CN=NetGuardian Local DNS Test',
                '-keyalg','RSA','-keysize','2048','-validity','3650','-noprompt')
        run(JAVA,'-cp',str(test_classes)+os.pathsep+str(TOOLS/'apksig.jar'),'SignApk','--export',store,password_file,key_file,cert_file,'netguardian')
    dist=SOURCE/'dist';dist.mkdir(exist_ok=True);apk=dist/'NetGuardian-DNS-Test.apk'
    signing=run(JAVA,'-cp',str(test_classes)+os.pathsep+str(TOOLS/'apksig.jar'),'SignApk',unsigned,apk,key_file,cert_file).strip()
    metadata=run(aapt,'dump','badging',apk)
    if "package: name='netguardian.dnstest'" not in metadata:raise RuntimeError('Wrong package in APK')
    with zipfile.ZipFile(apk) as archive:
        if archive.testzip() is not None:raise RuntimeError('Corrupt APK')
        info=archive.getinfo('resources.arsc')
        with apk.open('rb') as handle:
            handle.seek(info.header_offset);header=handle.read(30);name_length,extra_length=struct.unpack('<HH',header[26:30])
        if info.compress_type!=zipfile.ZIP_STORED or (info.header_offset+30+name_length+extra_length)%4:raise RuntimeError('Resource alignment failed')
    report=dict(apk=str(apk),bytes=apk.stat().st_size,sha256=hashlib.sha256(apk.read_bytes()).hexdigest(),
                packet_tests=lines[0],exact_payload_detector=dict(detected=result['detected'],risk_weight=result['risk_weight'],queries=len(domains)),
                combined_test=combined_report,
                signature=signing,metadata=metadata,physical_router_writes=0,phone_hardware_tested=False,
                note='Signed and statically verified. Installation, Wi-Fi routing and capture from the physical phone require user validation.')
    (dist/'build-results.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))

if __name__=='__main__':main()
