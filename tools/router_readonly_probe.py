"""Authenticated GET-only firmware identification. Auth POSTs are session-only."""
import os,sys,json
from pathlib import Path
import xml.etree.ElementTree as ET
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dotenv import load_dotenv
from router.huawei_client import HuaweiRouterClient
load_dotenv(Path(__file__).resolve().parents[1]/'.env')
c=HuaweiRouterClient(os.getenv('HUAWEI_ROUTER_USERNAME','user'),os.environ['HUAWEI_ROUTER_PASSWORD'])
c.login()
for path in ['/api/device/information','/api/user/state-login','/api/global/module-switch','/api/wlan/wifi-feature-switch','/api/wlan/multi-macfilter-settings','/api/wlan/mac-filter','/api/wlan/host-list']:
 r=c.session.get(c.base_url+path,headers={'__RequestVerificationToken':c.token},timeout=5)
 try: root=c._parse_xml(r)
 except RuntimeError as error:
  print(path,str(error));continue
 if path.startswith('/api/wlan/'):
  if path.endswith('host-list'):
   print(path,[{'ip':n.findtext('IpAddress'),'mac':n.findtext('MacAddress'),'name':n.findtext('HostName')} for n in root.findall('.//Host')])
  else:
   print(path,ET.tostring(root,encoding='unicode'))
  (Path(__file__).resolve().parents[1]/'.test-work/router-capabilities'/ (path.rsplit('/',1)[-1]+'.xml')).write_text(ET.tostring(root,encoding='unicode'),encoding='utf-8')
 print(path,{n.tag:n.text for n in root if n.tag in {'DeviceName','HardwareVersion','SoftwareVersion','WebUIVersion','ProductFamily','State','usertype','fw_macfilter_enabled'} or 'macfilter' in n.tag.lower()})
c.close()
