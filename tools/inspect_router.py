"""Read-only router WebUI asset discovery; never sends configuration requests."""
from pathlib import Path
import re,sys
from urllib.parse import urljoin,urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import requests
BASE='http://192.168.8.1'
out=Path(__file__).resolve().parents[1]/'.test-work/router-capabilities'
out.mkdir(exist_ok=True)
s=requests.Session();s.trust_env=False
if '--authenticated' in sys.argv:
 import os
 from dotenv import load_dotenv
 from router.huawei_client import HuaweiRouterClient
 load_dotenv(Path(__file__).resolve().parents[1]/'.env')
 client=HuaweiRouterClient(os.getenv('HUAWEI_ROUTER_USERNAME','user'),os.environ['HUAWEI_ROUTER_PASSWORD'])
 client.login();s=client.session
 print('Authenticated session established; credentials and CSRF tokens redacted')
r=s.get(BASE+(sys.argv[1] if len(sys.argv)>1 else '/'),timeout=10);r.raise_for_status()
print('home',r.status_code,'path',urlsplit(r.url).path)
scripts=re.findall(r'<script[^>]+src=["\']([^"\']+)',r.text,re.I)
links=re.findall(r'<(?:a|iframe)[^>]+(?:href|src)=["\']([^"\']+)',r.text,re.I)
print('scripts',scripts);print('links',links[:30])
for i,src in enumerate(scripts):
 url=urljoin(r.url,src)
 if urlsplit(url).netloc!='192.168.8.1':continue
 asset=s.get(url,timeout=10);asset.raise_for_status()
 name=urlsplit(url).path.rsplit('/',1)[-1]
 (out/name).write_text(asset.text,encoding='utf-8')
 print('asset',urlsplit(url).path,'bytes',len(asset.content))
