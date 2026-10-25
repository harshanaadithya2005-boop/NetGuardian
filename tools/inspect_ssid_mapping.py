"""Read-only SSID/filter mapping and management-route inspection.

Authentication POSTs only. Never persists or prints WLAN passwords or tokens.
"""
from pathlib import Path
import json
import os
import sys
from urllib.parse import urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import config
from router.huawei_client import HuaweiRouterClient


def main():
    client=HuaweiRouterClient(os.getenv('HUAWEI_ROUTER_USERNAME','user'),os.environ['HUAWEI_ROUTER_PASSWORD'])
    original=client.session.request
    allowed_get={'/api/webserver/SesTokInfo','/api/device/information','/api/wlan/wifi-feature-switch',
                 '/api/wlan/multi-macfilter-settings','/api/wlan/multi-basic-settings','/api/wlan/host-list',
                 '/html/wlanmacfilter.html'}
    counts={'GET':0,'AUTH_POST':0,'CONFIG_POST':0}
    def guarded(method,url,**kwargs):
        path=urlsplit(url).path
        if urlsplit(url).netloc!='192.168.8.1':raise RuntimeError('Read-only probe forbids a different host')
        if method.upper()=='GET' and path in allowed_get:counts['GET']+=1
        elif method.upper()=='POST' and path in {'/api/user/challenge_login','/api/user/authentication_login'}:counts['AUTH_POST']+=1
        else:raise RuntimeError('Read-only probe forbids this request')
        return original(method,url,**kwargs)
    client.session.request=guarded
    try:
        client.login()
        capability,filters=client.probe_quarantine_capabilities()
        response=client.session.get(client.base_url+'/api/wlan/multi-basic-settings',headers={'__RequestVerificationToken':client.token},timeout=5,allow_redirects=False)
        client._update_token(response)
        root=client._parse_xml(response)
        ssids=[]
        safe_fields={'Index','WifiSsid','WifiEnable','WifiSsidEnable','Ssid','SsidName','WifiBand','WifiFrequency','WifiBroadcast','WifiHide','wifitotalswitch','WifiSsidStatus'}
        for node in root.findall('./Ssids/Ssid'):
            entry={field.tag:field.text or '' for field in node if field.tag in safe_fields}
            entry['available_field_names']=[field.tag for field in node]
            ssids.append(entry)
        hostroot=client.get_xml('/api/wlan/host-list')
        hosts=[]
        for node in hostroot.findall('.//Host'):
            entry={field.tag:field.text or '' for field in node if field.tag in {'IpAddress','MacAddress','HostName'} or 'ssid' in field.tag.lower()}
            entry['available_field_names']=[field.tag for field in node]
            hosts.append(entry)
        from scapy.all import conf,get_if_hwaddr
        iface,ip,gateway=conf.route.route('192.168.8.1')
        route={'source_ip':ip,'adapter':conf.ifaces.dev_from_networkname(str(iface)).description,'mac':get_if_hwaddr(iface).upper()}
        response=client.session.get(client.base_url+'/html/wlanmacfilter.html',timeout=5,allow_redirects=False)
        result={'firmware':capability['firmware'],'ssids':ssids,'filters':filters.summary(),
                'hosts':hosts,'management_route':route,'filter_page_http_status':response.status_code,
                'requests':counts,'protection_mode':config.PROTECTION_MODE,'writes_enabled':config.ROUTER_WRITES_ENABLED,
                'auto_quarantine':config.AUTO_QUARANTINE,'filter_settings_digest':filters.digest()}
        out=Path(__file__).resolve().parents[1]/'.test-work/ssid-mapping-readonly.json'
        out.write_text(json.dumps(result,indent=2),encoding='utf-8')
        # A recovery reference contains ONLY the MAC-filter settings, not WLAN keys.
        out.with_name('macfilter-before-ssid-test.xml').write_text(filters.xml(),encoding='utf-8')
        print(json.dumps(result,indent=2))
    finally:client.close()

if __name__=='__main__':main()
