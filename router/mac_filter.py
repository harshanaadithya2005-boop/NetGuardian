"""Strict adapter for the read-only-identified B310s-925 WLAN filter contract.

Evidence: router-served /js/wlanmacfilter.js, postData()/initPage().
No speculative endpoint fallback, Wi-Fi restart, firewall or router reboot.
"""
import copy
from dataclasses import dataclass
import hashlib
import json
import re
import time
import xml.etree.ElementTree as ET

FIRMWARE = {"DeviceName": "B310s-925", "HardwareVersion": "WL1B310CM01",
            "SoftwareVersion": "21.333.01.02.297", "WebUIVersion": "17.100.09.00.03"}
FILTER_ENDPOINT = "/api/wlan/multi-macfilter-settings"
MAC_RE = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")


class QuarantineError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message
        super().__init__(message)


def normalize_mac(value):
    mac = str(value or "").strip().upper()
    if not MAC_RE.fullmatch(mac) or mac == "00:00:00:00:00:00" or int(mac[:2],16) & 1:
        raise QuarantineError("INVALID_MAC", "A verified unicast MAC address is required; rediscover the device.")
    return mac


def _semantic(node):
    text=(node.text or "").strip()
    if node.tag.startswith('WifiMacFilterMac'):
        text=text.upper()
    return (node.tag, tuple(sorted(node.attrib.items())), text,
            tuple(sorted((_semantic(n) for n in node), key=repr)))


class FilterSnapshot:
    def __init__(self, xml):
        try:
            self.root=ET.fromstring(xml) if isinstance(xml,(str,bytes)) else copy.deepcopy(xml)
        except ET.ParseError:
            raise QuarantineError("SCHEMA_UNSUPPORTED", "Router returned invalid filter XML.")
        if self.root.tag not in {"response","request"} or [n.tag for n in self.root] != ['Ssids']:
            raise QuarantineError("SCHEMA_UNSUPPORTED", "Unexpected filter schema; no settings were written.")
        self.ssids={}
        for node in self.root.find('Ssids'):
            names=[n.tag for n in node]
            index=node.findtext('Index')
            if node.tag!='Ssid' or index not in {'0','1','2','3'} or index in self.ssids or len(names)!=len(set(names)):
                raise QuarantineError("SCHEMA_UNSUPPORTED", "Ambiguous SSID filter records; no settings were written.")
            required={'Index','WifiMacFilterStatus'} | {f'WifiMacFilterMac{i}' for i in range(10)} | {f'wifihostname{i}' for i in range(10)}
            if not required.issubset(names) or node.findtext('WifiMacFilterStatus') not in {'0','1','2'}:
                raise QuarantineError("SCHEMA_UNSUPPORTED", "Unsupported MAC filter fields or access mode.")
            for i in range(10):
                mac=node.findtext(f'WifiMacFilterMac{i}')
                if mac: normalize_mac(mac)
            self.ssids[index]=node
        if set(self.ssids)!={'0','1','2','3'}:
            raise QuarantineError("SCHEMA_UNSUPPORTED", "Expected four SSID records on the identified firmware.")

    def xml(self, request=False):
        root=copy.deepcopy(self.root);root.tag='request' if request else 'response'
        return ET.tostring(root,encoding='unicode')

    def digest(self):
        return hashlib.sha256(repr(_semantic(self.root.find('Ssids'))).encode()).hexdigest()

    def summary(self):
        return [{"index":key,"mode":{"0":"DISABLED","1":"WHITELIST","2":"DENYLIST"}[node.findtext('WifiMacFilterStatus')],
                 "entries":[node.findtext(f'WifiMacFilterMac{i}').upper() for i in range(10) if node.findtext(f'WifiMacFilterMac{i}')]} for key,node in sorted(self.ssids.items())]

    def contains(self, mac, indices):
        mac=normalize_mac(mac)
        return all(self.ssids[i].findtext('WifiMacFilterStatus')=='2' and any((self.ssids[i].findtext(f'WifiMacFilterMac{j}') or '').upper()==mac for j in range(10)) for i in indices)


def plan_block(before, mac, indices, allow_enable=False):
    mac=normalize_mac(mac)
    if not isinstance(indices,list) or not indices or any(type(i) is not str or i not in before.ssids for i in indices) or len(set(indices))!=len(indices):
        raise QuarantineError("INVALID_SCOPE", "Select explicit SSID indices from the capability report.")
    after=FilterSnapshot(before.xml())
    ownership=[]
    for index in indices:
        node=after.ssids[index];mode=node.findtext('WifiMacFilterStatus')
        existing=[(node.findtext(f'WifiMacFilterMac{j}') or '').upper() for j in range(10)]
        if mode=='1':
            raise QuarantineError("WHITELIST_MODE", "Whitelist mode is active. NetGuardian will not convert it or remove allow rules.")
        if mode=='0' and (not allow_enable or any(existing)):
            raise QuarantineError("MODE_CHANGE_REQUIRED", "Disabled filtering needs explicit deny-list activation approval and an empty existing list.")
        if mac in existing:
            raise QuarantineError("EXISTING_RULE", "This MAC already has an unmanaged rule. It will not be adopted or removed by NetGuardian.")
        slots=[j for j,value in enumerate(existing) if not value]
        if not slots:
            raise QuarantineError("LIST_FULL", "The router's ten MAC slots are full; no existing rule will be removed.")
        slot=slots[0]
        ownership.append({"index":index,"slot":slot,"previous_mode":mode,
                          "previous_mac":node.findtext(f'WifiMacFilterMac{slot}') or '',
                          "previous_hostname":node.findtext(f'wifihostname{slot}') or ''})
        node.find(f'WifiMacFilterMac{slot}').text=mac
        node.find('WifiMacFilterStatus').text='2'
    return after,ownership


def plan_release(current, mac, ownership):
    """Remove only owned entries; never restore a stale full snapshot over UI edits."""
    mac=normalize_mac(mac)
    if not ownership:
        raise QuarantineError("NO_OWNERSHIP", "No managed rule ownership is recorded. Review router rules manually.")
    after=FilterSnapshot(current.xml())
    for item in ownership:
        node=after.ssids[item['index']]
        mode=node.findtext('WifiMacFilterStatus')
        if mode not in {'0','2'}:
            raise QuarantineError("MODE_CONFLICT", "Router mode changed externally; automatic release is unsafe. Use the recovery snapshot.")
        # An external editor may reorder entries. Find our exact MAC, never delete
        # another MAC just because it now occupies the originally allocated slot.
        slots=[j for j in range(10) if (node.findtext(f'WifiMacFilterMac{j}') or '').upper()==mac]
        if len(slots)>1:
            raise QuarantineError("RULE_CONFLICT", "Duplicate router entries require manual recovery.")
        if slots:
            slot=slots[0]
            node.find(f'WifiMacFilterMac{slot}').text=item['previous_mac']
            # Hostname metadata was never changed by our block; preserve it.
            # The router may have learned or normalized it since that write.
        remaining=any(node.findtext(f'WifiMacFilterMac{j}') for j in range(10))
        # Restore DISABLED only if no other administrator/managed rules depend
        # on this deny list. Otherwise preserve their active filtering mode.
        if item['previous_mode']=='0' and not remaining:
            node.find('WifiMacFilterStatus').text='0'
    return after


@dataclass(frozen=True)
class WritePermit:
    operation_id: str
    mac: str
    before_digest: str
    after_digest: str
    expires_at: float
    authorization_token: str | None = None
    action: str | None = None
    ssid_indices: tuple = ()
    device_id: int | None = None

    def validate(self, before, after):
        from router.write_safety import require_writes_allowed
        require_writes_allowed()
        validate_target_delta(before,after,self.mac,self.action,self.ssid_indices)
        if self.authorization_token:
            from router.manual_mode import validate
            validate(self.authorization_token,self,before,after)
            return
        import config
        if not (config.PROTECTION_MODE=='LIVE' and config.ROUTER_WRITES_ENABLED and config.RECOVERY_CONFIRMED):
            raise QuarantineError("WRITES_DISABLED", "Router writes remain disabled pending explicit live-test and recovery approval.")
        if self.mac not in config.AUTHORIZED_TEST_MACS or time.time()>self.expires_at:
            raise QuarantineError("NOT_AUTHORIZED", "This MAC has no current separately authorized live-test permission.")
        if self.before_digest!=before.digest() or self.after_digest!=after.digest():
            raise QuarantineError("PLAN_CHANGED", "The approved router change no longer matches the prepared plan.")


def validate_target_delta(before,after,mac,action=None,indices=()):
    """Reject a validly hashed plan that contains another device's MAC delta."""
    target=normalize_mac(mac)
    for index,node in before.ssids.items():
        new=after.ssids[index]
        if {n.tag for n in node}!={n.tag for n in new}:
            raise QuarantineError('TARGET_DELTA_MISMATCH','Payload changes the router schema.')
        if _semantic(node)==_semantic(new):continue
        if indices and index not in indices:
            raise QuarantineError('TARGET_DELTA_MISMATCH','Payload changes an unconfirmed SSID.')
        for old_field in node:
            field=old_field.tag;new_value=(new.findtext(field) or '').strip();old_value=(old_field.text or '').strip()
            if field.startswith('WifiMacFilterMac'):
                if old_value.upper()==new_value.upper():continue
                if old_value and normalize_mac(old_value)!=target or new_value and normalize_mac(new_value)!=target:
                    raise QuarantineError('TARGET_DELTA_MISMATCH','Payload MAC differs from the selected and confirmed device.')
                if action=='quarantine' and (old_value or not new_value) or action in {'release','recover'} and new_value:
                    raise QuarantineError('TARGET_DELTA_MISMATCH','Payload action differs from the confirmed operation.')
            elif field=='WifiMacFilterStatus':
                if old_value!=new_value and (old_value,new_value) not in {('0','2'),('2','0')}:
                    raise QuarantineError('TARGET_DELTA_MISMATCH','Payload attempts an unsupported filter mode change.')
                if old_value!=new_value and new_value=='2' and not after.contains(target,[index]):
                    raise QuarantineError('TARGET_DELTA_MISMATCH','Payload enables filtering without the selected target.')
                if old_value!=new_value and new_value=='0' and any(new.findtext(f'WifiMacFilterMac{j}') for j in range(10)):
                    raise QuarantineError('TARGET_DELTA_MISMATCH','Payload disables filtering for unrelated rules.')
            elif old_value!=new_value:
                raise QuarantineError('TARGET_DELTA_MISMATCH','Payload changes unrelated router settings.')
    if action=='quarantine' and (not indices or not after.contains(target,list(indices))):
        raise QuarantineError('TARGET_DELTA_MISMATCH','Payload does not quarantine the exact confirmed MAC and scope.')
