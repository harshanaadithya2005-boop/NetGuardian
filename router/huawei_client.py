
import hashlib
import hmac
import secrets
import xml.etree.ElementTree as ET
from http.cookies import SimpleCookie
from urllib.parse import urlsplit

import requests


class HuaweiRouterClient:
    def __init__(self, username, password, base_url="http://192.168.8.1"):
        self.username = username
        self.password = password
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.trust_env = False
        self.token = None
        self.authenticated = False

    def _parse_xml(self, response):
        response.raise_for_status()

        root = ET.fromstring(response.content)

        if root.tag == "error":
            code = root.findtext("code")
            raise RuntimeError(f"Huawei API error: {code}")

        if root.tag != "response":
            raise RuntimeError("Unexpected Huawei API response")

        return root

    def _make_xml(self, fields):
        root = ET.Element("request")

        for name, value in fields.items():
            ET.SubElement(root, name).text = str(value)

        return ET.tostring(
            root,
            encoding="utf-8",
            xml_declaration=True
        )

    def _post(self, endpoint, fields):
        if endpoint not in {"/api/user/challenge_login", "/api/user/authentication_login"}:
            raise RuntimeError("Configuration writes require the authorized MAC filter path")
        response = self.session.post(
            self.base_url + endpoint,
            data=self._make_xml(fields),
            headers={
                "__RequestVerificationToken": self.token,
                "Content-Type": "application/xml",
                "X-Requested-With": "XMLHttpRequest",
            },
            timeout=5,
            allow_redirects=False,
        )

        self._update_token(response)
        result = self._parse_xml(response)
        return result

    def _update_token(self, response):
        self.token = (
            response.headers.get("__RequestVerificationToken")
            or response.headers.get("__RequestVerificationTokenone")
            or response.headers.get("__requestverificationtoken")
            or response.headers.get("__requestverificationtokenone")
            or self.token
        )

    def get_xml(self, endpoint):
        """Authenticated reads from only the router-observed capability APIs."""
        allowed = {"/api/device/information", "/api/user/state-login", "/api/global/module-switch",
                   "/api/wlan/wifi-feature-switch", "/api/wlan/multi-macfilter-settings", "/api/wlan/host-list", "/api/wlan/multi-basic-settings"}
        if endpoint not in allowed:
            raise ValueError("Unverified router read endpoint")
        if not self.authenticated:
            self.login()
        response = self.session.get(self.base_url + endpoint,
                                    headers={"__RequestVerificationToken": self.token}, timeout=5, allow_redirects=False)
        self._update_token(response)
        return self._parse_xml(response)

    def read_mac_filter(self):
        from router.mac_filter import FilterSnapshot, FILTER_ENDPOINT
        return FilterSnapshot(self.get_xml(FILTER_ENDPOINT))

    def probe_quarantine_capabilities(self):
        from router.mac_filter import FIRMWARE, FILTER_ENDPOINT, QuarantineError
        info = self.get_xml("/api/device/information")
        actual = {key: info.findtext(key) for key in FIRMWARE}
        if actual != FIRMWARE:
            raise QuarantineError("FIRMWARE_UNSUPPORTED", "Router firmware differs from the read-only-verified profile. No writes are supported.")
        features = self.get_xml("/api/wlan/wifi-feature-switch")
        if features.findtext("maxapnum") != "4" or features.findtext("isdoublechip") != "0":
            raise QuarantineError("FEATURES_UNSUPPORTED", "WLAN feature layout changed; MAC filtering is disabled in NetGuardian.")
        snapshot = self.read_mac_filter()
        return {"firmware": actual, "endpoint": FILTER_ENDPOINT, "filters": snapshot.summary(),
                "write_contract": "router WebUI postData; record-0 block/release verified on 2026-10-25",
                "atomic_compare_and_set": False, "immediate_disconnect_verified": False,
                "live_verified_scopes": ["0"], "timed_recovery_live_verified": False}, snapshot

    def write_mac_filter(self, before, after, permit):
        """One exact planned replacement, preserving all read settings; no retry."""
        from router.mac_filter import QuarantineError, FILTER_ENDPOINT, WritePermit
        if self.base_url != "http://192.168.8.1" or not isinstance(permit, WritePermit):
            raise QuarantineError("NOT_AUTHORIZED", "A scoped permit for the configured router is required.")
        permit.validate(before, after)
        if self.read_mac_filter().digest() != before.digest():
            raise QuarantineError("CONCURRENT_CHANGE", "Router settings changed after planning. Refresh the plan; nothing was written.")
        permit.validate(before, after)
        from router.manual_mode import authorized_wire_write
        with authorized_wire_write(permit,before,after):
            payload=after.xml(request=True).encode('utf-8')
            from router.write_audit import record_wire_intent
            record_wire_intent(permit,payload)
            response = self.session.post(self.base_url + FILTER_ENDPOINT, data=payload,
                                         headers={"__RequestVerificationToken": self.token, "Content-Type": "application/xml",
                                                  "X-Requested-With": "XMLHttpRequest"}, timeout=5, allow_redirects=False)
        self._update_token(response)
        if response.status_code != 200:
            raise QuarantineError("WRITE_REJECTED", "Router rejected the change. Read-back reconciliation is required before retrying.")
        root = self._parse_xml(response)
        if (root.text or "").strip().upper() != "OK":
            raise QuarantineError("WRITE_REJECTED", "Router did not acknowledge the operation; verify current settings.")

    def login(self):
        response = self.session.get(
            self.base_url + "/api/webserver/SesTokInfo",
            timeout=5,
            allow_redirects=False,
        )

        root = self._parse_xml(response)

        cookies = SimpleCookie()
        cookies.load(root.findtext("SesInfo") or "")

        if "SessionID" not in cookies:
            raise RuntimeError("Huawei SessionID missing")

        self.session.cookies.set(
            "SessionID",
            cookies["SessionID"].value,
            domain=urlsplit(self.base_url).hostname,
            path="/",
        )

        self.token = root.findtext("TokInfo")

        if not self.token:
            raise RuntimeError("Huawei verification token missing")

        client_nonce = secrets.token_hex(32)

        challenge = self._post(
            "/api/user/challenge_login",
            {
                "username": self.username,
                "firstnonce": client_nonce,
                "mode": 1,
            },
        )

        if challenge.findtext("modeselected") != "1":
            raise RuntimeError("Unsupported Huawei authentication mode")

        server_nonce = challenge.findtext("servernonce")
        salt_hex = challenge.findtext("salt")
        iterations = int(challenge.findtext("iterations"))

        if not server_nonce or not server_nonce.startswith(client_nonce):
            raise RuntimeError("Invalid router challenge nonce")

        if not salt_hex or not 1 <= iterations <= 1000000:
            raise RuntimeError("Invalid router challenge parameters")

        auth_message = (
            f"{client_nonce},{server_nonce},{server_nonce}"
        ).encode("utf-8")

        salted_password = hashlib.pbkdf2_hmac(
            "sha256",
            self.password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            iterations,
        )

        # Huawei mode 1 calculation verified with this router.
        client_key = hmac.new(
            b"Client Key",
            salted_password,
            hashlib.sha256,
        ).digest()

        stored_key = hashlib.sha256(client_key).digest()

        signature = hmac.new(
            auth_message,
            stored_key,
            hashlib.sha256,
        ).digest()

        client_proof = bytes(
            a ^ b for a, b in zip(client_key, signature)
        ).hex()

        self._post(
            "/api/user/authentication_login",
            {
                "clientproof": client_proof,
                "finalnonce": server_nonce,
            },
        )

        self.authenticated = True
        return True

    def get_connected_wifi_devices(self):
        if not self.authenticated:
            self.login()

        root = self.get_xml("/api/wlan/host-list")

        devices = []

        for host in root.findall(".//Host"):
            def field(name):
                value = host.findtext(name)
                return value.strip() if value else None

            ip = field("IpAddress")
            mac = field("MacAddress")

            if not ip or not mac:
                continue

            devices.append({
                "ip": ip,
                "mac": mac.upper(),
                "hostname": field("HostName"),
                "associated_time": field("AssociatedTime"),
            })

        return devices

    def enabled_wifi_scopes(self):
        # This firmware's host-list has no per-client SSID field. Identity can
        # be assigned to a scope only when exactly one SSID is enabled.
        root=self.get_xml('/api/wlan/multi-basic-settings')
        return [n.findtext('Index') for n in root.findall('./Ssids/Ssid')
                if n.findtext('WifiEnable')=='1' and n.findtext('wifitotalswitch')=='1']

    def close(self):
        self.session.close()
