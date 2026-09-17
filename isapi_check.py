#!/usr/bin/env python3
"""ISAPI check tool for Tiandy/Hikvision NVRs and cameras (READ-ONLY).

Tests the Hikvision-style ISAPI web API that the bulk tool uses:
  - login check (HTTP Digest auth, Basic fallback)
  - GET /ISAPI/System/Network/SNMP   (the URL captured from DevTools)
  - GET /ISAPI/Security/users        (password change endpoint)
  - probes several port-config endpoints (/HTTP, /RTSP, /UPnP, ...)
    because Tiandy returns HTTP 400 on the standard Hikvision ones

This script makes NO changes to the device - it only reads config.

Usage:
  python isapi_check.py [ip] [web_port] [username] [password]

Example:
  python isapi_check.py 192.168.7.60 80 admin jblbsl07
"""

import base64
import hashlib
import re
import sys
import xml.etree.ElementTree as ET

try:
    import requests
except ImportError:
    print("requests library missing - pip install requests")
    sys.exit(1)

try:
    from Crypto.Cipher import DES as _DES
except ImportError:
    _DES = None

TD_CONST = "ZzYyXxWw12345678"


def _rev_bits(data):
    return bytes(int(f"{b:08b}"[::-1], 2) for b in data)


def _td_key(access, password):
    m = hashlib.md5((access + password + TD_CONST).encode()).hexdigest().upper()
    return m[12:20].encode()


def _td_decrypt(b64, key8):
    raw = _DES.new(_rev_bits(key8), _DES.MODE_ECB).decrypt(_rev_bits(base64.b64decode(b64)))
    data = _rev_bits(raw)
    n = data[-1]
    if 0 < n <= 8 and data[-n:-1] == b"\x00" * (n - 1):
        data = data[:-n]
    return data.decode()

IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.7.60"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
USER = sys.argv[3] if len(sys.argv) > 3 else "admin"
PASS = sys.argv[4] if len(sys.argv) > 4 else ""

BASE = f"http://{IP}:{PORT}"


def isapi_get(path, accept="application/xml"):
    headers = {"Accept": accept} if accept else {}
    session = requests.Session()
    session.auth = requests.auth.HTTPDigestAuth(USER, PASS)
    resp = session.get(BASE + path, headers=headers, timeout=12)
    if resp.status_code == 401:
        session.auth = requests.auth.HTTPBasicAuth(USER, PASS)
        resp = session.get(BASE + path, headers=headers, timeout=12)
    return resp


def _probe(path, desc, accept="application/xml"):
    try:
        resp = isapi_get(path, accept=accept)
    except Exception as e:
        print(f"[FAIL] {path}  ({desc})")
        print(f"       Connection error: {e}")
        print()
        return
    code = resp.status_code
    if code == 200:
        tag = "OK"
    elif code == 401:
        tag = "AUTH"
    elif code == 404:
        tag = "MISSING"
    else:
        tag = f"HTTP {code}"
    print(f"[{tag:7}] {path}  ({desc})")
    if code == 200:
        text = resp.text.strip().replace("\n", "\n       ")
        print("       " + text[:250])
    elif code == 401:
        print("       -> Login failed: incorrect username/password")
    elif code == 404:
        print("       -> Endpoint not found")
    print()


def dump_decrypted_users():
    """Decrypt EVERY field of every Tiandy <User> entry - shows hidden fields
    (permissions/authority lists) that the plain dump above leaves encrypted."""
    print("DECRYPTED Tiandy user entries (all fields, including permissions if present):")
    if _DES is None:
        print("       pycryptodome missing - cannot decrypt (pip install pycryptodome)")
        print()
        return
    r = isapi_get("/ISAPI/Security/users")
    if r.status_code != 200:
        print(f"       [HTTP {r.status_code}] - could not read user list")
        print()
        return
    m = re.search(r"<access>([0-9A-Fa-f]{32})</access>", r.text or "")
    if not m:
        print("       (plaintext Hikvision-style list - nothing encrypted to decrypt)")
        print()
        return
    key = _td_key(m.group(1).upper(), PASS)
    try:
        root = ET.fromstring(r.text)
    except ET.ParseError:
        print("       could not parse user list XML")
        print()
        return
    found = 0
    for user in root.iter():
        if user.tag.split("}")[-1] != "User":
            continue
        found += 1
        print(f"       --- User #{found} ---")
        for child in user:
            tag = child.tag.split("}")[-1]
            val = (child.text or "").strip()
            if not val:
                print(f"       {tag}: (empty)")
                continue
            try:
                dec = _td_decrypt(val, key)
            except Exception:
                print(f"       {tag}: {val[:44]}... (not decodable)")
                continue
            if all(32 <= ord(c) < 127 for c in dec):
                print(f"       {tag}: {dec}")
            else:
                print(f"       {tag}: (binary, {len(dec)} bytes)")
    if not found:
        print("       no <User> entries found")
    print()


def main():
    if not PASS:
        print("Password required - usage: python isapi_check.py [ip] [port] [username] [password]")
        sys.exit(1)
    print(f"Checking ISAPI on {BASE}  (user: {USER})  [READ-ONLY - makes no changes]")
    print("=" * 60)
    _probe("/ISAPI/System/Network/SNMP", "SNMP config (your captured URL)")
    _probe("/ISAPI/Security/users", "user list (password change endpoint)")
    print("FULL response of /ISAPI/Security/users (read-only):")
    r = isapi_get("/ISAPI/Security/users")
    if r.status_code == 200:
        print(r.text)
    else:
        print(f"[HTTP {r.status_code}] - could not read")
    print()
    dump_decrypted_users()
    print("Permission-related endpoints (read-only probes):")
    for path in ("/ISAPI/Security/permissions", "/ISAPI/Security/userPermissions",
                 "/ISAPI/UserMgmt/permissions", "/ISAPI/Security/users/1/permissions"):
        _probe(path, "permission config?")
    print("Port config endpoint (URL captured from your NVR):")
    _probe("/ISAPI/System/Network/interfaces/IPandPort/1", "port config (HTTP/RTSP/Server/HTTPS/DATA)")
    print("FULL response of /ISAPI/System/Network/interfaces/IPandPort/1 (read-only):")
    r = isapi_get("/ISAPI/System/Network/interfaces/IPandPort/1")
    if r.status_code == 200:
        print(r.text)
    else:
        print(f"[HTTP {r.status_code}] - could not read")
    print()
    _probe("/ISAPI/System/Network/interfaces/IPandPort/1/", "trailing slash")
    _probe("/ISAPI/System/Network/UPnP", "UPnP (old UI port table)")
    print("=" * 60)
    print("If IPandPort/1 returns GET 200, the port change is ready.")
    print("If it returns 400/404, capture the port page's Save request (F12 -> Network ->")
    print("Copy as cURL) and send it here (with URL + method + body).")


if __name__ == "__main__":
    main()