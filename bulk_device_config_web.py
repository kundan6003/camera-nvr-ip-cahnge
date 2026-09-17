#!/usr/bin/env python3
"""
Bulk Device Config Tool - WEB (Browser) Version
==================================================
Two tools in one place:
  Tab 1: UBNT airOS (SSH)    - Bulk username/password change for
                                Ubiquiti airOS wireless devices (SSH)
  Tab 2: Tiandy & Hikvision (ISAPI) - Bulk password + web port + playback
                                permission change (HTTP/HTTPS/RTSP) for
                                Tiandy/Hikvision NVRs and cameras via the
                                Hikvision-style ISAPI web API (digest auth,
                                PUT xml). A common user is created read-only
                                AND gets playback (replay) + preview permission on all channels
                                channels (local + web) automatically.
                                v2.7: fresh responsive UI - gradient header,
                                pill tabs, card layout, collapsible per-feature
                                help, sticky table headers, mobile-friendly.
                                v2.8: dark teal "iCleaner-style" theme -
                                glowing progress ring for run status, icon
                                guide tiles, floating bottom tab bar.
                                v3.3: cameras whose firmware has NO ISAPI user
                                management (GET /ISAPI/Security/users -> 404)
                                now fall back to the standard ONVIF SetUser for
                                the password change, so mixed NVR+camera batches
                                succeed instead of failing with 404.
                                v3.4: the Tiandy auto-reboot checkbox now restarts
                                devices after a PASSWORD change too (not just port
                                changes), so the change is always saved/applied.
                                Cameras without an ISAPI reboot endpoint are
                                rebooted via the standard ONVIF SystemReboot.
                                v3.5: ONVIF requests now try BOTH Tiandy ONVIF
                                paths - the standard /onvif/device_service AND
                                /onvif/http_service (some Tiandy camera firmwares
                                only answer on the second one and return an HTML
                                404/501 "method not recognized" page on the first).
                                v3.6: ONVIF also falls back to Tiandy's dedicated
                                ONVIF port 8899 when the web port only returns
                                HTML 404/501 pages - many Tiandy camera models run
                                their ONVIF service there instead of the web port.
                                v3.7: ONVIF port scan widened (8899/8000/8080) and
                                the working ONVIF endpoint is cached per device so
                                follow-up calls in the same run are instant.
                                v4.0: merged Kundan's v3.9 features in - Branch Name
                                column for every Tiandy row, a Select NVR picker
                                (Discover/Sync use the picked row, not just the first),
                                Google Sheet sync (NVR + discovered cameras pushed to
                                the user's own Apps Script webhook, script included),
                                and an immediate admin-port switch when the device
                                moves its HTTP server to the new HTTP port mid-run.

NOTE - How this was built: the ISAPI endpoints used here come from real
requests captured on a Tiandy NVR's own web UI via browser DevTools, e.g.
  PUT http://admin:pass@IP/ISAPI/System/Network/SNMP  ->  200 OK
The port settings (HTTP/HTTPS/RTSP/Server/DATA) live in
  /ISAPI/System/Network/interfaces/IPandPort/1
and are changed read-modify-write: GET the config XML, change the port
values, PUT it back.
Password change: Tiandy ENCRYPTS the user XML in /ISAPI/Security/users
(base64 DES-ECB with bit-reversed bytes; key = MD5(access + login password +
"ZzYyXxWw12345678").upper()[12:20]) - this was reverse-engineered from the
NVR's own JS (external/des.min.js + js/app.min.js) and verified live (200 OK
on a no-op PUT). The encrypted body goes to the COLLECTION url
/ISAPI/Security/users wrapped in <UserList><access>...</UserList> (PUT to
/users/1 returns 400 "Invalid Operation"). Plaintext Hikvision-style lists
fall back to a plaintext PUT on /ISAPI/Security/users/{id}. The NVR admin
username is locked by Tiandy (Edit User shows it greyed out), so the tool
only changes passwords, never usernames.

Setup (once):
  pip install flask requests paramiko openpyxl

Run:
  python3 bulk_device_config_web.py

Then open in your browser:
  http://localhost:5000
"""

import base64
import csv
import hashlib
import io
import json
import queue
import re
import socket
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from xml.sax.saxutils import escape

from flask import Flask, request, Response, jsonify, send_file

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

try:
    import openpyxl
    OPENPYXL_AVAILABLE = True
except ImportError:
    OPENPYXL_AVAILABLE = False

try:
    from Crypto.Cipher import DES as _TD_DES
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

PORT = int(__import__("os").environ.get("PORT", "5000") or 5000)
APP_VERSION = "4.6"  # 4.4e = sheet-side: searchable branch picker dialog + styled dropdown (Apps Script v4.4c)

UBNT_COLUMNS = ["ip", "ssh_port", "username", "current_password",
                "new_username", "new_password", "new_web_port", "new_http_port"]
TIANDY_COLUMNS = ["branch_name", "ip", "web_port", "username", "current_password",
                  "new_password", "new_http_port", "new_https_port",
                  "new_rtsp_port", "common_username", "common_password"]


# ---------------------------------------------------------------------------
# Tiandy & Hikvision (ISAPI) logic
# ---------------------------------------------------------------------------
# Tiandy NVRs expose a Hikvision-style ISAPI web API (captured from the
# NVR's own web UI via browser DevTools, e.g.
#   PUT http://admin:pass@IP/ISAPI/System/Network/SNMP  ->  200 OK
# with HTTP Digest auth). Ports are changed read-modify-write: GET the
# config XML, change the port value, PUT it back. The NVR admin username
# is locked by Tiandy, so only passwords are changed here.

def _root_namespace(xml_text):
    m = re.search(r'xmlns="([^"]+)"', xml_text or "")
    return m.group(1) if m else None


def _isapi_request(ip, port, username, password, method, path, body=None, timeout=12):
    """Send an ISAPI request. Tries HTTP Digest auth first, then Basic."""
    url = f"http://{ip}:{port}{path}"
    headers = {"Content-Type": "application/xml", "Accept": "application/xml"}
    try:
        session = requests.Session()
        session.auth = requests.auth.HTTPDigestAuth(username, password)
        resp = session.request(method, url, data=body, headers=headers, timeout=timeout)
        if resp.status_code == 401:
            session.auth = requests.auth.HTTPBasicAuth(username, password)
            resp = session.request(method, url, data=body, headers=headers, timeout=timeout)
        return resp
    except requests.exceptions.RequestException as e:
        raise ConnectionError(f"Connection error: {e}")


def _isapi_status_detail(text, limit=220):
    """Pull statusCode/statusString out of an ISAPI <ResponseStatus> error body."""
    code = re.search(r"<statusCode>\s*([0-9]+)", text or "")
    msg = re.search(r"<statusString>\s*([^<]+)", text or "")
    if code or msg:
        detail = f"statusCode={code.group(1) if code else '?'}"
        if msg:
            detail += ", statusString=" + msg.group(1).strip()
        return detail
    return (text or "").strip()[:limit]


# ONVIF (standard, brand-independent) user management - the NVR also speaks
# ONVIF, whose CreateUsers/SetUser calls work without the Tiandy DES format.
_ONVIF_NS = "http://www.onvif.org/ver10/device/wsdl"


# Tiandy camera firmwares are inconsistent about WHERE the ONVIF device
# service lives: most answer on the standard /onvif/device_service on the
# web port, some only answer on /onvif/http_service, and many run their ONVIF
# service on a DEDICATED port (8899 by default) instead of the web UI port
# (which keeps serving only the web UI + ISAPI and replies with a plain HTML
# 404/501 "method not recognized" page to every ONVIF POST). We try each
# port/path combo and keep the first reply that actually comes from an ONVIF
# service (SOAP/XML or an auth challenge).
_ONVIF_PATHS = ("/onvif/device_service", "/onvif/http_service")
_ONVIF_FALLBACK_PORTS = (8899, 8000, 8080)  # Tiandy default + common alternates
_onvif_endpoint_cache = {}  # (ip, web_port) -> (onvif_port, path) once discovered


def _is_wrong_onvif_path(resp):
    """True when the response is a plain HTTP error page (HTML 404/501) or an
    empty body - i.e. THIS endpoint is not the device's ONVIF service. A real
    ONVIF answer is a SOAP envelope/XML or an auth challenge."""
    text = resp.text or ""
    low = text[:400].lower()
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "soap" in ctype or "envelope" in low or "fault" in low:
        return False  # a real ONVIF/SOAP answer (may still contain a <Fault>)
    if "html" in ctype or "<html" in low or "<body" in low:
        return True   # plain HTML error page (404/501 "not recognized")
    if not text.strip():
        return True   # empty reply
    return False      # XML/ISAPI answer - treat as real


def _onvif_device_request(ip, port, username, password, inner_body, action, timeout=12):
    """POST a SOAP body to the device's ONVIF device service (digest auth).
    Tries the web port (device_service + http_service paths), then common
    dedicated ONVIF ports (8899/8000/8080), and returns the first real ONVIF
    response. The winning endpoint is cached per device so later calls in the
    same run (SetUser, SystemReboot) go straight to it. inner_body must
    already carry its own tds:/tt: prefixes (or a default ns)."""
    envelope = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"'
                ' xmlns:tds="http://www.onvif.org/ver10/device/wsdl"'
                ' xmlns:tt="http://www.onvif.org/ver10/schema">'
                f'<s:Body>{inner_body}</s:Body></s:Envelope>')
    action_uri = f'"{_ONVIF_NS}/{action}"'
    headers = {"Content-Type": f'application/soap+xml; charset=utf-8; action={action_uri}',
               "SOAPAction": action_uri}

    def _post(eport, path, t):
        url = f"http://{ip}:{eport}{path}"
        session = requests.Session()
        session.auth = requests.auth.HTTPDigestAuth(username, password)
        resp = session.post(url, data=envelope, headers=headers, timeout=t)
        if resp.status_code == 401:
            session.auth = requests.auth.HTTPBasicAuth(username, password)
            resp = session.post(url, data=envelope, headers=headers, timeout=t)
        return resp

    key = (str(ip), int(port))
    endpoints = []
    cached = _onvif_endpoint_cache.get(key)
    if cached:
        endpoints.append(cached)
    endpoints += [(port, p) for p in _ONVIF_PATHS]
    endpoints += [(fp, p) for fp in _ONVIF_FALLBACK_PORTS if fp != port for p in _ONVIF_PATHS]
    last_resp = None
    last_err = None
    seen = set()
    for eport, path in endpoints:
        if (eport, path) in seen:
            continue
        seen.add((eport, path))
        # A closed/filtered fallback port must not slow the run down - probe
        # non-primary endpoints with a shorter timeout.
        t = timeout if eport == port else min(timeout, 5)
        try:
            resp = _post(eport, path, t)
        except requests.exceptions.RequestException as e:
            last_err = e
            continue  # port closed/filtered - try the next endpoint
        last_resp = resp
        if not _is_wrong_onvif_path(resp):
            _onvif_endpoint_cache[key] = (eport, path)
            return resp
        if cached and (eport, path) == cached:
            _onvif_endpoint_cache.pop(key, None)  # stale - keep scanning
    if last_resp is None and last_err is not None:
        raise ConnectionError(f"ONVIF connection error: {last_err}")
    return last_resp


# ---------------------------------------------------------------------------
# Per-user permission doc (local + remote playback/preview etc.)
# The NVR web UI's Permission page does this in two steps (captured from
# app_js.js + verified live):
#   read : POST /ISAPI/Security/UserPermission  <User><userName>x</userName></User>
#   write: PUT  /ISAPI/Security/UserPermission  <UserPermission>...full doc...
# The PUT is read-modify-write: the whole <UserPermission> document is sent
# back with the wanted bits flipped, everything else untouched.
# ---------------------------------------------------------------------------

def isapi_grant_playback(ip, port, username, password, user_name, timeout=12):
    """Set up a common user's permissions exactly like the reference setup:
    Manual (clearAlarm) + Shutdown/Reboot (restartOrShutdown) ticked under
    Local AND Remote Device Privilege - which is what makes the web UI show
    the master "All" checkbox ticked - plus playback (replay) AND preview on
    ALL channels (local + remote/web). Log Search, Alarm, Manage Channels,
    Parameter Set, System Set, User Management, Voice Talkback and record
    are left untouched (a Common user must not get those). Returns a short
    description of what changed."""
    path = "/ISAPI/Security/UserPermission"
    body = f"<User><userName>{escape(user_name)}</userName></User>"
    r = _isapi_request(ip, port, username, password, "POST", path, body=body, timeout=timeout)
    if r.status_code == 401:
        raise ValueError("Authentication failed - HTTP 401")
    if r.status_code != 200:
        raise RuntimeError(f"POST {path} returned HTTP {r.status_code}: "
                           f"{_isapi_status_detail(r.text)}")
    doc = r.text or ""

    def _counts(section):
        m = re.search(rf"<{section}>(.*?)</{section}>", doc, re.S)
        if not m:
            return ((0, 0), (0, 0))
        seg = m.group(1)
        plays = re.findall(r"<playBack>([^<]+)</playBack>", seg)
        prevs = re.findall(r"<preview>([^<]+)</preview>", seg)
        return ((plays.count("true"), len(plays)), (prevs.count("true"), len(prevs)))

    before_l, before_r = _counts("localPermission"), _counts("remotePermission")
    if before_l[0][1] == 0 and before_r[0][1] == 0:
        raise RuntimeError(f"{path}: the permission response has no per-channel "
                           f"playback entries - send the response XML so it can be handled")

    def _flip(seg):
        # Manual + Shutdown/Reboot = the two privileges the reference dmk
        # user has; with these set the NVR web UI shows "All" ticked.
        seg = re.sub(r"<clearAlarm>false</clearAlarm>", "<clearAlarm>true</clearAlarm>", seg)
        seg = re.sub(r"<restartOrShutdown>false</restartOrShutdown>",
                     "<restartOrShutdown>true</restartOrShutdown>", seg)
        seg = re.sub(r"<playBack>false</playBack>", "<playBack>true</playBack>", seg)
        seg = re.sub(r"<preview>false</preview>", "<preview>true</preview>", seg)
        return seg

    doc = re.sub(r"<localPermission>(.*?)</localPermission>",
                 lambda m: "<localPermission>" + _flip(m.group(1)) + "</localPermission>", doc, flags=re.S)
    doc = re.sub(r"<remotePermission>(.*?)</remotePermission>",
                 lambda m: "<remotePermission>" + _flip(m.group(1)) + "</remotePermission>", doc, flags=re.S)

    put = _isapi_request(ip, port, username, password, "PUT", path, body=doc, timeout=timeout)
    if put.status_code == 401:
        raise ValueError("Authentication failed - HTTP 401")
    if put.status_code != 200:
        raise RuntimeError(f"PUT {path} returned HTTP {put.status_code}: "
                           f"{put.text[:200]} - could not enable playback/preview for '{user_name}'. "
                           f"If it keeps failing, capture the NVR Permission page's Save "
                           f"request (F12 -> Network -> Copy as cURL) and send it")

    # verify
    after_l, after_r = before_l, before_r
    r2 = _isapi_request(ip, port, username, password, "POST", path, body=body, timeout=timeout)
    if r2.status_code == 200:
        after_l = _counts("localPermission")
        after_r = _counts("remotePermission")
    return (f"Manual + Shutdown/Reboot ticked, playback & preview enabled on all "
            f"channels (local + web) for '{user_name}' "
            f"(local playback {before_l[0][0]}/{before_l[0][1]} -> {after_l[0][0]}/{after_l[0][1]}, "
            f"preview {before_l[1][0]}/{before_l[1][1]} -> {after_l[1][0]}/{after_l[1][1]}; "
            f"web playback {before_r[0][0]}/{before_r[0][1]} -> {after_r[0][0]}/{after_r[0][1]}, "
            f"preview {before_r[1][0]}/{before_r[1][1]} -> {after_r[1][0]}/{after_r[1][1]})")


def _onvif_fault_text(resp):
    """Extract the human-readable reason from a SOAP 1.1/1.2 fault (any prefix,
    any case - e.g. SOAP-ENV:Reason/SOAP-ENV:Text)."""
    text = resp.text or ""
    for pat in (r"<[^>]*faultstring[^>]*>([^<]+)",
                r"<[^>]*:Text[^>]*>([^<]+)",
                r"<[^>]*Reason[^>]*>([^<]+)"):
        m = re.search(pat, text, re.I)
        if m:
            return m.group(1).strip()[:160]
    return text.strip()[:160]


def _onvif_user_bodies(action, name, pwd, level):
    """The same ONVIF request in two encodings: prefixed (tds:/tt:) and
    default-namespace - firmwares differ in what they accept."""
    return (
        f'<tds:{action}><tds:User>'
        f'<tt:Username>{escape(name)}</tt:Username>'
        f'<tt:Password>{escape(pwd)}</tt:Password>'
        f'<tt:UserLevel>{escape(level)}</tt:UserLevel>'
        f'</tds:User></tds:{action}>',
        f'<{action} xmlns="{_ONVIF_NS}"><User>'
        f'<Username>{escape(name)}</Username>'
        f'<Password>{escape(pwd)}</Password>'
        f'<UserLevel>{escape(level)}</UserLevel>'
        f'</User></{action}>',
    )


def _onvif_grant_playback_best_effort(ip, port, username, password, user_name, timeout=12):
    """Best-effort playback permission for ONVIF-only devices. Many camera
    firmwares do not expose per-channel permission documents at all, in which
    case the fresh user can already play back and this simply confirms it."""
    for body in (f'<tds:GetUsers/>', f'<GetUsers xmlns="{_ONVIF_NS}"/>'):
        resp = _onvif_device_request(ip, port, username, password, body,
                                     "GetUsers", timeout=timeout)
        if resp.status_code == 200 and "Fault" not in (resp.text or ""):
            return (f"ONVIF user list confirmed '{user_name}' exists "
                    "(no per-channel permission doc on this device - "
                    "playback follows the user level)")
    raise RuntimeError("ONVIF GetUsers did not answer after the user change")


def _onvif_create_or_update_user(ip, port, username, password, name, pwd, level, timeout=12):
    """Create (or update) a user via the standard ONVIF device service.
    Returns (action, level); raises RuntimeError listing every rejection."""
    existing = None
    get_errs = []
    for get_body in (f'<tds:GetUsers/>', f'<GetUsers xmlns="{_ONVIF_NS}"/>'):
        resp = _onvif_device_request(ip, port, username, password, get_body,
                                     "GetUsers", timeout=timeout)
        if resp.status_code == 200 and "Fault" not in (resp.text or ""):
            for m in re.finditer(r"<(?:\w+:)?Username>([^<]+)</(?:\w+:)?Username>", resp.text):
                if m.group(1).strip().lower() == name.lower():
                    existing = m.group(1).strip()
                    break
            break
        get_errs.append(f"GetUsers HTTP {resp.status_code}: {_onvif_fault_text(resp)}")
    if existing:
        errs = []
        for body in _onvif_user_bodies("SetUser", existing, pwd, level):
            r = _onvif_device_request(ip, port, username, password, body, "SetUser", timeout=timeout)
            if r.status_code == 200 and "Fault" not in (r.text or ""):
                return "updated", level
            errs.append(f"HTTP {r.status_code}: {_onvif_fault_text(r)}")
        raise RuntimeError(f"ONVIF SetUser ({level}) failed - " + " | ".join(errs))
    errs = []
    for body in _onvif_user_bodies("CreateUsers", name, pwd, level):
        r = _onvif_device_request(ip, port, username, password, body, "CreateUsers", timeout=timeout)
        if r.status_code == 200 and "Fault" not in (r.text or ""):
            return "created", level
        errs.append(f"HTTP {r.status_code}: {_onvif_fault_text(r)}")
    raise RuntimeError(f"ONVIF CreateUsers ({level}) failed - " + " | ".join(errs))


PORT_LABELS = {"http": "HTTP", "https": "HTTPS", "rtsp": "RTSP",
               "server": "Server", "data": "DATA"}
# Match order matters: 'https' must win over 'http' inside 'httpsPort'.
PORT_KEYS_ORDERED = ["https", "server", "rtsp", "data", "http"]
# Tiandy keeps ports as <protocol>HTTP</protocol> + <portNo>80</portNo> pairs.
_PORT_PROTO_MAP = {"HTTP": "http", "HTTPS": "https", "RTSP": "rtsp",
                   "SERVER": "server", "DATA": "data", "DATA_PORT": "data"}


def _set_port_in_xml(xml_text, port_map):
    """port_map: {"http": 8080, "https": 8443, "rtsp": 8554, "server": 3001, "data": 3002}.
    Returns (new_xml, changed_msgs). Supports two real-world layouts:
      1) Tiandy: <protocol>HTTP</protocol> next to <portNo>80</portNo> in the
         same parent element (AdminAccessProtocol entries)
      2) Hikvision-style: elements named httpPort / httpsPort / rtspPort ...
    Only the port keys the caller asked for are touched; 'httpsPort' is never
    treated as HTTP."""
    root = ET.fromstring(xml_text)
    changed = []
    done = set()

    # 1) Tiandy-style protocol + portNo pairs
    for parent in root.iter():
        children = {}
        for child in parent:
            children[child.tag.split("}")[-1].lower()] = child
        proto_el = children.get("protocol")
        if proto_el is None or not (proto_el.text or "").strip():
            continue
        key = _PORT_PROTO_MAP.get(proto_el.text.strip().upper())
        if not key or key not in port_map or key in done:
            continue
        for ctag, cel in children.items():
            if "port" in ctag and "no" in ctag and cel.text and cel.text.strip().isdigit():
                cel.text = str(port_map[key])
                changed.append(f"{PORT_LABELS.get(key, key.upper())} port -> {port_map[key]}")
                done.add(key)
                break

    # 2) Hikvision-style tags (httpPort/httpsPort/rtspPort/serverPort/dataPort)
    for elem in root.iter():
        tag = elem.tag.split("}")[-1].lower()
        for key in PORT_KEYS_ORDERED:
            if key in tag:
                text = elem.text
                if text is not None and text.strip().isdigit() and key in port_map and key not in done:
                    elem.text = str(port_map[key])
                    changed.append(f"{PORT_LABELS.get(key, key.upper())} port -> {port_map[key]}")
                    done.add(key)
                break

    return ET.tostring(root, encoding="unicode"), changed


# ---------------------------------------------------------------------------
# Tiandy user-list encryption - reverse-engineered from the NVR's own web UI
# (external/des.min.js + js/app.min.js on the device). The device ENCRYPTS the
# <userName>/<password>/<userLevel> values in /ISAPI/Security/users requests
# and responses, which is why plaintext PUT bodies always got HTTP 400.
#   * cipher : DES-ECB with every byte's bits reversed (key/data/output)
#   * pad    : NUL bytes then one final byte = pad length (8 - len % 8)
#   * key    : MD5(access + <logged-in password> + "ZzYyXxWw12345678")
#              -> hex upper -> chars [12:20] used as the 8-byte DES key
#   * access : MD5(str(epoch_ms)).upper() (client generates a fresh one)
# The change is PUT to the COLLECTION url /ISAPI/Security/users (NOT /users/1,
# which returns 400 "Invalid Operation") with a <UserList><access>... wrapper.
# Verified live: a no-op password PUT with this exact body returned 200 OK.
# ---------------------------------------------------------------------------

_TD_CONST = "ZzYyXxWw12345678"


def _td_reverse_bits(data):
    """Reverse the order of the bits inside every byte (Tiandy DES quirk)."""
    return bytes(int(f"{b:08b}"[::-1], 2) for b in data)


def _td_pad8(text):
    d = text.encode()
    m = len(d) % 8
    if m:
        d = d + b"\x00" * (7 - m) + bytes([8 - m])
    return d


def _td_unpad8(data):
    n = data[-1]
    if 0 < n <= 8 and data[-n:-1] == b"\x00" * (n - 1):
        return data[:-n]
    return data


def _td_encrypt(text, key8):
    """Encrypt a value the same way the NVR web UI does -> base64 string."""
    out = _TD_DES.new(_td_reverse_bits(key8), _TD_DES.MODE_ECB).encrypt(
        _td_reverse_bits(_td_pad8(text)))
    return base64.b64encode(_td_reverse_bits(out)).decode()


def _td_decrypt(b64, key8):
    """Decrypt a base64 value the same way the NVR web UI does -> plaintext."""
    raw = _TD_DES.new(_td_reverse_bits(key8), _TD_DES.MODE_ECB).decrypt(
        _td_reverse_bits(base64.b64decode(b64)))
    return _td_unpad8(_td_reverse_bits(raw)).decode()


def _td_key(access_token, login_password):
    m = hashlib.md5((access_token + login_password + _TD_CONST).encode()).hexdigest().upper()
    return m[12:20].encode()


def _td_user_update_xml(user_id, user_name, new_password, user_level, login_password):
    """Build the encrypted <UserList> PUT body exactly like the NVR web UI."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("pycryptodome library missing - pip install pycryptodome")
    access = hashlib.md5(str(int(time.time() * 1000)).encode()).hexdigest().upper()
    key = _td_key(access, login_password)
    return (
        "<UserList><access>" + access + "</access><User><id>" + str(user_id) + "</id>"
        "<userName>" + _td_encrypt(user_name, key) + "</userName>"
        "<password>" + _td_encrypt(new_password, key) + "</password>"
        "<userLevel>" + _td_encrypt(user_level, key) + "</userLevel>"
        "</User></UserList>"
    )


def _td_user_add_xml(user_name, new_password, user_level, login_password, user_id=None):
    """Encrypted <UserList> body for ADDING a user. Tiandy assigns <id>
    server-side, so no <id> is sent by default. user_id="" sends an empty
    <id></id> element and an int sends that value (firmware-dependent)."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("pycryptodome library missing - pip install pycryptodome")
    access = hashlib.md5(str(int(time.time() * 1000)).encode()).hexdigest().upper()
    key = _td_key(access, login_password)
    if user_id is None:
        id_part = ""
    elif user_id == "":
        id_part = "<id></id>"
    else:
        id_part = f"<id>{user_id}</id>"
    return (
        "<UserList><access>" + access + "</access><User>" + id_part
        + "<userName>" + _td_encrypt(user_name, key) + "</userName>"
        + "<password>" + _td_encrypt(new_password, key) + "</password>"
        + "<userLevel>" + _td_encrypt(user_level, key) + "</userLevel>"
        + "</User></UserList>"
    )


def _tiandy_users(users_xml, login_password):
    """Decrypt a GET /ISAPI/Security/users response -> [(id, name, level), ...].
    Returns None when the response is NOT the encrypted Tiandy format
    (i.e. a plaintext Hikvision-style list)."""
    m = re.search(r"<access>([0-9A-Fa-f]{32})</access>", users_xml or "")
    if not m:
        return None
    key = _td_key(m.group(1).upper(), login_password)
    out = []
    for um in re.finditer(r"<User>(.*?)</User>", users_xml, re.S):
        blk = um.group(1)

        def val(tag):
            vm = re.search(r"<" + tag + r">([^<]*)</" + tag + r">", blk)
            return vm.group(1) if vm else ""

        try:
            out.append((val("id"), _td_decrypt(val("userName"), key),
                        _td_decrypt(val("userLevel"), key)))
        except Exception:
            raise ValueError(
                "Could not decrypt the Tiandy user list - 'Current Password' may be wrong "
                "(digest auth worked, but the derived key did not match)")
    return out


def _plain_user_target(users_xml, username):
    """Find (id, real_name) of the admin in a plaintext (Hikvision-style) user list."""
    root = ET.fromstring(users_xml)
    fallback = None
    for elem in root.iter():
        if elem.tag.split("}")[-1].lower() != "user":
            continue
        fields = {}
        for child in elem:
            fields[child.tag.split("}")[-1].lower()] = (child.text or "").strip()
        if fields.get("username", "").lower() == username.lower():
            return fields.get("id", "1"), fields.get("username", username)
        if fallback is None:
            fallback = (fields.get("id", "1"), fields.get("username", username))
    if fallback:
        return fallback
    for elem in root.iter():
        if elem.tag.split("}")[-1].lower() == "id" and (elem.text or "").strip():
            return (elem.text or "").strip(), username
    raise ValueError("No user found in the device user list")


def _tiandy_change_password(ip, port, username, cur_pass, new_pass, users, timeout=12):
    """Tiandy encrypted user list: PUT the encrypted body to the COLLECTION url."""
    target = None
    for uid, name, level in users:
        if name.lower() == username.lower():
            target = (uid, name, level)
            break
    if target is None:  # admin is user id 1 on these devices
        for uid, name, level in users:
            if str(uid) == "1":
                target = (uid, name, level)
                break
    if target is None and users:
        target = users[0]
    if target is None:
        raise ValueError("No user found in the device user list")
    uid, real_name, level = target
    body = _td_user_update_xml(uid, real_name, new_pass, level or "Administrator", cur_pass)
    put_resp = _isapi_request(ip, port, username, cur_pass, "PUT",
                              "/ISAPI/Security/users", body=body, timeout=timeout)
    if put_resp.status_code == 401:
        raise ValueError("Authentication failed - current username/password is incorrect (HTTP 401)")
    if put_resp.status_code != 200:
        raise RuntimeError(
            f"PUT /ISAPI/Security/users returned HTTP {put_resp.status_code}: "
            f"{put_resp.text[:200]} - password change for user '{real_name}' (id {uid}) failed. "
            f"If it keeps failing, capture the Edit User page's Confirm request "
            f"(F12 -> Network -> Copy as cURL) and send it")
    return real_name


def _hik_change_password(ip, port, username, cur_pass, new_pass, users_xml, timeout=12):
    """Plaintext (Hikvision-style) user list: plaintext PUT to /ISAPI/Security/users/{id}."""
    uid, real_name = _plain_user_target(users_xml, username)
    bodies = [
        f"<User><id>{uid}</id><userName>{escape(real_name)}</userName>"
        f"<password>{escape(new_pass)}</password></User>",
        f"<User><id>{uid}</id><userName>{escape(real_name)}</userName>"
        f"<oldPassword>{escape(cur_pass)}</oldPassword><password>{escape(new_pass)}</password></User>",
    ]
    errors = []
    for body in bodies:
        put_resp = _isapi_request(ip, port, username, cur_pass, "PUT",
                                  f"/ISAPI/Security/users/{uid}", body=body, timeout=timeout)
        if put_resp.status_code == 401:
            raise ValueError("Authentication failed - current username/password is incorrect (HTTP 401)")
        if put_resp.status_code == 200:
            return real_name
        errors.append(f"HTTP {put_resp.status_code}: {put_resp.text[:160]}")
    raise RuntimeError(
        f"PUT /ISAPI/Security/users/{uid} failed with the Hikvision format: " + " | ".join(errors)
        + " - capture this device's password-change request (F12 -> Network -> Copy as cURL) and send it"
    )


def _onvif_change_password(ip, port, username, cur_pass, new_pass, timeout=12):
    """Change the admin password via the camera's standard ONVIF device service
    (SetUser with the existing username). This is the fallback for camera
    firmwares that have NO ISAPI user management (GET /ISAPI/Security/users
    returns 404) but DO speak ONVIF on the same web port (e.g. some Tiandy
    camera firmwares). Returns the real username that was changed."""
    # 1) Discover the exact username as the device stores it (and confirm the
    #    device answers at all) via GetUsers.
    existing = None
    get_errs = []
    for get_body in ('<tds:GetUsers/>', f'<GetUsers xmlns="{_ONVIF_NS}"/>'):
        resp = _onvif_device_request(ip, port, username, cur_pass, get_body,
                                     "GetUsers", timeout=timeout)
        if resp.status_code == 200 and "Fault" not in (resp.text or ""):
            for m in re.finditer(r"<(?:\w+:)?Username>([^<]+)</(?:\w+:)?Username>", resp.text):
                if m.group(1).strip().lower() == username.lower():
                    existing = m.group(1).strip()
                    break
            break
        get_errs.append(f"GetUsers HTTP {resp.status_code}: {_onvif_fault_text(resp)}")
    target_name = existing or username
    # 2) SetUser with the new password - both encodings, prefixed first.
    errs = list(get_errs)
    for body in _onvif_user_bodies("SetUser", target_name, new_pass, "Administrator"):
        r = _onvif_device_request(ip, port, username, cur_pass, body, "SetUser", timeout=timeout)
        if r.status_code == 200 and "Fault" not in (r.text or ""):
            return target_name
        errs.append(f"SetUser HTTP {r.status_code}: {_onvif_fault_text(r)}")
    raise RuntimeError("ONVIF password change failed - " + " | ".join(errs)
                       + " - ONVIF was probed on the web port AND ports 8899/8000/8080"
                         " without a single SOAP reply, so this firmware exposes no ONVIF"
                         " user service at all. To support this model, capture its own web"
                         " UI's password change: open the camera UI -> Configuration ->"
                         " User Management -> edit admin, press F12 -> Network, click"
                         " Confirm, then right-click the request -> Copy -> Copy as cURL"
                         " and send it")


def isapi_change_password(ip, port, username, cur_pass, new_pass, timeout=12):
    if not REQUESTS_AVAILABLE:
        raise RuntimeError("requests library missing - pip install requests")
    resp = _isapi_request(ip, port, username, cur_pass, "GET", "/ISAPI/Security/users", timeout=timeout)
    if resp.status_code == 401:
        raise ValueError("Authentication failed - current username/password is incorrect (HTTP 401)")
    if resp.status_code == 404:
        # This firmware has no ISAPI user management (common on Tiandy/Hikvision
        # CAMERA firmwares - only NVRs expose /ISAPI/Security/users). Fall back
        # to the standard ONVIF SetUser on the same web port.
        return _onvif_change_password(ip, port, username, cur_pass, new_pass, timeout=timeout)
    if resp.status_code != 200:
        raise RuntimeError(f"GET /ISAPI/Security/users returned HTTP {resp.status_code}: {resp.text[:200]}")
    users = _tiandy_users(resp.text, cur_pass)
    if users is not None:
        return _tiandy_change_password(ip, port, username, cur_pass, new_pass, users, timeout=timeout)
    return _hik_change_password(ip, port, username, cur_pass, new_pass, resp.text, timeout=timeout)


def isapi_manage_common_user(ip, port, username, password, common_name, common_pass,
                             grant_playback=True, timeout=12):
    """Create or update a read-only user (Authority = Common) on a Tiandy/Hikvision
    device, then tick Manual + Shutdown/Reboot (Local & Remote) and grant
    playback (replay) AND preview permission on all channels - a fresh
    common user starts with none of these. Log Search, Alarm, Manage
    Channels, Parameter Set, System Set, User Management, Voice Talkback
    and record stay off (not allowed for Authority = Common).
    NVRs and cameras both speak ISAPI, so this works on either - just point
    the row at the camera's IP + Web Port. If a user with the same name already
    exists its password/authority is updated, otherwise it is created.
    Returns (action, real_name, level) where action is 'created' or 'updated'."""
    users_path = "/ISAPI/Security/users"

    # Cameras without ISAPI user management (GET -> 404): do the whole job via
    # the standard ONVIF device service instead (CreateUsers/SetUser).
    probe = _isapi_request(ip, port, username, password, "GET", users_path, timeout=timeout)
    if probe.status_code == 404:
        action, name, level = "created", common_name, "User"
        try:
            action, level = _onvif_create_or_update_user(
                ip, port, username, password, common_name, common_pass, "Viewer", timeout=timeout)
        except Exception as e:
            raise RuntimeError(
                f"This device has no ISAPI user management (404) and the ONVIF fallback failed: {e}")
        note = ""
        try:
            note = ", " + _onvif_grant_playback_best_effort(
                ip, port, username, password, common_name, timeout=timeout)
        except Exception as e:
            note = f" (user {action}, but ONVIF playback permission FAILED: {e})"
        return (action, name, level, note)

    def _finish(action, name, level):
        """Common-user create/update succeeded -> also tick Manual +
        Shutdown/Reboot and grant playback & preview on all channels."""
        if not grant_playback:
            return (action, name, level, "")
        try:
            note = isapi_grant_playback(ip, port, username, password, name, timeout=timeout)
            return (action, name, level, ", " + note)
        except Exception as e:
            return (action, name, level,
                    f" (user {action}, but playback permission FAILED: {e})")

    resp = _isapi_request(ip, port, username, password, "GET", users_path, timeout=timeout)
    if resp.status_code == 401:
        raise ValueError("Authentication failed - username/password is incorrect (HTTP 401)")
    if resp.status_code != 200:
        raise RuntimeError(f"GET {users_path} returned HTTP {resp.status_code}: {resp.text[:200]}")

    users = _tiandy_users(resp.text, password)
    if users is not None:
        # Encrypted Tiandy format (same encryption as the password change).
        # IMPORTANT: Tiandy's real API value for the read-only authority shown
        # as "Common" in the web UI is "Viewer" - sending "Common" makes the
        # whole request fail with statusCode=5 (Invalid XML Format).
        level = "Viewer"
        for uid, name, _lvl in users:
            if name.lower() == common_name.lower():
                body = _td_user_update_xml(uid, name, common_pass, level, password)
                put = _isapi_request(ip, port, username, password, "PUT", users_path,
                                     body=body, timeout=timeout)
                if put.status_code == 401:
                    raise ValueError("Authentication failed - HTTP 401")
                if put.status_code != 200:
                    raise RuntimeError(f"PUT {users_path} returned HTTP {put.status_code}: "
                                       f"{put.text[:200]} - could not update common user '{name}'")
                return _finish("updated", name, level)
        try:
            next_id = max(int(u[0]) for u in users if str(u[0]).isdigit()) + 1
        except ValueError:
            next_id = len(users) + 1
        # 1st choice: the standard ONVIF CreateUsers (the NVR also speaks ONVIF;
        # try Tiandy's read-only "Viewer" level first, then ONVIF's standard
        # read-only "User"). Falls back to the encrypted ISAPI add-user variants.
        onvif_errs = []
        onvif_result = None
        for lvl in ("Viewer", "User"):
            try:
                onvif_result = _onvif_create_or_update_user(
                    ip, port, username, password, common_name, common_pass, lvl, timeout=timeout)
                break
            except ConnectionError:
                onvif_errs.append("ONVIF endpoint unreachable")
                break
            except ValueError as e:
                onvif_errs.append(str(e))
                break
            except Exception as e:
                onvif_errs.append(str(e))
        if onvif_result:
            action, real_level = onvif_result
            return _finish(action, common_name, real_level)
        # 2nd choice: encrypted ISAPI add-user - try the id-less body (like the
        # web UI), an empty <id></id>, then the next free id, POST and PUT.
        errors = []
        bodies = [
            ("no <id>", _td_user_add_xml(common_name, common_pass, level, password)),
            ("empty <id>", _td_user_add_xml(common_name, common_pass, level, password, user_id="")),
            (f"<id>{next_id}</id>", _td_user_add_xml(common_name, common_pass, level, password, user_id=next_id)),
        ]
        for label, body in bodies:
            for method in ("POST", "PUT"):
                r = _isapi_request(ip, port, username, password, method, users_path,
                                   body=body, timeout=timeout)
                if r.status_code == 200:
                    return _finish("created", common_name, level)
                if r.status_code == 401:
                    raise ValueError("Authentication failed - HTTP 401")
                errors.append(f"{label}, {method} HTTP {r.status_code}: "
                              f"{_isapi_status_detail(r.text)}")
        raise RuntimeError(
            "Create common user failed - ONVIF: " + ("; ".join(onvif_errs) or "not tried")
            + " | ISAPI add-user: " + " | ".join(errors)
            + ". If both paths fail, open the NVR web UI, press F12 -> Network, add "
            "the user manually (User Management -> Add), right-click the request -> "
            "Copy -> Copy as cURL, and send it so the exact format can be added"
        )

    # Plaintext Hikvision-style format
    existing = None
    try:
        root = ET.fromstring(resp.text)
        for elem in root.iter():
            if elem.tag.split("}")[-1].lower() != "user":
                continue
            fields = {c.tag.split("}")[-1].lower(): (c.text or "").strip() for c in elem}
            if fields.get("username", "").lower() == common_name.lower():
                existing = (fields.get("id", "1"), fields.get("username", common_name))
                break
    except ET.ParseError:
        pass
    level = "Viewer"  # Hikvision's read-only authority
    if existing:
        uid, name = existing
        body = (f"<User><id>{uid}</id><userName>{escape(name)}</userName>"
                f"<password>{escape(common_pass)}</password>"
                f"<userLevel>{level}</userLevel></User>")
        put = _isapi_request(ip, port, username, password, "PUT", f"{users_path}/{uid}",
                             body=body, timeout=timeout)
        if put.status_code == 401:
            raise ValueError("Authentication failed - HTTP 401")
        if put.status_code != 200:
            raise RuntimeError(f"PUT {users_path}/{uid} returned HTTP {put.status_code}: "
                               f"{put.text[:200]} - could not update common user '{name}'")
        return _finish("updated", name, level)
    body = (f"<User><userName>{escape(common_name)}</userName>"
            f"<password>{escape(common_pass)}</password>"
            f"<userLevel>{level}</userLevel></User>")
    post = _isapi_request(ip, port, username, password, "POST", users_path,
                          body=body, timeout=timeout)
    if post.status_code == 401:
        raise ValueError("Authentication failed - HTTP 401")
    if post.status_code != 200:
        raise RuntimeError(f"POST {users_path} returned HTTP {post.status_code}: "
                           f"{_isapi_status_detail(post.text)} - could not create common "
                           f"user '{common_name}'")
    return _finish("created", common_name, level)


def tiandy_discover_cameras(ip, port, username, password, timeout=12):
    """List every camera added to a Tiandy NVR - channel, name, IP, admin port,
    online status, and the DECRYPTED camera login credentials (the same DES
    scheme as the user list). Read-only: GETs only.
    Returns a list of dicts."""
    resp = _isapi_request(ip, port, username, password, "GET",
                          "/ISAPI/ContentMgmt/InputProxy/channels/status", timeout=timeout)
    if resp.status_code == 401:
        raise ValueError("Authentication failed - username/password is incorrect (HTTP 401)")
    if resp.status_code != 200:
        raise RuntimeError(f"GET channels/status returned HTTP {resp.status_code}: "
                           f"{_isapi_status_detail(resp.text)}")
    xml = resp.text
    # The DES access token lives at the ROOT of the status list (not per block)
    root_am = re.search(r"<access>([0-9A-Fa-f]{32})</access>", xml)
    root_key = _td_key(root_am.group(1).upper(), password) if (root_am and CRYPTO_AVAILABLE) else None
    cams = []
    for blk in xml.split("<InputProxyChannelStatus>")[1:]:
        def g(tag):
            mm = re.search(r"<" + tag + r">([^<]*)</" + tag + r">", blk)
            return (mm.group(1).strip() if mm else "")
        ch = g("channel") or g("id")
        name = g("channelName")
        ipaddr = g("ipAddress")
        admin_port = g("adminPortNo")
        online = g("online") == "true"
        proto = g("adminProtocol") or "Private"
        # decrypt the stored camera login (root access token; block-level fallback)
        cam_user = cam_pass = ""
        eu = re.search(r"<userName>([^<]*)</userName>", blk)
        ep = re.search(r"<password>([^<]*)</password>", blk)
        am = re.search(r"<access>([0-9A-Fa-f]{32})</access>", blk)
        key = root_key or (_td_key(am.group(1).upper(), password) if (am and CRYPTO_AVAILABLE) else None)
        if key and eu and ep and eu.group(1) and ep.group(1):
            try:
                cam_user = _td_decrypt(eu.group(1), key)
                cam_pass = _td_decrypt(ep.group(1), key)
            except Exception:
                cam_user = cam_pass = ""
        cams.append({"channel": ch, "name": name, "ip": ipaddr, "admin_port": admin_port,
                     "protocol": proto, "online": online,
                     "cam_user": cam_user, "cam_pass": cam_pass})
    cams.sort(key=lambda c: (len(c["channel"]), c["channel"]))
    return cams


def isapi_change_ports(ip, port, username, password, ports, timeout=12):
    """ports: {"http": 8080, "https": 8443, "rtsp": 8554, "server": 3001, "data": 3002}.
    Uses the NVR's real port-config resource (captured from its web UI):
    /ISAPI/System/Network/interfaces/IPandPort/1
    Returns (msgs, warnings)."""
    path = "/ISAPI/System/Network/interfaces/IPandPort/1"
    resp = _isapi_request(ip, port, username, password, "GET", path, timeout=timeout)
    if resp.status_code == 404:
        return [], [f"'{path}' endpoint not found (404) - this NVR firmware does not support this path"]
    if resp.status_code == 401:
        raise ValueError("Authentication failed - current username/password is incorrect (HTTP 401)")
    if resp.status_code != 200:
        raise RuntimeError(f"GET {path} returned HTTP {resp.status_code}: {resp.text[:200]}")
    new_xml, changed = _set_port_in_xml(resp.text, ports)
    if not changed:
        missing = ", ".join(k.upper() for k in ports)
        raise RuntimeError(
            f"{path}: no port entries for {missing} found - this NVR's response uses a different "
            f"structure. Run isapi_check.py (it now prints the FULL response XML) and send the "
            f"output, or capture the port page's Save request (F12 -> Network -> Copy as cURL)"
        )
    put_resp = _isapi_request(ip, port, username, password, "PUT", path, body=new_xml, timeout=timeout)
    if put_resp.status_code != 200:
        raise RuntimeError(f"PUT {path} returned HTTP {put_resp.status_code}: {put_resp.text[:200]} - "
                           f"if the body format is wrong, capture the port page's Save request (Copy as cURL) and send it")
    return changed, []


def isapi_reboot(ip, port, username, password, timeout=12):
    resp = _isapi_request(ip, port, username, password, "PUT", "/ISAPI/System/reboot", body="", timeout=timeout)
    if resp.status_code in (200, 202):
        return
    if resp.status_code == 404:
        # Camera firmware without an ISAPI reboot endpoint - use the standard
        # ONVIF SystemReboot instead (same port, digest auth).
        for body in ("<tds:SystemReboot/>", f'<SystemReboot xmlns="{_ONVIF_NS}"/>'):
            try:
                r = _onvif_device_request(ip, port, username, password, body,
                                          "SystemReboot", timeout=timeout)
            except ConnectionError:
                break
            if r.status_code == 200 and "Fault" not in (r.text or ""):
                return
    raise RuntimeError(f"PUT /ISAPI/System/reboot returned HTTP {resp.status_code}: {resp.text[:200]}")


def process_tiandy(row, dry_run=False, do_reboot=True, retries=2, wait=3):
    ip = row.get("ip", "").strip()
    port = int(str(row.get("web_port", "80")).strip() or 80)
    username = row.get("username", "").strip()
    cur_pass = row.get("current_password", "").strip()
    new_pass = row.get("new_password", "").strip()
    common_user = row.get("common_username", "").strip()
    common_pass = row.get("common_password", "").strip()

    if bool(common_user) != bool(common_pass):
        return "FAILED", ("Common user: fill BOTH 'Common Username' and 'Common Password' "
                          "(or leave both empty to skip the common user)")
    if common_user and common_user.lower() == username.lower():
        return "FAILED", "Common Username cannot be the same as the Current Username"

    ports = {}
    for col, label in (("new_http_port", "HTTP"), ("new_https_port", "HTTPS"),
                       ("new_rtsp_port", "RTSP"), ("new_server_port", "Server"),
                       ("new_data_port", "DATA")):
        val = row.get(col, "").strip()
        if val:
            if not val.isdigit() or not (1 <= int(val) <= 65535):
                return "FAILED", f"Invalid {label} port '{val}' - must be a number between 1 and 65535"
            ports[label.lower()] = int(val)

    if not new_pass and not ports and not common_user:
        return "FAILED", ("Set a New Password, at least one port, or a Common user "
                          "- nothing will be changed")

    if dry_run:
        changes = []
        if new_pass:
            changes.append("password updated")
        if common_user:
            changes.append(f"common user '{common_user}' create/update (authority Common, read-only) "
                           f"+ Manual & Shutdown/Reboot ticked, playback & preview on all channels")
        for label, val in ports.items():
            changes.append(f"{PORT_LABELS.get(label, label.upper())} port -> {val}")
        preview = "Simulated OK - " + (", ".join(changes) if changes else "no changes")
        preview += f" (reboot={'yes' if do_reboot else 'no'})"
        return "DRY-RUN", preview

    if not REQUESTS_AVAILABLE:
        return "FAILED", "requests library missing - pip install requests"

    last_err = None
    for attempt in range(1, retries + 1):
        try:
            parts = []
            warnings = []
            cu_failed = False
            if new_pass:
                final_user = isapi_change_password(ip, port, username, cur_pass, new_pass)
                parts.append(f"username='{final_user}', password updated")
                # The NVR may take 1-2 seconds to apply the password change,
                # so logging in with the new password immediately can return 401 - wait.
                auth_user, auth_pass = username, new_pass
                time.sleep(3)
            else:
                auth_user, auth_pass = username, cur_pass

            if ports:
                port_msgs, port_warns, port_err, cred_ok = [], [], None, None
                creds_list = [(auth_user, auth_pass)]
                if new_pass:
                    # If auth with the new password fails, try the old password too
                    # (if the change has not been applied yet, the old one still works).
                    creds_list.append((username, cur_pass))
                for cred_user, cred_pass in creds_list:
                    tries = 3 if (new_pass and cred_pass == new_pass) else 1
                    for _ in range(tries):
                        try:
                            port_msgs, port_warns = isapi_change_ports(ip, port, cred_user, cred_pass, ports)
                            cred_ok = cred_pass
                            break
                        except ValueError as e:
                            # 401 auth error - the password may still be applying
                            port_err = e
                            time.sleep(3)
                        except Exception as e:
                            # non-auth error (endpoint/format/network) - retrying is pointless
                            port_err = e
                            break
                    if cred_ok is not None or (port_err is not None and not isinstance(port_err, ValueError)):
                        break
                if cred_ok is None:
                    if parts:
                        hint = (" NOTE: could not authenticate with the new password - "
                                "try logging in with it on the NVR web UI") if (
                            new_pass and isinstance(port_err, ValueError)) else ""
                        return "PARTIAL", f"{', '.join(parts)} applied, but the port change failed: {port_err}.{hint}"
                    return "FAILED", f"Port change failed: {port_err}"
                auth_user, auth_pass = username, cred_ok
                parts.extend(port_msgs)
                warnings.extend(port_warns)
                if new_pass and cred_ok == cur_pass:
                    warnings.append("port change used the OLD password - "
                                    "the new password does not seem to have been applied yet")

                # Some Tiandy/Hikvision firmwares switch their admin HTTP
                # server over to the new HTTP port IMMEDIATELY - before the
                # explicit reboot - so any further requests on the old port
                # hit a dead connection. Switch to the new port ourselves.
                if "http" in ports and int(ports["http"]) != port:
                    old_port = port
                    port = int(ports["http"])
                    warnings.append(f"device switched its admin port from {old_port} to {port} "
                                    f"immediately (before reboot) - remaining steps use the new port")
                    time.sleep(3)

            if common_user:
                cu_ok, cu_err = None, None
                cu_creds = [(auth_user, auth_pass)]
                if new_pass:
                    cu_creds.append((username, cur_pass))
                for cred_user, cred_pass in cu_creds:
                    for _ in range(2):
                        try:
                            cu_ok = isapi_manage_common_user(
                                ip, port, cred_user, cred_pass, common_user, common_pass)
                            break
                        except ValueError as e:
                            cu_err = e  # 401 - the new password may still be applying
                            time.sleep(3)
                        except Exception as e:
                            cu_err = e
                            break
                    if cu_ok is not None:
                        break
                if cu_ok is None:
                    cu_failed = True
                    warnings.append(f"common user '{common_user}' NOT created/updated: {cu_err}")
                    if not parts:
                        # the common user was the only change requested
                        return "FAILED", (f"common user '{common_user}' NOT created/updated: "
                                          f"{cu_err}")
                else:
                    cu_action, cu_name, cu_level, cu_note = cu_ok
                    parts.append(f"common user '{cu_name}' {cu_action} "
                                 f"(authority {cu_level}, read-only){cu_note}")

            changes_txt = ", ".join(parts)
            if warnings:
                changes_txt += " | NOTE: " + "; ".join(warnings)

            final_status = "PARTIAL" if cu_failed else "SUCCESS"
            if do_reboot and (new_pass or ports):
                # Reboot after a PASSWORD and/or PORT change so the device saves
                # and applies everything (rebooting right after the change makes
                # the new credentials/ports take effect for sure).
                try:
                    isapi_reboot(ip, port, auth_user, auth_pass)
                    reboot_txt = "device is rebooting (1-2 min) to apply/save the changes"
                    if ports:
                        urls = []
                        if "http" in ports:
                            urls.append(f"http://{ip}:{ports['http']}")
                        if "https" in ports:
                            urls.append(f"https://{ip}:{ports['https']}")
                        url_txt = ", ".join(urls) if urls else "the device web UI"
                        reboot_txt += f" - after reboot, open the web UI on {url_txt}."
                    else:
                        reboot_txt += "."
                    return final_status, f"{changes_txt} set, {reboot_txt}"
                except Exception as e:
                    return "PARTIAL", (
                        f"{changes_txt} applied, but triggering the reboot failed: {e} - "
                        f"reboot the device manually."
                    )
            if ports:
                return final_status, (
                    f"{changes_txt} applied. The new ports take effect after a reboot "
                    f"- reboot the device manually."
                )
            if cu_failed:
                return "PARTIAL", f"{changes_txt}"
            return "SUCCESS", f"{changes_txt}."
        except ValueError as e:
            return "FAILED", str(e)
        except Exception as e:
            last_err = str(e)
            if attempt < retries:
                time.sleep(wait)
    return "FAILED", last_err or "Unknown error"


# ---------------------------------------------------------------------------
# UBNT airOS (SSH) logic
# ---------------------------------------------------------------------------

def _connect_transport(ip, port, username, password, timeout=10):
    sock = socket.create_connection((ip, port), timeout=timeout)
    transport = paramiko.Transport(sock)
    try:
        security = transport.get_security_options()
        try:
            security.kex = tuple(security.kex) + (
                "diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1",
                "diffie-hellman-group14-sha1",
            )
        except Exception:
            pass
        try:
            security.key_types = tuple(security.key_types) + ("ssh-rsa", "ssh-dss")
        except Exception:
            pass
        try:
            security.ciphers = tuple(security.ciphers) + (
                "aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc",
            )
        except Exception:
            pass
    except Exception:
        pass
    transport.banner_timeout = timeout
    transport.connect(username=username, password=password)
    return transport


def _exec(transport, command, timeout=10):
    chan = transport.open_session(timeout=timeout)
    chan.settimeout(timeout)
    chan.exec_command(command)
    out_chunks, err_chunks = [], []
    while True:
        if chan.recv_ready():
            out_chunks.append(chan.recv(4096))
        if chan.recv_stderr_ready():
            err_chunks.append(chan.recv_stderr(4096))
        if chan.exit_status_ready():
            while chan.recv_ready():
                out_chunks.append(chan.recv(4096))
            while chan.recv_stderr_ready():
                err_chunks.append(chan.recv_stderr(4096))
            break
        time.sleep(0.05)
    exit_status = chan.recv_exit_status()
    chan.close()
    return b"".join(out_chunks).decode(errors="ignore"), b"".join(err_chunks).decode(errors="ignore"), exit_status


def change_airos_credentials(ip, port, username, current_password, new_password,
                               new_username=None, new_web_port=None, new_http_port=None,
                               do_save=True, do_reboot=False, timeout=10):
    try:
        transport = _connect_transport(ip, port, username, current_password, timeout=timeout)
    except paramiko.AuthenticationException:
        return "FAILED", "Authentication failed - current username/password is incorrect"
    except Exception as e:
        return "FAILED", f"Connection error: {e}"

    username_changing = bool(new_username and new_username.strip() and new_username.strip() != username)
    web_port = (new_web_port or "").strip()   # secure (HTTPS) server port -> httpd.https.port
    http_port = (new_http_port or "").strip()  # plain (HTTP) server port   -> httpd.port
    port_changing = bool(web_port or http_port)

    try:
        if new_password:
            passwd_out, passwd_err, exit_status = _exec(
                transport, f"echo -e '{new_password}\\n{new_password}' | passwd", timeout=timeout
            )
            combined = (passwd_out + passwd_err).lower()
            if "password updated" not in combined and "success" not in combined and exit_status != 0:
                if "error" in combined or "fail" in combined:
                    return "FAILED", f"passwd command error: {passwd_out}{passwd_err}".strip()

        cmd_persist = (
            f'HASH=$(grep "^{username}:" /etc/passwd | cut -d ":" -f 2); '
            f'sed -ir "s!users.1.password=.*!users.1.password=$HASH!" /var/tmp/system.cfg'
        )
        _, persist_err, persist_status = _exec(transport, cmd_persist, timeout=timeout)
        if persist_status != 0 and persist_err.strip():
            return "PARTIAL", (
                f"Password changed now, but there was a warning persisting the config: {persist_err.strip()}"
            )

        if username_changing:
            new_uname = new_username.strip()
            cmd_rename = f'sed -ir "s!users.1.name=.*!users.1.name={new_uname}!" /var/tmp/system.cfg'
            _, rename_err, rename_status = _exec(transport, cmd_rename, timeout=timeout)
            if rename_status != 0 and rename_err.strip():
                return "PARTIAL", f"Password changed, but there was a warning renaming the username: {rename_err.strip()}"

        if port_changing:
            port_cmds = []
            if web_port:
                port_cmds.append(
                    f"sed -ir '/httpd.https.port=/d' /var/tmp/system.cfg; "
                    f"echo 'httpd.https.port={web_port}' >> /var/tmp/system.cfg"
                )
            if http_port:
                port_cmds.append(
                    f"sed -ir '/httpd.port=/d' /var/tmp/system.cfg; "
                    f"echo 'httpd.port={http_port}' >> /var/tmp/system.cfg"
                )
            _, port_err, port_status = _exec(transport, "; ".join(port_cmds), timeout=timeout)
            if port_status != 0 and port_err.strip():
                return "PARTIAL", (
                    f"Password changed, but there was a warning setting the web port: {port_err.strip()}"
                )

        if do_save:
            _, save_err, save_status = _exec(
                transport, "cfgmtd -f /var/tmp/system.cfg -w", timeout=timeout
            )
            if save_status != 0 and save_err.strip():
                return "PARTIAL", f"Password changed, but there was a warning from the 'save' command: {save_err.strip()}"

        needs_reboot = username_changing or port_changing
        if needs_reboot:
            changes = []
            if username_changing:
                changes.append(f"username '{username}' -> '{new_username.strip()}'")
            if web_port:
                changes.append(f"HTTPS port -> {web_port}")
            if http_port:
                changes.append(f"HTTP port -> {http_port}")
            changes_txt = ", ".join(changes)
            if do_reboot:
                try:
                    _exec(transport, "reboot", timeout=3)
                except Exception:
                    pass
                urls = []
                if web_port:
                    urls.append(f"https://{ip}:{web_port}")
                if http_port:
                    urls.append(f"http://{ip}:{http_port}")
                url_txt = ", ".join(urls) if urls else "the device"
                return "SUCCESS", (
                    f"Password updated. {changes_txt} set, device is rebooting (1-2 min) - "
                    f"after reboot, log in with the new username+password and open the web UI on {url_txt}."
                )
            else:
                return "PARTIAL", (
                    f"Password updated. {changes_txt} saved to the config, "
                    f"but reboot was NOT triggered - until it reboots, old settings will still be active."
                )

        return "SUCCESS", "Password changed and config saved"

    except Exception as e:
        return "FAILED", f"Command execution error: {e}"
    finally:
        try:
            transport.close()
        except Exception:
            pass


def process_ubnt(row, dry_run=False, do_reboot=False, retries=1, wait=3):
    ip = row.get("ip", "").strip()
    port = int(str(row.get("ssh_port", "22")).strip() or 22)
    username = row.get("username", "").strip()
    cur_pass = row.get("current_password", "").strip()
    new_pass = row.get("new_password", "").strip()
    new_user = row.get("new_username", "").strip()
    new_web_port = row.get("new_web_port", "").strip()
    new_http_port = row.get("new_http_port", "").strip()

    for field, label in ((new_web_port, "HTTPS port"), (new_http_port, "HTTP port")):
        if field and (not field.isdigit() or not (1 <= int(field) <= 65535)):
            return "FAILED", f"Invalid {label} '{field}' - must be a number between 1 and 65535"

    if dry_run:
        preview = "Simulated OK - password updated"
        changes = []
        if new_user and new_user != username:
            changes.append(f"username '{username}' -> '{new_user}'")
        if new_web_port:
            changes.append(f"HTTPS port -> {new_web_port}")
        if new_http_port:
            changes.append(f"HTTP port -> {new_http_port}")
        if changes:
            preview += ", " + ", ".join(changes) + f" (reboot={'yes' if do_reboot else 'no'})"
        return "DRY-RUN", preview

    if not PARAMIKO_AVAILABLE:
        return "FAILED", "paramiko library missing - pip install paramiko"

    last_status, last_msg = "FAILED", "Unknown error"
    for attempt in range(1, retries + 1):
        last_status, last_msg = change_airos_credentials(
            ip, port, username, cur_pass, new_pass, new_username=new_user,
            new_web_port=new_web_port, new_http_port=new_http_port, do_reboot=do_reboot
        )
        if last_status in ("SUCCESS", "PARTIAL"):
            return last_status, last_msg
        if attempt < retries:
            time.sleep(wait)
    return last_status, last_msg


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)
RUN_STATE = {"running": False, "queue": None}
RUN_LOCK = threading.Lock()

TOOLS = {
    "ubnt": {"columns": UBNT_COLUMNS, "process": process_ubnt},
    "tiandy": {"columns": TIANDY_COLUMNS, "process": process_tiandy},
}


def _run_worker(tool, rows, dry_run, do_reboot, q):
    process_fn = TOOLS[tool]["process"]
    success, partial, failed = 0, 0, 0
    log_rows = []
    total = len(rows)
    for i, row in enumerate(rows, 1):
        ip = row.get("ip", "?")
        status, message = process_fn(row, dry_run=dry_run, do_reboot=do_reboot)
        if status in ("SUCCESS", "DRY-RUN"):
            success += 1
        elif status == "PARTIAL":
            partial += 1
        else:
            failed += 1
        entry = {"i": i, "total": total, "ip": ip, "status": status, "message": message}
        log_rows.append({"ip": ip, "status": status, "message": message,
                          "timestamp": datetime.now().isoformat(timespec="seconds")})
        q.put(entry)

    log_path = f"{tool}_config_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    try:
        with open(log_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "status", "message", "timestamp"])
            writer.writeheader()
            writer.writerows(log_rows)
    except Exception:
        log_path = None

    q.put({"done": True, "success": success, "partial": partial, "failed": failed,
           "total": total, "log_path": log_path})
    with RUN_LOCK:
        RUN_STATE["running"] = False


@app.route("/")
def index():
    return Response(INDEX_HTML, mimetype="text/html")


@app.route("/api/status")
def api_status():
    return jsonify({
        "requests": REQUESTS_AVAILABLE,
        "paramiko": PARAMIKO_AVAILABLE,
        "openpyxl": OPENPYXL_AVAILABLE,
        "crypto": CRYPTO_AVAILABLE,
        "running": RUN_STATE["running"],
    })


@app.route("/api/<tool>/load", methods=["POST"])
def api_load(tool):
    if tool not in TOOLS:
        return jsonify({"error": "Unknown tool"}), 400
    columns = TOOLS[tool]["columns"]
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file was uploaded"}), 400
    filename = f.filename.lower()
    rows = []
    try:
        if filename.endswith(".csv"):
            text = f.read().decode("utf-8-sig")
            reader = csv.DictReader(io.StringIO(text))
            for r in reader:
                rows.append({c: (r.get(c) or "") for c in columns})
        elif filename.endswith(".xlsx"):
            if not OPENPYXL_AVAILABLE:
                return jsonify({"error": "openpyxl missing - pip install openpyxl"}), 400
            wb = openpyxl.load_workbook(f, data_only=True)
            ws = wb.active
            header = [c.value for c in ws[1]]
            for r in ws.iter_rows(min_row=2, values_only=True):
                if not any(r):
                    continue
                row = dict(zip(header, r))
                rows.append({c: ("" if row.get(c) is None else str(row.get(c))) for c in columns})
        else:
            return jsonify({"error": "Only .csv or .xlsx files are supported"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

    return jsonify({"rows": rows})


@app.route("/api/<tool>/save", methods=["POST"])
def api_save(tool):
    if tool not in TOOLS:
        return jsonify({"error": "Unknown tool"}), 400
    columns = TOOLS[tool]["columns"]
    data = request.get_json(force=True)
    rows = data.get("rows", [])
    fmt = data.get("format", "csv")

    if fmt == "xlsx":
        if not OPENPYXL_AVAILABLE:
            return jsonify({"error": "openpyxl missing"}), 400
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Devices"
        ws.append(columns)
        for row in rows:
            ws.append([row.get(c, "") for c in columns])
        buf = io.BytesIO()
        wb.save(buf)
        buf.seek(0)
        return send_file(buf, as_attachment=True, download_name=f"{tool}_devices.xlsx",
                          mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    else:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
        mem = io.BytesIO(buf.getvalue().encode("utf-8"))
        return send_file(mem, as_attachment=True, download_name=f"{tool}_devices.csv", mimetype="text/csv")


@app.route("/api/<tool>/run", methods=["POST"])
def api_run(tool):
    if tool not in TOOLS:
        return jsonify({"error": "Unknown tool"}), 400
    with RUN_LOCK:
        if RUN_STATE["running"]:
            return jsonify({"error": "A run is already in progress (ubnt or tiandy) - please wait for it to finish"}), 409
        data = request.get_json(force=True)
        rows = data.get("rows", [])
        dry_run = bool(data.get("dry_run", True))
        do_reboot = bool(data.get("do_reboot", True))
        if not rows:
            return jsonify({"error": "No devices in the list"}), 400

        q = queue.Queue()
        RUN_STATE["queue"] = q
        RUN_STATE["running"] = True
        t = threading.Thread(target=_run_worker, args=(tool, rows, dry_run, do_reboot, q), daemon=True)
        t.start()
    return jsonify({"started": True})


@app.route("/api/stream")
def api_stream():
    q = RUN_STATE["queue"]

    def gen():
        if q is None:
            yield "data: " + json.dumps({"done": True, "error": "no run"}) + "\n\n"
            return
        while True:
            item = q.get()
            yield "data: " + json.dumps(item) + "\n\n"
            if item.get("done"):
                break

    return Response(gen(), mimetype="text/event-stream")


@app.route("/api/tiandy/discover", methods=["POST"])
def api_tiandy_discover():
    """Discover the cameras connected to one Tiandy NVR (read-only)."""
    data = request.get_json(force=True)
    ip = (data.get("ip") or "").strip()
    port = (data.get("web_port") or "80").strip() or "80"
    username = (data.get("username") or "").strip()
    password = (data.get("current_password") or "").strip()
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    if not REQUESTS_AVAILABLE:
        return jsonify({"error": "requests library missing - pip install requests"}), 400
    try:
        channels = tiandy_discover_cameras(ip, port, username, password)
    except ValueError as e:
        return jsonify({"error": str(e)}), 401
    except ConnectionError as e:
        return jsonify({"error": str(e)}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ip": ip, "port": port, "channels": channels})


@app.route("/api/tiandy/sync_sheet", methods=["POST"])
def api_tiandy_sync_sheet():
    """Push one NVR + its discovered cameras to a Google Sheet.

    Uses a Google Apps Script Web App URL as a simple webhook, so no Google
    Cloud project / OAuth / service-account JSON is needed - the user just
    pastes a script into their own Sheet once (Extensions -> Apps Script),
    deploys it as a Web App, and pastes the resulting URL into this tool.
    This tool never talks to Google's API directly; it just POSTs JSON to
    that URL and the Apps Script (running under the sheet owner's account)
    writes the rows."""
    if not REQUESTS_AVAILABLE:
        return jsonify({"error": "requests library missing - pip install requests"}), 400
    data = request.get_json(force=True)
    webhook_url = (data.get("webhook_url") or "").strip()
    nvr = data.get("nvr") or {}
    cameras = data.get("cameras") or []
    if not webhook_url:
        return jsonify({"error": "Paste your Google Sheet webhook URL first (see the setup guide)"}), 400
    if not webhook_url.startswith("https://script.google.com/"):
        return jsonify({"error": "That doesn't look like a Google Apps Script Web App URL "
                                 "(should start with https://script.google.com/macros/...)"}), 400
    if not cameras:
        return jsonify({"error": "No discovered cameras to sync - run Discover Cameras first"}), 400

    payload = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "nvr_ip": nvr.get("ip", ""),
        "nvr_port": nvr.get("web_port", ""),
        "nvr_username": nvr.get("username", ""),
        "nvr_password": nvr.get("current_password", ""),
        "nvr_new_http_port": nvr.get("new_http_port", ""),
        "nvr_new_https_port": nvr.get("new_https_port", ""),
        "nvr_new_rtsp_port": nvr.get("new_rtsp_port", ""),
        "nvr_common_username": nvr.get("common_username", ""),
        "nvr_common_password": nvr.get("common_password", ""),
        "branch_name": nvr.get("branch_name", ""),
        "cameras": [
            {
                "channel": c.get("channel", ""),
                "name": c.get("name", ""),
                "ip": c.get("ip", ""),
                "port": c.get("admin_port", ""),
                "username": c.get("cam_user", ""),
                "password": c.get("cam_pass", ""),
                "online": bool(c.get("online")),
            }
            for c in cameras
        ],
    }
    try:
        resp = requests.post(webhook_url, json=payload, timeout=20, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Could not reach the Google Sheet webhook: {e}"}), 502
    # Apps Script Web Apps often answer with a 200 that contains a small JSON
    # or text body - treat any non-2xx as failure and surface the body.
    if resp.status_code >= 300:
        return jsonify({"error": f"Google Sheet webhook returned HTTP {resp.status_code}: "
                                 f"{resp.text[:300]}"}), 502
    return jsonify({"ok": True, "rows_added": len(cameras) + 1, "response": resp.text[:300]})


# ---------------------------------------------------------------------------
# Frontend
# ---------------------------------------------------------------------------

INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bulk Device Config Tool v__VER__</title>
<style>
  * { box-sizing: border-box; }
  :root {
    --bg0: #070b12; --bg1: #0b1120;
    --card: #0e1526; --card2: #101a30;
    --line: rgba(45, 212, 191, .14); --line2: rgba(148, 163, 184, .14);
    --ink: #e6edf7; --muted: #8fa3bd;
    --teal: #2dd4bf; --teal2: #14b8a6; --teal-soft: rgba(45, 212, 191, .12);
    --danger: #f87171; --ok: #34d399; --warn: #fbbf24;
    --radius: 16px;
  }
  html, body { margin: 0; padding: 0; }
  body {
    font-family: "Segoe UI", system-ui, -apple-system, Roboto, Arial, sans-serif;
    color: var(--ink); font-size: 14px; min-height: 100vh;
    background:
      radial-gradient(900px 420px at 85% -10%, rgba(45, 212, 191, .16), transparent 60%),
      radial-gradient(700px 380px at -10% 12%, rgba(56, 130, 246, .10), transparent 55%),
      linear-gradient(180deg, var(--bg1), var(--bg0) 45%);
    background-attachment: fixed;
  }

  .wrap { max-width: 1180px; margin: 0 auto; padding: 20px 18px 40px; }

  /* ---------- header ---------- */
  .topbar { display: flex; align-items: center; justify-content: space-between; gap: 14px; flex-wrap: wrap; }
  .brand { display: flex; align-items: center; gap: 13px; }
  .logo { width: 46px; height: 46px; border-radius: 14px; flex: 0 0 auto;
          background: radial-gradient(120% 120% at 30% 20%, #2dd4bf, #0f766e 70%);
          display: flex; align-items: center; justify-content: center; font-size: 22px;
          box-shadow: 0 0 24px rgba(45, 212, 191, .45), inset 0 0 0 1px rgba(255,255,255,.12); }
  .brand h1 { margin: 0; font-size: 19px; letter-spacing: .01em; }
  .brand p { margin: 3px 0 0; font-size: 12.5px; color: var(--muted); }
  .top-meta { display: flex; gap: 8px; flex-wrap: wrap; }
  .pill { background: rgba(255,255,255,.04); border: 1px solid var(--line);
          border-radius: 999px; padding: 5px 13px; font-size: 12px; font-weight: 600; color: #bfeee6; }
  .pill.ver { background: var(--teal-soft); border-color: rgba(45,212,191,.4); color: var(--teal);
              box-shadow: 0 0 14px rgba(45,212,191,.25); }

  /* ---------- hero: progress ring + status ---------- */
  .hero { margin-top: 0; display: grid; grid-template-columns: auto 1fr; gap: 14px;
          align-items: center; background: linear-gradient(180deg, var(--card2), var(--card));
          border: 1px solid var(--line); border-radius: 14px; padding: 9px 16px;
          box-shadow: 0 6px 18px rgba(2, 8, 20, .4); }
  .ring-wrap { position: relative; width: 78px; height: 78px; flex: 0 0 auto; }
  .ring-wrap svg { width: 78px; height: 78px; transform: rotate(-90deg); }
  .ring-bg { fill: none; stroke: rgba(148, 163, 184, .15); stroke-width: 10; }
  .ring-fg { fill: none; stroke: url(#tealGrad); stroke-width: 10; stroke-linecap: round;
             stroke-dasharray: 339.29; stroke-dashoffset: 339.29; transition: stroke-dashoffset .3s ease; }
  .ring-center { position: absolute; inset: 0; display: flex; flex-direction: column;
                 align-items: center; justify-content: center; }
  .ring-pct { font-size: 18px; font-weight: 700; color: var(--teal);
              text-shadow: 0 0 12px rgba(45, 212, 191, .55); }
  .ring-label { font-size: 9px; letter-spacing: .12em; text-transform: uppercase; color: var(--muted); }
  .hero-side { min-width: 0; }
  .hero-kicker { font-size: 9.5px; letter-spacing: .14em; text-transform: uppercase; color: var(--muted); margin-bottom: 3px; }
  .status-bar { display: inline-block; font-size: 12px; font-weight: 600; color: var(--ink);
                background: rgba(255,255,255,.04); border: 1px solid var(--line2);
                border-radius: 9px; padding: 5px 11px; }
  .hero-note { color: var(--muted); font-size: 11.5px; margin-top: 5px; line-height: 1.45; }

  /* ---------- section labels ---------- */
  .sec { font-size: 11px; letter-spacing: .16em; text-transform: uppercase;
         color: var(--muted); margin: 22px 2px 10px; }

  /* ---------- toolbar ---------- */
  .toolbar { display: flex; flex-wrap: wrap; gap: 9px; align-items: center; }
  .btn { display: inline-flex; align-items: center; gap: 8px; padding: 10px 15px;
         font-size: 13px; font-weight: 600; border-radius: 12px; cursor: pointer;
         border: 1px solid var(--line2); background: var(--card); color: var(--ink);
         transition: all .15s ease; }
  .btn:hover { border-color: rgba(45, 212, 191, .45); background: var(--teal-soft); }
  .btn:active { transform: translateY(1px); }
  .btn:focus-visible { outline: 2px solid var(--teal); outline-offset: 2px; }
  .btn:disabled { opacity: .45; cursor: not-allowed; transform: none; }
  .btn.primary { background: var(--teal); border-color: var(--teal); color: #04211d;
                 box-shadow: 0 0 18px rgba(45, 212, 191, .35); }
  .btn.primary:hover { background: #5eead4; }
  .btn.go { background: linear-gradient(135deg, #2dd4bf, #0d9488); border-color: #14b8a6; color: #03211c;
            box-shadow: 0 0 22px rgba(45, 212, 191, .45); }
  .btn.go:hover { filter: brightness(1.1); }
  .btn.discover { background: rgba(45, 212, 191, .08); border-color: rgba(45, 212, 191, .35); color: var(--teal); }
  .btn.discover:hover { background: rgba(45, 212, 191, .16); }
  .reboot-label { display: inline-flex; align-items: center; gap: 7px; font-size: 12.5px;
                  color: var(--muted); background: rgba(255,255,255,.03);
                  border: 1px dashed var(--line2); border-radius: 12px; padding: 9px 13px; cursor: pointer; }

  /* ---------- panels & cards ---------- */
  .tab-panel { display: none; }
  .tab-panel.active { display: block; animation: fade .18s ease; }
  @keyframes fade { from { opacity: 0; transform: translateY(5px); } to { opacity: 1; } }
  .card { background: linear-gradient(180deg, var(--card2), var(--card));
          border: 1px solid var(--line); border-radius: 20px; padding: 18px;
          box-shadow: 0 10px 30px rgba(2, 8, 20, .45); }

  /* ---------- feature tiles (guides) ---------- */
  .tiles { display: grid; grid-template-columns: repeat(auto-fill, minmax(215px, 1fr)); gap: 10px; }
  details.tile { background: var(--card); border: 1px solid var(--line); border-radius: 14px;
                 padding: 13px 14px; cursor: pointer; transition: border-color .15s ease, background .15s ease; }
  details.tile:hover { border-color: rgba(45, 212, 191, .4); }
  details.tile[open] { background: var(--card2); border-color: rgba(45, 212, 191, .45);
                       box-shadow: 0 0 20px rgba(45, 212, 191, .08); }
  details.tile summary { list-style: none; display: flex; align-items: center; gap: 10px;
                         font-weight: 600; font-size: 13px; color: var(--ink); user-select: none; }
  details.tile summary::-webkit-details-marker { display: none; }
  .tile-ico { width: 34px; height: 34px; border-radius: 10px; flex: 0 0 auto;
              display: flex; align-items: center; justify-content: center; font-size: 16px;
              background: var(--teal-soft); border: 1px solid var(--line); }
  details.tile p { margin: 10px 2px 2px; font-size: 12.5px; line-height: 1.6; color: var(--muted); }
  details.tile b { color: var(--ink); }
  details.tile code { color: #7dd3fc; font-size: 12px; }

  /* ---------- tables ---------- */
  .table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 14px;
                background: var(--card); }
  table { border-collapse: separate; border-spacing: 0; width: 100%; }
  #devTable-ubnt { min-width: 940px; }
  #devTable-tiandy { min-width: 1330px; }
  thead th { position: sticky; top: 0; z-index: 2; background: #0c1322; color: #9fb4cf;
             font-size: 11px; text-transform: uppercase; letter-spacing: .08em;
             padding: 11px 9px; text-align: left; white-space: nowrap;
             border-bottom: 1px solid var(--line); }
  tbody td { border-bottom: 1px solid rgba(148, 163, 184, .08); padding: 0; }
  tbody tr:nth-child(even) { background: rgba(255, 255, 255, .015); }
  tbody tr:hover { background: rgba(45, 212, 191, .05); }
  td input { width: 100%; min-width: 106px; border: 0; background: transparent;
             padding: 10px 11px; font-size: 13px; color: var(--ink); caret-color: var(--teal); }
  td input:focus { outline: none; background: rgba(45, 212, 191, .07);
                   box-shadow: inset 0 -2px 0 var(--teal); }
  .row-actions { text-align: center; padding: 5px 6px !important; white-space: nowrap; }
  .row-actions button { padding: 4px 11px; font-size: 12px; border-radius: 8px;
                        border: 1px solid rgba(248, 113, 113, .35); background: transparent;
                        color: var(--danger); cursor: pointer; font-weight: 600; }
  .row-actions button:hover { background: rgba(248, 113, 113, .12); }

  /* ---------- discover panel ---------- */
  #discoverPanel { display: none; margin-top: 14px; border: 1px solid rgba(45, 212, 191, .35);
                   border-radius: 16px; overflow: hidden; background: var(--card);
                   box-shadow: 0 0 26px rgba(45, 212, 191, .12); }
  .disc-head { display: flex; align-items: center; justify-content: space-between; gap: 10px;
               background: rgba(45, 212, 191, .08); border-bottom: 1px solid var(--line);
               padding: 11px 15px; flex-wrap: wrap; }
  .disc-head h4 { margin: 0; font-size: 14px; }
  #discSummary { font-weight: normal; color: var(--muted); font-size: 12px; }
  #discSel { color: var(--teal); font-size: 12px; font-weight: 700; }
  .disc-scroll { max-height: 280px; overflow: auto; }
  #discoverTable { width: 100%; min-width: 720px; }
  #discoverTable th { position: sticky; top: 0; background: #0c1322; }
  #discoverTable th, #discoverTable td { padding: 8px 11px; font-size: 12.5px;
                                         text-align: left; border-bottom: 1px solid rgba(148,163,184,.08); }
  #discoverTable tbody tr { cursor: pointer; }
  #discoverTable tbody tr:hover td { background: rgba(45, 212, 191, .06); }
  #discoverTable tr.selected td { background: rgba(45, 212, 191, .14); }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 999px;
           font-size: 11px; font-weight: 700; }
  .badge.ok { background: rgba(52, 211, 153, .15); color: var(--ok);
              box-shadow: 0 0 10px rgba(52, 211, 153, .25); }
  .badge.off { background: rgba(248, 113, 113, .12); color: var(--danger); }
  .disc-actions { display: flex; gap: 9px; align-items: center; flex-wrap: wrap; padding: 11px 15px; }
  .hint { color: var(--muted); font-size: 12px; }

  /* ---------- log ---------- */
  .log-box { background: #060a12; color: #9fb4cf; font-family: ui-monospace, Consolas,
             "Courier New", monospace; font-size: 12.5px; line-height: 1.65;
             padding: 15px; height: 270px; overflow-y: auto; border-radius: 14px;
             border: 1px solid var(--line2); }
  .log-line { white-space: pre-wrap; word-break: break-word; }
  .log-line.success { color: var(--ok); }
  .log-line.partial { color: var(--warn); }
  .log-line.fail { color: var(--danger); }
  .log-line.dry { color: #60a5fa; }

  .warn { background: rgba(248, 113, 113, .1); border: 1px solid rgba(248, 113, 113, .35);
          color: #fecaca; padding: 10px 14px; border-radius: 12px; font-size: 13px; margin-bottom: 14px; }

  footer { margin-top: 28px; }
  .dev-card { max-width: 560px; margin: 0 auto; background: linear-gradient(135deg, rgba(45, 212, 191, .10), rgba(14, 21, 38, .6));
              border: 1px solid rgba(45, 212, 191, .3); border-radius: 16px; padding: 16px 20px;
              display: flex; align-items: center; justify-content: space-between; gap: 14px; flex-wrap: wrap;
              box-shadow: 0 0 26px rgba(45, 212, 191, .12); }
  .dev-left { display: flex; align-items: center; gap: 13px; min-width: 0; }
  .dev-avatar { width: 44px; height: 44px; border-radius: 50%; flex: 0 0 auto;
                background: radial-gradient(120% 120% at 30% 20%, #5eead4, #0f766e 75%);
                display: flex; align-items: center; justify-content: center;
                font-weight: 800; font-size: 15px; color: #04211d; letter-spacing: .02em;
                box-shadow: 0 0 16px rgba(45, 212, 191, .45); }
  .dev-kicker { font-size: 10.5px; letter-spacing: .16em; text-transform: uppercase;
                color: var(--teal); opacity: .85; margin-bottom: 2px; }
  .dev-name { font-size: 14.5px; font-weight: 700; color: var(--ink); }
  .dev-note { font-size: 11.5px; color: var(--muted); margin-top: 1px; }
  .dev-tags { display: flex; gap: 6px; flex-wrap: wrap; }
  .dev-tag { font-size: 10.5px; font-weight: 600; color: #bfeee6;
             background: rgba(45, 212, 191, .08); border: 1px solid rgba(45, 212, 191, .25);
             border-radius: 999px; padding: 3px 10px; }
  .foot-fine { text-align: center; color: var(--muted); font-size: 11.5px; margin-top: 10px; }

  /* ---------- top tab bar ---------- */
  .tab-bar { display: flex; justify-content: center; margin: 14px 0 10px; }
  .nav-inner { display: flex; gap: 6px; background: rgba(14, 21, 38, .8);
               border: 1px solid var(--line); border-radius: 16px; padding: 6px;
               box-shadow: 0 10px 26px rgba(2, 8, 20, .5);
               backdrop-filter: blur(10px); }
  .tab-btn { display: inline-flex; align-items: center; gap: 10px;
             padding: 11px 22px; font-size: 13.5px; font-weight: 700;
             cursor: pointer; border: 1px solid transparent; border-radius: 12px;
             background: transparent; color: var(--muted); transition: all .15s ease; }
  .tab-btn small { font-weight: 500; font-size: 11px; opacity: .7; }
  .tab-btn:hover { color: var(--teal); background: rgba(45, 212, 191, .05); }
  .tab-btn.active { background: var(--teal-soft); border-color: rgba(45, 212, 191, .45);
                    color: var(--teal); box-shadow: 0 0 18px rgba(45, 212, 191, .28); }
  .tab-btn .ico { font-size: 18px; }

  /* ---------- responsive ---------- */
  @media (max-width: 720px) {
    .wrap { padding: 14px 12px 130px; }
    .hero { gap: 10px; padding: 9px 12px; }
    .ring-wrap { width: 66px; height: 66px; }
    .ring-wrap svg { width: 66px; height: 66px; }
    .brand h1 { font-size: 16px; }
    .brand p { font-size: 11.5px; }
    .logo { width: 40px; height: 40px; font-size: 19px; }
    .toolbar .btn { flex: 1 1 auto; justify-content: center; }
    .reboot-label { width: 100%; justify-content: center; }
    td input { font-size: 16px; min-width: 122px; }
    .tab-btn { flex: 1; justify-content: center; padding: 10px 12px; }
    .nav-inner { width: 100%; }
  }
</style>
</head>
<body>

<div class="wrap">

  <header class="topbar">
    <div class="brand">
      <div class="logo">&#128736;</div>
      <div>
        <h1>Bulk Device Config Tool</h1>
        <p>Passwords &middot; web ports &middot; playback permissions &mdash; in bulk, from your browser</p>
      </div>
    </div>
    <div class="top-meta">
      <span class="pill ver">v__VER__</span>
      <span class="pill">UBNT &middot; Tiandy &middot; Hikvision</span>
    </div>
  </header>


  <!-- ============ TOP TAB BAR ============ -->
  <nav class="tab-bar">
    <div class="nav-inner">
      <button class="tab-btn active" onclick="switchTab('ubnt')"><span class="ico">&#128225;</span>UBNT airOS <small>SSH</small></button>
      <button class="tab-btn" onclick="switchTab('tiandy')"><span class="ico">&#128249;</span>Tiandy &middot; Hikvision <small>ISAPI</small></button>
    </div>
  </nav>

  <!-- ============ HERO: progress ring + status ============ -->
  <section class="hero">
    <div class="ring-wrap" aria-hidden="true">
      <svg viewBox="0 0 120 120">
        <defs>
          <linearGradient id="tealGrad" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stop-color="#5eead4"/>
            <stop offset="100%" stop-color="#0d9488"/>
          </linearGradient>
        </defs>
        <circle class="ring-bg" cx="60" cy="60" r="54"></circle>
        <circle class="ring-fg" id="ringFg" cx="60" cy="60" r="54"></circle>
      </svg>
      <div class="ring-center">
        <div class="ring-pct" id="ringPct">0%</div>
        <div class="ring-label">progress</div>
      </div>
    </div>
    <div class="hero-side">
      <div class="hero-kicker">Run status</div>
      <span class="status-bar" id="statusBar">Ready</span>
      <div class="hero-note">Load your device list (or add rows manually), preview with
        <b>Dry&nbsp;Run</b>, then <b>Run</b> to apply. Activity appears in the log at the bottom.</div>
    </div>
  </section>

  <div id="lib-warn"></div>

  <!-- ================= UBNT TAB ================= -->
  <div class="tab-panel active" id="panel-ubnt">
    <div class="sec">Ubiquiti airOS &middot; over SSH</div>
    <div class="card">
      <div class="toolbar">
        <button class="btn" onclick="document.getElementById('fileInput-ubnt').click()">&#128193; Load CSV/Excel</button>
        <input type="file" id="fileInput-ubnt" accept=".csv,.xlsx" style="display:none" onchange="loadFile('ubnt', this)">
        <button class="btn" onclick="saveFile('ubnt', 'csv')">&#128190; Save CSV</button>
        <button class="btn" onclick="saveFile('ubnt', 'xlsx')">&#128190; Save Excel</button>
        <button class="btn" onclick="addRow('ubnt')">&#10133; Add Device</button>
        <button class="btn discover" onclick="startRun('ubnt', true)" id="dryBtn-ubnt">&#128269; Dry Run</button>
        <button class="btn go" onclick="startRun('ubnt', false)" id="runBtn-ubnt">&#9654; Run (Apply)</button>
        <label class="reboot-label"><input type="checkbox" id="rebootChk-ubnt" checked> Auto-reboot devices whose username/web ports change</label>
      </div>

      <div class="sec" style="display:flex; align-items:center; gap:10px">
        <button class="btn discover" id="guidesBtn-ubnt" onclick="toggleGuides('ubnt')">&#9432; Guides &amp; Help</button>
      </div>
      <div class="tiles" id="guides-ubnt" style="display:none">
        <details class="tile">
          <summary><span class="tile-ico">&#128225;</span> What this tab does</summary>
          <p>Bulk username/password change for <b>Ubiquiti airOS</b> wireless devices over SSH.
             Changing the password takes effect immediately; port changes need a reboot
             (the auto-reboot checkbox handles it).</p>
        </details>
        <details class="tile">
          <summary><span class="tile-ico">&#128274;</span> Ports</summary>
          <p><b>New HTTPS Port</b> = Secure Server Port (default 443). <b>New HTTP Port</b> = Server Port
             (default 80). Leave a field blank to keep the current port.</p>
        </details>
        <details class="tile">
          <summary><span class="tile-ico">&#128202;</span> CSV / Excel</summary>
          <p><b>Load CSV/Excel</b> fills the table from your file, <b>Save CSV/Excel</b> downloads the
             current table. Use it to prepare a batch, run a <b>Dry Run</b>, then apply for real.</p>
        </details>
        <details class="tile">
          <summary><span class="tile-ico">&#9888;&#65039;</span> Be careful</summary>
          <p>As soon as a password changes, the <b>old password stops working</b>. Test on
             <b>1 device</b> first, then run the whole batch.</p>
        </details>
      </div>

      <div class="sec">Devices</div>
      <div class="table-wrap">
        <table id="devTable-ubnt">
          <thead>
            <tr>
              <th>IP Address</th><th>SSH Port</th><th>Current Username</th>
              <th>Current Password</th><th>New Username (optional)</th><th>New Password</th>
              <th>New HTTPS Port</th><th>New HTTP Port</th>
              <th style="width:74px">Action</th>
            </tr>
          </thead>
          <tbody id="tbody-ubnt"></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- ================= TIANDY & HIKVISION TAB ================= -->
  <div class="tab-panel" id="panel-tiandy">
    <div class="sec">Tiandy &amp; Hikvision &middot; ISAPI</div>
    <div class="card">
      <div class="toolbar">
        <button class="btn" onclick="document.getElementById('fileInput-tiandy').click()">&#128193; Load CSV/Excel</button>
        <input type="file" id="fileInput-tiandy" accept=".csv,.xlsx" style="display:none" onchange="loadFile('tiandy', this)">
        <button class="btn" onclick="saveFile('tiandy', 'csv')">&#128190; Save CSV</button>
        <button class="btn" onclick="saveFile('tiandy', 'xlsx')">&#128190; Save Excel</button>
        <button class="btn" onclick="addRow('tiandy')">&#10133; Add Device</button>
        <button class="btn discover" onclick="discoverCameras()" id="discBtn-tiandy">&#128269; Discover Cameras</button>
        <button class="btn discover" onclick="startRun('tiandy', true)" id="dryBtn-tiandy">&#128269; Dry Run</button>
        <button class="btn go" onclick="startRun('tiandy', false)" id="runBtn-tiandy">&#9654; Run (Apply)</button>
        <label class="reboot-label"><input type="checkbox" id="rebootChk-tiandy" checked> Auto-reboot devices whose web ports change</label>
      </div>

      <div class="toolbar" style="margin-top:10px">
        <label class="reboot-label" style="gap:9px">&#127970; Select NVR (Discover/Sync):
          <select id="nvrSelect" style="background:var(--card2); color:var(--ink); border:1px solid var(--line2); border-radius:9px; padding:7px 10px; font-size:13px; outline:none; cursor:pointer; min-width:210px">
            <option value="">- auto (first row) -</option>
          </select>
        </label>
        <input type="text" id="sheetWebhook" placeholder="Google Sheet Apps Script Web App URL (https://script.google.com/...)" style="flex:1 1 240px; min-width:220px; background:var(--card2); color:var(--ink); border:1px solid var(--line2); border-radius:12px; padding:10px 13px; font-size:13px; outline:none">
        <button class="btn discover" onclick="syncToSheet()" id="syncBtn-tiandy">&#128202; Sync to Google Sheet</button>
      </div>

      <div class="sec" style="display:flex; align-items:center; gap:10px">
        <button class="btn discover" id="guidesBtn-tiandy" onclick="toggleGuides('tiandy')">&#9432; Guides &amp; Help</button>
      </div>
      <div class="tiles" id="guides-tiandy" style="display:none">
        <details class="tile">
          <summary><span class="tile-ico">&#128249;</span> Discover Cameras</summary>
          <p>Pick the NVR row in <b>Select NVR</b> (or fill <b>IP / Web Port / admin credentials</b> in the first row), then click <b>Discover Cameras</b>.
             Every camera on that NVR appears below (channel, name, IP, port, decrypted login, online status) &mdash;
             select rows and <b>Send to Table</b> to add them as device rows. Works on Tiandy cameras too.</p>
        </details>
        <details class="tile">
          <summary><span class="tile-ico">&#128202;</span> Google Sheet Sync</summary>
          <p>Open your Google Sheet &rarr; <b>Extensions &rarr; Apps Script</b>, paste <code>google_sheet_sync_script.gs</code> (from this project folder), deploy as a <b>Web App</b> (Execute as Me, Access: Anyone) and paste the URL in the box next to <b>Select NVR</b>. Then: pick the NVR row &rarr; <b>Discover Cameras</b> &rarr; <b>Sync to Google Sheet</b>. NVR login + Common (read-only) user + camera logins land in the Devices/Latest tabs; the Dashboard tab builds itself (branch dropdown + summary).</p>
        </details>
        <details class="tile">
          <summary><span class="tile-ico">&#128268;</span> Service ports</summary>
          <p>HTTP / HTTPS / RTSP changed read-modify-write on
             <code>/ISAPI/System/Network/interfaces/IPandPort/1</code>. Defaults: 80 / 443 / 554.
             Leave blank to keep. A reboot applies new ports &mdash; auto-reboot checkbox triggers it.</p>
        </details>
        <details class="tile">
          <summary><span class="tile-ico">&#128100;</span> Common user + replay</summary>
          <p>Fill <b>BOTH</b> Common Username &amp; Password (or neither). Creates/updates a read-only
             Viewer (Authority = <b>Common</b>) and then <b>automatically ticks Manual +
             Shutdown/Reboot (Local &amp; Remote) and grants playback &amp; preview on ALL
             channels, local + web</b> &mdash; the same setup as ticking "All" by hand. Username needs
             <b>&ge; 6 characters</b> ('dmkuser1' works, 'dmk' does not). If the user fails but other changes
             applied, the result shows <b>PARTIAL</b>.</p>
        </details>
        <details class="tile">
          <summary><span class="tile-ico">&#9888;&#65039;</span> Be careful</summary>
          <p>Tiandy locks the admin username &mdash; only the password is changed. Once changed, the
             <b>old password stops working</b>. Test on <b>1 device</b> first.</p>
        </details>
      </div>

      <div class="sec">Devices</div>
      <div class="table-wrap">
        <table id="devTable-tiandy">
          <thead>
            <tr>
              <th>Branch Name</th><th>IP Address</th><th>Web Port</th><th>Current Username</th>
              <th>Current Password</th><th>New Password</th>
              <th>New HTTP Port</th><th>New HTTPS Port</th><th>New RTSP Port</th>
              <th>Common Username</th><th>Common Password (read-only)</th>
              <th style="width:74px">Action</th>
            </tr>
          </thead>
          <tbody id="tbody-tiandy"></tbody>
        </table>
      </div>

      <div id="discoverPanel">
        <div class="disc-head">
          <h4>&#128249; Discovered cameras <span id="discSummary"></span></h4>
          <span id="discSel"></span>
          <button class="btn" onclick="document.getElementById('discoverPanel').style.display='none'">&#10005; Close</button>
        </div>
        <div class="disc-scroll">
          <table id="discoverTable">
            <thead><tr><th>Ch</th><th>Name</th><th>IP</th><th>Port</th><th>Username</th><th>Password</th><th>Status</th></tr></thead>
            <tbody id="discTbody"></tbody>
          </table>
        </div>
        <div class="disc-actions">
          <button class="btn primary" onclick="sendDiscoveredToTable()">&#10132; Send to Table</button>
          <span class="hint">Click rows to select (click again to deselect). Cameras are added using their decrypted login credentials.</span>
        </div>
      </div>
    </div>
  </div>

  <!-- ================= LOG ================= -->
  <div class="sec">Activity</div>
  <div class="card" style="padding:14px">
    <div class="log-box" id="logBox"></div>
  </div>

  <footer>
    <div class="dev-card">
      <div class="dev-left">
        <div class="dev-avatar">KS</div>
        <div>
          <div class="dev-kicker">Developed by</div>
          <div class="dev-name">Kundan Kumar Singh</div>
          <div class="dev-note">Bulk Device Config Tool</div>
        </div>
      </div>
      <div class="dev-tags">
        <span class="dev-tag">v__VER__</span>
        <span class="dev-tag">UBNT</span>
        <span class="dev-tag">Tiandy</span>
        <span class="dev-tag">Hikvision</span>
      </div>
    </div>
    <div class="foot-fine">Runs entirely on your machine &mdash; device credentials never leave your network.</div>
  </footer>
</div>


<script>
const TOOL_COLUMNS = {
  ubnt: ["ip", "ssh_port", "username", "current_password", "new_username", "new_password", "new_web_port", "new_http_port"],
  tiandy: ["branch_name", "ip", "web_port", "username", "current_password", "new_password", "new_http_port", "new_https_port", "new_rtsp_port", "common_username", "common_password"],
};
const DEFAULT_PORT = { ubnt: "22", tiandy: "80" };
const RING_LEN = 339.29;

function toggleGuides(name) {
  const el = document.getElementById("guides-" + name);
  const btn = document.getElementById("guidesBtn-" + name);
  if (!el || !btn) return;
  const show = el.style.display === "none";
  el.style.display = show ? "" : "none";
  btn.innerHTML = show ? "&#9432; Hide Guides" : "&#9432; Guides &amp; Help";
}

function switchTab(tool) {
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
  document.querySelector(`.tab-btn[onclick="switchTab('${tool}')"]`).classList.add("active");
  document.getElementById("panel-" + tool).classList.add("active");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function setProgress(pct) {
  const ring = document.getElementById("ringFg");
  const txt = document.getElementById("ringPct");
  if (ring) ring.style.strokeDashoffset = (RING_LEN * (1 - pct / 100)).toFixed(2);
  if (txt) txt.textContent = pct + "%";
}

function addRow(tool, values) {
  const cols = TOOL_COLUMNS[tool];
  const portCol = tool === "ubnt" ? "ssh_port" : "web_port";
  values = values || {};
  const tbody = document.getElementById("tbody-" + tool);
  const tr = document.createElement("tr");
  cols.forEach(col => {
    const td = document.createElement("td");
    const inp = document.createElement("input");
    inp.value = values[col] || (col === portCol ? DEFAULT_PORT[tool] : "");
    inp.dataset.col = col;
    if (tool === "tiandy") inp.addEventListener("input", refreshNvrPicker);
    td.appendChild(inp);
    tr.appendChild(td);
  });
  const actionTd = document.createElement("td");
  actionTd.className = "row-actions";
  const delBtn = document.createElement("button");
  delBtn.textContent = "Delete";
  delBtn.onclick = () => { tr.remove(); if (tool === "tiandy") refreshNvrPicker(); };
  actionTd.appendChild(delBtn);
  tr.appendChild(actionTd);
  tbody.appendChild(tr);
  if (tool === "tiandy") refreshNvrPicker();
}

function getRows(tool) {
  const rows = [];
  document.querySelectorAll("#tbody-" + tool + " tr").forEach(tr => {
    const row = {};
    tr.querySelectorAll("input").forEach(inp => { row[inp.dataset.col] = inp.value.trim(); });
    if (row.ip) rows.push(row);
  });
  return rows;
}

function loadFile(tool, input) {
  const file = input.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append("file", file);
  fetch(`/api/${tool}/load`, {method: "POST", body: fd})
    .then(r => r.json())
    .then(data => {
      if (data.error) { alert(data.error); return; }
      document.getElementById("tbody-" + tool).innerHTML = "";
      data.rows.forEach(r => addRow(tool, r));
      logLine(`Loaded ${data.rows.length} rows from ${file.name}`, "dry");
    })
    .catch(e => alert("Load failed: " + e));
  input.value = "";
}

function saveFile(tool, fmt) {
  const rows = getRows(tool);
  fetch(`/api/${tool}/save`, {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({rows: rows, format: fmt})
  }).then(r => {
    if (!r.ok) { r.json().then(d => alert(d.error || "Save failed")); return; }
    return r.blob();
  }).then(blob => {
    if (!blob) return;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${tool}_devices.${fmt}`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

function logLine(text, cls) {
  const box = document.getElementById("logBox");
  const div = document.createElement("div");
  div.className = "log-line " + (cls || "");
  const ts = new Date().toLocaleTimeString();
  div.textContent = `[${ts}] ${text}`;
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

function setButtons(tool, disabled) {
  document.getElementById("dryBtn-" + tool).disabled = disabled;
  document.getElementById("runBtn-" + tool).disabled = disabled;
}

function startRun(tool, dryRun) {
  const rows = getRows(tool);
  if (rows.length === 0) { alert("No devices in the table."); return; }
  const doReboot = (tool === "ubnt" || tool === "tiandy") ? document.getElementById("rebootChk-" + tool).checked : false;

  if (!dryRun) {
    let msg = `${rows.length} device(s) will have REAL changes applied.

`;
    if (tool === "ubnt") {
      const renameCount = rows.filter(r => r.new_username && r.new_username !== r.username).length;
      if (renameCount) {
        msg += `${renameCount} device(s) will also have their USERNAME changed - reboot will ${doReboot ? "happen automatically" : "NOT happen"}.

`;
      }
    }
    const portCount = rows.filter(r => ["new_web_port", "new_http_port", "new_https_port", "new_rtsp_port"].some(c => r[c] && r[c].trim())).length;
    if (portCount) {
      if (tool === "ubnt") {
        msg += `${portCount} device(s) will also have their WEB ports changed (HTTPS and/or HTTP) - reboot will ${doReboot ? "happen automatically" : "NOT happen"}.

`;
      } else {
        msg += `${portCount} device(s) will also have their web ports changed (HTTP/HTTPS/RTSP via ISAPI) - reboot will ${doReboot ? "happen automatically" : "NOT happen"}.

`;
      }
    }
    const commonCount = rows.filter(r => r.common_username && r.common_username.trim() && r.common_password && r.common_password.trim()).length;
    if (commonCount) {
      msg += `${commonCount} device(s) will also get a READ-ONLY user (authority Common) created/updated WITH Manual + Shutdown/Reboot ticked (Local & Remote) and playback & preview permission on all channels (local + web).

`;
    }
    msg += "As soon as the password changes, the old password will stop working. Testing on 1 device first is recommended." + String.fromCharCode(10, 10) + "Continue?";
    if (!confirm(msg)) return;
  }

  setButtons(tool, true);
  setProgress(0);
  document.getElementById("statusBar").textContent = `[${tool}] Processing 0/${rows.length}...`;

  fetch(`/api/${tool}/run`, {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({rows: rows, dry_run: dryRun, do_reboot: doReboot})
  }).then(r => r.json()).then(data => {
    if (data.error) { alert(data.error); setButtons(tool, false); return; }
    const es = new EventSource("/api/stream");
    es.onmessage = (evt) => {
      const item = JSON.parse(evt.data);
      if (item.done) {
        es.close();
        setButtons(tool, false);
        setProgress(100);
        document.getElementById("statusBar").textContent =
          `[${tool}] Done. Success: ${item.success}, Partial: ${item.partial}, Failed: ${item.failed}`;
        let msg = `Total: ${item.total} | Success: ${item.success} | Partial: ${item.partial} | Failed: ${item.failed}`;
        if (item.log_path) msg += String.fromCharCode(10, 10) + "Log saved: " + item.log_path;
        alert(msg);
        return;
      }
      const cls = {"SUCCESS":"success", "PARTIAL":"partial", "FAILED":"fail", "DRY-RUN":"dry"}[item.status] || "";
      logLine(`[${tool}] [${item.i}/${item.total}] ${item.ip} -> ${item.status}: ${item.message}`, cls);
      setProgress(Math.round((item.i / item.total) * 100));
      document.getElementById("statusBar").textContent = `[${tool}] Processing ${item.i}/${item.total}...`;
    };
    es.onerror = () => { es.close(); setButtons(tool, false); };
  }).catch(e => { alert("Run failed: " + e); setButtons(tool, false); });
}

fetch("/api/status").then(r => r.json()).then(s => {
  const warnDiv = document.getElementById("lib-warn");
  let warnings = [];
  if (!s.requests) warnings.push("requests library missing (Tiandy & Hikvision tab disabled) - pip install requests");
  if (!s.crypto) warnings.push("pycryptodome library missing (Tiandy password change disabled) - pip install pycryptodome");
  if (!s.paramiko) warnings.push("paramiko library missing (UBNT tab disabled) - pip install paramiko");
  if (!s.openpyxl) warnings.push("openpyxl missing (Excel load/save disabled) - pip install openpyxl");
  if (warnings.length) warnDiv.innerHTML = '<div class="warn">' + warnings.join("<br>") + '</div>';
});

let DISCOVERED = [];

function updateDiscSel() {
  const n = document.querySelectorAll("#discTbody tr.selected").length;
  document.getElementById("discSel").textContent = n ? `${n} selected` : "";
}

function refreshNvrPicker() {
  const sel = document.getElementById("nvrSelect");
  if (!sel || typeof getRows !== "function") return;
  const rows = getRows("tiandy");
  const prev = sel.value;
  sel.innerHTML = '<option value="">- auto (first row) -</option>' +
    rows.map((r, i) => `<option value="${i}">${r.ip}:${r.web_port || "80"}${r.branch_name ? " - " + r.branch_name : ""}</option>`).join("");
  sel.value = (prev && [...sel.options].some(o => o.value === prev)) ? prev : "";
}

function getPickedNvr() {
  const rows = getRows("tiandy");
  if (!rows.length || !rows[0].ip) return null;
  const sel = document.getElementById("nvrSelect");
  if (sel && sel.value !== "" && rows[+sel.value]) return rows[+sel.value];
  return rows[0];
}

async function discoverCameras() {
  const nvr = getPickedNvr();
  if (!nvr) { alert("Fill a row with the NVR's IP, Web Port, Username and Current Password first."); return; }
  const btn = document.getElementById("discBtn-tiandy");
  btn.disabled = true; btn.textContent = "Discovering...";
  document.getElementById("statusBar").textContent = `Discovering cameras on ${nvr.ip}...`;
  try {
    const resp = await fetch("/api/tiandy/discover", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ip: nvr.ip, web_port: nvr.web_port, username: nvr.username, current_password: nvr.current_password})
    });
    const data = await resp.json();
    if (!resp.ok || data.error) { alert(data.error || "Discovery failed"); return; }
    DISCOVERED = data.channels || [];
    const tb = document.getElementById("discTbody");
    tb.innerHTML = "";
    DISCOVERED.forEach((c, idx) => {
      const tr = document.createElement("tr");
      tr.dataset.idx = idx;
      [c.channel, c.name, c.ip, c.admin_port, c.cam_user, c.cam_pass].forEach(v => {
        const td = document.createElement("td");
        td.textContent = v || "";
        tr.appendChild(td);
      });
      const td = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = "badge " + (c.online ? "ok" : "off");
      badge.textContent = c.online ? "online" : "offline";
      td.appendChild(badge);
      tr.appendChild(td);
      tr.onclick = () => { tr.classList.toggle("selected"); updateDiscSel(); };
      tb.appendChild(tr);
    });
    const online = DISCOVERED.filter(c => c.online).length;
    document.getElementById("discSummary").textContent = `- ${DISCOVERED.length} camera(s) on ${data.ip}:${data.port} (${online} online)`;
    updateDiscSel();
    document.getElementById("discoverPanel").style.display = "block";
    logLine(`Discovered ${DISCOVERED.length} camera(s) on ${data.ip}`, "dry");
    document.getElementById("statusBar").textContent =
      `Discovered ${DISCOVERED.length} camera(s) on ${data.ip}:${data.port}`;
    setProgress(100);
  } catch (e) {
    document.getElementById("statusBar").textContent = "Discovery failed - see the alert for details";
    alert("Discovery failed: " + e);
  } finally {
    btn.disabled = false; btn.textContent = "Discover Cameras";
  }
}

function sendDiscoveredToTable() {
  const sel = [...document.querySelectorAll("#discTbody tr.selected")].map(tr => DISCOVERED[tr.dataset.idx]);
  const cams = sel.length ? sel : DISCOVERED;
  if (!cams.length) { alert("Nothing to add."); return; }
  const nvrRow = getPickedNvr();
  const branch = nvrRow ? (nvrRow.branch_name || "") : "";
  cams.forEach(c => addRow("tiandy", {
    branch_name: branch,
    ip: c.ip, web_port: c.admin_port || "80",
    username: c.cam_user, current_password: c.cam_pass,
    new_password: "", new_http_port: "", new_https_port: "", new_rtsp_port: "",
    common_username: "", common_password: ""
  }));
  logLine(`Added ${cams.length} camera(s) to the device table`, "success");
  document.getElementById("discoverPanel").style.display = "none";
}

// Remember the Google Sheet webhook URL across page reloads (localStorage)
(function initSheetWebhook() {
  const el = document.getElementById("sheetWebhook");
  if (!el) return;
  try {
    el.value = localStorage.getItem("tiandy_sheet_webhook") || "";
    el.addEventListener("input", () => {
      try { localStorage.setItem("tiandy_sheet_webhook", el.value.trim()); } catch (e) {}
    });
  } catch (e) { /* localStorage unavailable - box just stays manual */ }
})();

async function syncToSheet() {
  const nvr = getPickedNvr();
  if (!nvr) { alert("Fill a row with the NVR's IP, Web Port, Username and Current Password first."); return; }
  if (!DISCOVERED.length) { alert("Run Discover Cameras first - the discovered camera list is what gets synced."); return; }
  const url = document.getElementById("sheetWebhook").value.trim();
  if (!url) { alert("Paste your Google Sheet Apps Script Web App URL first (see the Google Sheet Sync guide tile)."); return; }
  const btn = document.getElementById("syncBtn-tiandy");
  btn.disabled = true; btn.textContent = "Syncing...";
  document.getElementById("statusBar").textContent = "Syncing " + DISCOVERED.length + " camera(s) + NVR to Google Sheet...";
  try {
    const resp = await fetch("/api/tiandy/sync_sheet", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({webhook_url: url, nvr: nvr, cameras: DISCOVERED})
    });
    const data = await resp.json();
    if (!resp.ok || data.error) {
      logLine("Google Sheet sync FAILED: " + (data.error || ("HTTP " + resp.status)), "fail");
      document.getElementById("statusBar").textContent = "Google Sheet sync failed - see the log";
      alert(data.error || "Sync failed");
      return;
    }
    (data.warnings || []).forEach(w => logLine("Sheet warning: " + w, "partial"));
    const camTxt = (data.cameras !== undefined) ? " (" + data.cameras + " camera row(s))" : "";
    logLine("Google Sheet sync OK - " + data.rows_added + " row(s) written" + camTxt +
            ((data.warnings || []).length ? " | " + data.warnings.length + " warning(s)" : ""), "success");
    document.getElementById("statusBar").textContent =
      "Google Sheet updated - " + data.rows_added + " row(s) added" + camTxt;
    setProgress(100);
    let msg = "Google Sheet updated - " + data.rows_added + " row(s) added" + camTxt + ".";
    if ((data.warnings || []).length) msg += String.fromCharCode(10, 10) + "Sheet warnings:" + String.fromCharCode(10) + data.warnings.join(String.fromCharCode(10));
    alert(msg);
  } catch (e) {
    document.getElementById("statusBar").textContent = "Google Sheet sync failed - see the alert for details";
    alert("Sync failed: " + e);
  } finally {
    btn.disabled = false; btn.innerHTML = "&#128202; Sync to Google Sheet";
  }
}

addRow("ubnt", {ip:"192.168.1.20", ssh_port:"22", username:"ubnt", current_password:"ubnt", new_username:"", new_password:"NewPass@2026", new_web_port:"", new_http_port:""});
addRow("tiandy", {ip:"192.168.7.60", web_port:"80", username:"admin", current_password:"admin123", new_password:"NewPass@2026", new_http_port:"", new_https_port:"", new_rtsp_port:""});
</script>

</body>
</html>

"""

INDEX_HTML = INDEX_HTML.replace("__VER__", APP_VERSION)


def _get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


if __name__ == "__main__":
    local_ip = _get_local_ip()
    print(f"Starting server... (v{APP_VERSION})")
    print(f"  Open on this PC:          http://localhost:{PORT}")
    if local_ip:
        print(f"  Open from another device on the network: http://{local_ip}:{PORT}")
    print("  (You may need to allow this Python/port through Windows Firewall to access it from another device)")
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)
