"""
Free Fire Guild Glory Bot - single file, Railway ready.

Pipeline:
    guest OAuth            -> access_token
    MajorLogin (AES+proto) -> JWT + GetLoginData URL
    GetLoginData           -> game server ip:port + session token
    TCP connect + LoginReq -> match farm loop -> guild glory

Env vars:
    ACCOUNTS_FILE   default accounts.json
    ACCOUNTS_JSON   inline JSON array, overrides the file
    GUILD_ID        optional guild to join
    REGION          ind | br | na | sg ...   (auto-fallback if wrong)
    FARM_ENABLED    default true
    MATCH_SECONDS   default 120
    RESTART_DELAY   default 15
    DEBUG_PACKETS   default false  -> hex dump of all TCP traffic
    LOG_LEVEL       default INFO
    PORT            default 8080
"""
import base64
import hashlib
import json
import logging
import os
import re
import socket
import struct
import threading
import time

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, jsonify, render_template_string

# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------

def _bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")

ACCOUNTS_FILE = os.getenv("ACCOUNTS_FILE", "accounts.json")
ACCOUNTS_JSON = os.getenv("ACCOUNTS_JSON", "").strip()
GUILD_ID      = os.getenv("GUILD_ID", "").strip()
REGION        = os.getenv("REGION", "ind").strip().lower()
FARM_ENABLED  = _bool("FARM_ENABLED", True)
MATCH_SECONDS = int(os.getenv("MATCH_SECONDS", "120"))
RESTART_DELAY = int(os.getenv("RESTART_DELAY", "15"))
DEBUG_PACKETS = _bool("DEBUG_PACKETS", False)
PORT          = int(os.getenv("PORT", "8080"))

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s | %(levelname)-7s | %(name)-8s | %(message)s",
)
log = logging.getLogger("bot")

# ---------------------------------------------------------------------------
# garena / free fire constants
# ---------------------------------------------------------------------------

OAUTH_URL     = "https://100067.connect.garena.com/oauth/guest/token/grant"
CLIENT_ID     = "100067"
CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"

RELEASE_VERSION = "OB55"
CLIENT_VERSION  = "1.132.3"
UNITY_VERSION   = "2018.4.11f1"
USER_AGENT      = "Dalvik/2.1.0 (Linux; U; Android 9; MI 8 Build/PKQ1.180729.001)"

REGION_HOSTS = {
    "ind": "client.ind.freefiremobile.com",
    "br":  "clientbp.ggblueshark.com",
    "na":  "clientbp.ggpolarbear.com",
    "sg":  "clientbp.ggpolarbear.com",
    "id":  "clientbp.ggpolarbear.com",
    "th":  "clientbp.ggpolarbear.com",
    "vn":  "clientbp.ggpolarbear.com",
    "my":  "clientbp.ggpolarbear.com",
    "me":  "clientbp.ggpolarbear.com",
    "ru":  "clientbp.ggpolarbear.com",
}

JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$")
IP_RE  = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?")

# ---------------------------------------------------------------------------
# protobuf wire codec
# ---------------------------------------------------------------------------

def _varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)

def _tag(field, wire):
    return _varint((field << 3) | wire)

def vint(field, value):
    return _tag(field, 0) + _varint(int(value))

def vstr(field, value):
    b = value if isinstance(value, (bytes, bytearray)) else str(value).encode()
    return _tag(field, 2) + _varint(len(b)) + bytes(b)

def vmsg(field, value):
    return _tag(field, 2) + _varint(len(value)) + bytes(value)

def _read_varint(buf, i):
    result = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, i
        shift += 7

def parse(buf):
    """Lenient decode -> {field_number: [values]}. Unknown fields are kept."""
    out = {}
    i, n = 0, len(buf)
    while i < n:
        try:
            key, i = _read_varint(buf, i)
        except IndexError:
            break
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, i = _read_varint(buf, i)
        elif wire == 2:
            ln, i = _read_varint(buf, i)
            value = bytes(buf[i:i + ln])
            i += ln
        elif wire == 5:
            value = bytes(buf[i:i + 4]); i += 4
        elif wire == 1:
            value = bytes(buf[i:i + 8]); i += 8
        else:
            break
        out.setdefault(field, []).append(value)
    return out

def iter_blobs(fields, depth=0):
    for values in fields.values():
        for v in values:
            if isinstance(v, (bytes, bytearray)):
                yield bytes(v)
                if depth < 3 and 4 <= len(v) <= 4096:
                    sub = parse(v)
                    if sub:
                        yield from iter_blobs(sub, depth + 1)

# ---------------------------------------------------------------------------
# AES helpers
# ---------------------------------------------------------------------------

def aes_key(*parts):
    return hashlib.md5("".join(parts).encode()).hexdigest().encode()

def aes_encrypt(data, key, iv=b"1" * 16):
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data, 16))

def aes_decrypt(data, key, iv=b"1" * 16):
    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), 16)

def try_decrypt(data, key):
    try:
        return aes_decrypt(data, key)
    except Exception:
        return data

# ---------------------------------------------------------------------------
# auth pipeline
# ---------------------------------------------------------------------------

def _headers(auth_token):
    return {
        "User-Agent": USER_AGENT,
        "Content-Type": "application/octet-stream",
        "Accept-Encoding": "gzip, deflate",
        "X-Unity-Version": UNITY_VERSION,
        "ReleaseVersion": RELEASE_VERSION,
        "X-GA": "v1 1",
        "Authorization": f"Bearer {auth_token}",
    }

def guest_login(uid, password, timeout=30):
    r = requests.post(
        OAUTH_URL,
        data={
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "client_type": "2",
        },
        timeout=timeout,
    )
    r.raise_for_status()
    data = r.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError(f"OAuth rejected: {data}")
    return token, (data.get("open_id") or data.get("openid") or "")

def _major_login_body(open_id, access_token):
    game = b""
    game += vstr(1, access_token)
    game += vstr(2, open_id)
    game += vint(3, 4)
    game += vstr(4, "Handheld")
    game += vint(5, 2000)
    game += vstr(6, "Android OS 9 / API-28 (PQ3A.190801.002/1631759359)")
    game += vstr(7, "Handheld")
    game += vint(8, 1280)
    game += vint(9, 720)
    game += vstr(10, "ARMv8-A")
    game += vstr(11, "Adreno (TM) 505")
    game += vstr(12, CLIENT_VERSION)
    game += vstr(13, "en")
    game += vint(14, 1)
    game += vint(15, 2)
    game += vstr(16, "freefire")

    req = b""
    req += vint(1, int(time.time()))
    req += vmsg(2, game)
    req += vstr(3, open_id)
    return req

def major_login(open_id, access_token, region):
    host = REGION_HOSTS.get(region, REGION_HOSTS["ind"])
    key = aes_key(open_id, access_token)
    r = requests.post(
        f"https://{host}/MajorLogin",
        headers=_headers(access_token),
        data=aes_encrypt(_major_login_body(open_id, access_token), key),
        timeout=30,
    )
    r.raise_for_status()
    return parse(try_decrypt(r.content, key))

def major_login_auto(open_id, access_token):
    """Try the configured region first, then fall back through the rest."""
    order = [REGION] + [r for r in REGION_HOSTS if r != REGION]
    last = None
    for region in order:
        try:
            fields = major_login(open_id, access_token, region)
            jwt, url = extract_tokens(fields)
            if jwt or url:
                return fields, region
            last = region
        except Exception as exc:
            last = f"{region}: {exc}"
    raise RuntimeError(f"MajorLogin failed on every region (last={last})")

def get_login_data(jwt, url, open_id=""):
    r = requests.post(url, headers=_headers(jwt), data=b"", timeout=30)
    r.raise_for_status()
    return parse(try_decrypt(r.content, aes_key(open_id, jwt)))

def extract_tokens(fields):
    jwt = url = None
    for blob in iter_blobs(fields):
        s = blob.decode("utf-8", "ignore").strip()
        if not jwt and JWT_RE.match(s):
            jwt = s
        if not url and s.startswith("http") and "logindata" in s.lower():
            url = s
    return jwt, url

def extract_server(fields):
    ip = port = token = None
    for blob in iter_blobs(fields):
        s = blob.decode("utf-8", "ignore").strip()
        if not ip and not s.startswith("eyJ"):
            m = IP_RE.search(s)
            if m:
                ip = m.group(1)
                if m.group(2):
                    port = int(m.group(2))
        if not token and JWT_RE.match(s):
            token = s
    if ip and not port:
        for blob in iter_blobs(fields):
            if len(blob) == 2:
                cand = int.from_bytes(blob, "big")
                if 1000 < cand < 65000:
                    port = cand
                    break
    return ip, port or 10001, token or ""

def jwt_region(jwt):
    """Read lock_region out of the JWT payload - the authoritative region."""
    try:
        payload = jwt.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return (data.get("lock_region") or data.get("region") or "").lower() or None
    except Exception:
        return None

def join_guild(host, jwt, open_id, guild_id):
    body = vint(1, int(guild_id)) + vstr(2, open_id)
    r = requests.post(
        f"https://{host}/JoinGuild",
        headers=_headers(jwt),
        data=aes_encrypt(body, aes_key(open_id, jwt)),
        timeout=30,
    )
    return r.status_code

# ---------------------------------------------------------------------------
# TCP game client
# ---------------------------------------------------------------------------

class GameClient:
    HEADER = ">H"
    TIMEOUT = 15

    def __init__(self, ip, port, token, open_id="", debug=False):
        self.ip, self.port, self.token, self.open_id = ip, port, token, open_id
        self.debug = debug
        self.sock = None
        self.seq = 0

    def connect(self):
        self.sock = socket.create_connection((self.ip, self.port), timeout=self.TIMEOUT)
        self.sock.settimeout(self.TIMEOUT)
        log.info("tcp connected %s:%s", self.ip, self.port)

    def _send(self, payload):
        frame = struct.pack(self.HEADER, len(payload)) + payload
        if self.debug:
            log.info(">> %s", frame.hex())
        self.sock.sendall(frame)

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("socket closed by server")
            buf += chunk
        return buf

    def _recv(self):
        size = struct.unpack(self.HEADER, self._recv_exact(2))[0]
        body = self._recv_exact(size)
        if self.debug:
            log.info("<< %s", body.hex())
        return body

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        finally:
            self.sock = None

    def login(self):
        req = vint(1, int(time.time())) + vstr(2, self.token) + vstr(3, self.open_id)
        self._send(req)
        res = parse(self._recv())
        log.info("tcp login ok (fields=%s)", sorted(res.keys()))
        return res

    def heartbeat(self):
        self.seq += 1
        self._send(vint(1, self.seq))
        try:
            self._recv()
        except socket.timeout:
            pass

    def start_match(self, mode=1):
        self._send(vint(1, int(time.time())) + vint(2, mode) + vint(3, 1))

    def leave_match(self):
        self._send(vint(1, 0))

    def farm(self, match_seconds=120, farm=True):
        if not farm:
            while True:
                self.heartbeat()
                time.sleep(30)
        while True:
            self.start_match()
            time.sleep(match_seconds)
            self.leave_match()
            time.sleep(5)
            self.heartbeat()

# ---------------------------------------------------------------------------
# workers
# ---------------------------------------------------------------------------

WORKERS = []

class Worker(threading.Thread):
    def __init__(self, account):
        super().__init__(daemon=True, name=account["name"])
        self.label = account["name"]
        self.uid = account["uid"]
        self.password = account["password"]
        self.status = "starting"
        self.server = ""
        self.region = REGION
        self.last_error = ""
        self.started = time.time()

    @property
    def uptime(self):
        s = int(time.time() - self.started)
        return f"{s // 3600}h {(s % 3600) // 60}m"

    @property
    def cls(self):
        if self.status == "farming":
            return "ok"
        return "err" if self.last_error else ""

    def snapshot(self):
        return {"name": self.label, "uid": self.uid, "status": self.status,
                "server": self.server, "region": self.region,
                "uptime": self.uptime, "cls": self.cls}

    def run(self):
        while True:
            try:
                self.cycle()
            except Exception as exc:
                self.last_error = f"{type(exc).__name__}: {exc}"
                self.status = "error"
                log.warning("[%s] %s", self.label, self.last_error)
            time.sleep(RESTART_DELAY)

    def cycle(self):
        self.last_error = ""
        self.status = "oauth"
        access_token, open_id = guest_login(self.uid, self.password)
        log.info("[%s] oauth ok (open_id=%s)", self.label, open_id[:12])

        self.status = "major_login"
        fields, self.region = major_login_auto(open_id, access_token)
        jwt, url = extract_tokens(fields)
        if not url:
            url = f"https://{REGION_HOSTS.get(self.region, REGION_HOSTS['ind'])}/GetLoginData"
        real = jwt_region(jwt) if jwt else None
        if real and real in REGION_HOSTS:
            self.region = real
        log.info("[%s] major_login ok region=%s jwt=%s", self.label, self.region, bool(jwt))

        if GUILD_ID:
            try:
                code = join_guild(REGION_HOSTS.get(self.region, REGION_HOSTS["ind"]),
                                  jwt or access_token, open_id, GUILD_ID)
                log.info("[%s] join_guild(%s) -> %s", self.label, GUILD_ID, code)
            except Exception as exc:
                log.info("[%s] join_guild skipped: %s", self.label, exc)

        self.status = "login_data"
        sfields = get_login_data(jwt or access_token, url, open_id)
        ip, port, session_token = extract_server(sfields)
        if not ip:
            raise RuntimeError("no game server in GetLoginData response")
        self.server = f"{ip}:{port}"
        log.info("[%s] server=%s", self.label, self.server)

        self.status = "connecting"
        client = GameClient(ip, port, session_token or jwt or "",
                            open_id=open_id, debug=DEBUG_PACKETS)
        client.connect()
        client.login()

        self.status = "farming"
        log.info("[%s] farming", self.label)
        client.farm(match_seconds=MATCH_SECONDS, farm=FARM_ENABLED)

# ---------------------------------------------------------------------------
# accounts
# ---------------------------------------------------------------------------

def load_accounts():
    if ACCOUNTS_JSON:
        raw = json.loads(ACCOUNTS_JSON)
    elif os.path.exists(ACCOUNTS_FILE):
        with open(ACCOUNTS_FILE) as fh:
            raw = json.load(fh)
    else:
        raw = []
    out = []
    for a in raw:
        uid = str(a.get("guest_uid") or a.get("uid") or "").strip()
        pwd = str(a.get("guest_password") or a.get("password") or "").strip()
        if uid and pwd:
            out.append({"name": a.get("name") or f"guest{uid[-4:]}",
                        "uid": uid, "password": pwd})
    return out

# ---------------------------------------------------------------------------
# web
# ---------------------------------------------------------------------------

app = Flask(__name__)

PAGE = """<!doctype html><html><head><meta charset="utf-8">
<title>FF Glory Bot</title><style>
body{font-family:system-ui,sans-serif;background:#0f1117;color:#e6e6e6;margin:0;padding:28px}
h1{font-size:20px;margin:0 0 6px}p.sub{color:#8b93a7;margin:0 0 20px;font-size:13px}
table{border-collapse:collapse;width:100%}
th,td{padding:9px 12px;border-bottom:1px solid #232936;text-align:left;font-size:14px}
th{color:#8b93a7;font-size:12px;text-transform:uppercase}
.b{padding:2px 9px;border-radius:99px;font-size:12px;background:#1f6feb26;color:#79c0ff}
.b.ok{background:#2ea04326;color:#56d364}.b.err{background:#f8514926;color:#ff7b72}
</style></head><body><h1>FF Guild Glory Bot</h1>
<p class="sub">guild={{guild or 'unset'}} &middot; region={{region}} &middot; farm={{farm}}</p>
<table><tr><th>Account</th><th>UID</th><th>Status</th><th>Server</th><th>Uptime</th></tr>
{% for w in workers %}<tr><td>{{w.name}}</td><td>{{w.uid}}</td>
<td><span class="b {{w.cls}}">{{w.status}}</span></td><td>{{w.server or '-'}}</td>
<td>{{w.uptime}}</td></tr>{% endfor %}</table></body></html>"""

@app.route("/")
def index():
    return render_template_string(PAGE, workers=[w.snapshot() for w in WORKERS],
                                  guild=GUILD_ID, region=REGION, farm=FARM_ENABLED)

@app.route("/healthz")
def healthz():
    return jsonify(status="ok", accounts=len(WORKERS))

@app.route("/api/status")
def api_status():
    return jsonify(accounts=[w.snapshot() for w in WORKERS])

def main():
    accounts = load_accounts()
    log.info("booting %d account(s) on region %s", len(accounts), REGION)
    if not accounts:
        log.warning("no accounts - set ACCOUNTS_JSON or add accounts.json")
    for a in accounts:
        w = Worker(a)
        WORKERS.append(w)
        w.start()
    app.run(host="0.0.0.0", port=PORT, threaded=True)

if __name__ == "__main__":
    main()