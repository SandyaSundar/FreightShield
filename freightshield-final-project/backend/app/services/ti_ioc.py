"""IOC extraction + normalization (pure, stdlib only). Private/reserved IPs and non-routable hosts are never IOCs."""
import base64
import ipaddress
import re
from urllib.parse import urlsplit

TYPES = ("ip", "domain", "url", "md5", "sha1", "sha256")
_URL = re.compile(r"\b(?:https?|hxxps?)://[^\s\"'<>\\]+", re.I)
_IP = re.compile(r"(?<![\d.])(?:\d{1,3}(?:\[?\.\]?)){3}\d{1,3}(?![\d.])")
_DOM = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\[?\.\]?))+[a-z]{2,24}\b", re.I)
_HASH = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9a-fA-F])")
_NOT_TLD = {"exe", "dll", "log", "txt", "conf", "json", "sh", "py", "js", "html", "php", "xml", "so", "tmp", "bak", "sys", "ini",
            "local", "internal", "lan", "localdomain", "invalid", "test", "example"}
MAX_LEN = {"url": 2048, "domain": 253}


def refang(s: str) -> str:
    return re.sub(r"hxxp", "http", s.replace("[.]", ".").replace("(.)", "."), flags=re.I)


def is_public_ip(v: str) -> bool:
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def normalize(kind: str, value: str) -> str | None:
    """Canonical form for dedupe, or None if the value is not a valid, routable IOC of that type."""
    v = refang((value or "").strip())
    if not v:
        return None
    if kind == "ip":
        return str(ipaddress.ip_address(v)) if is_public_ip(v) else None
    if kind in ("md5", "sha1", "sha256"):
        n = {"md5": 32, "sha1": 40, "sha256": 64}[kind]
        return v.lower() if re.fullmatch(rf"[0-9a-fA-F]{{{n}}}", v) else None
    if kind == "domain":
        d = v.lower().rstrip(".")
        tld = d.rsplit(".", 1)[-1]
        if len(d) > 253 or "." not in d or tld in _NOT_TLD or not re.fullmatch(r"[a-z0-9.-]+", d) or ".." in d:
            return None
        try:
            ipaddress.ip_address(d)
            return None
        except ValueError:
            return d
    if kind == "url":
        try:
            p = urlsplit(v)
        except ValueError:
            return None
        if p.scheme.lower() not in ("http", "https") or not p.hostname or len(v) > MAX_LEN["url"]:
            return None
        host = p.hostname.lower()
        if not (is_public_ip(host) or normalize("domain", host)):
            return None
        return p._replace(scheme=p.scheme.lower(), netloc=p.netloc.lower(), fragment="").geturl()
    return None


def hash_kind(h: str) -> str | None:
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h)) if re.fullmatch(r"[0-9a-fA-F]+", h or "") else None


def vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def extract_text(text: str) -> list[tuple[str, str]]:
    """IOCs found in free text, deduped, in a stable order. URLs also yield their host as ip/domain."""
    text = refang(str(text or ""))[:50000]
    out: dict[tuple[str, str], None] = {}

    def add(k, v):
        n = normalize(k, v)
        if n:
            out[(k, n)] = None
    for m in _URL.findall(text):
        m = m.rstrip(".,;)")
        add("url", m)
        host = urlsplit(m).hostname or ""
        add("ip" if re.fullmatch(r"[\d.]+", host) else "domain", host)
    for m in _IP.findall(text):
        add("ip", m)
    for m in _HASH.findall(text):
        add(hash_kind(m), m)
    for m in _DOM.findall(text):
        add("domain", m)
    return list(out)


def extract_alert(src: dict) -> list[tuple[str, str]]:
    """IOCs from one Wazuh alert _source: structured fields first, then free text (full_log / description)."""
    data, sc = src.get("data") or {}, src.get("syscheck") or {}
    found: dict[tuple[str, str], None] = {}

    def add(k, v):
        n = normalize(k, v) if v else None
        if n:
            found[(k, n)] = None
    for f in (data.get("srcip"), data.get("dstip"), src.get("srcip")):
        add("ip", f)
    add("url", data.get("url"))
    for f, k in (("md5_after", "md5"), ("sha1_after", "sha1"), ("sha256_after", "sha256")):
        add(k, sc.get(f))
    for t in (src.get("full_log"), (src.get("rule") or {}).get("description"), data.get("url")):
        for k, v in extract_text(t):
            found[(k, v)] = None
    return list(found)
