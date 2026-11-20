"""Phase 6 pure logic: IOC extraction/normalization, scoring, MITRE mapping, correlation. No network, no DB."""
import pytest

from app.services import ti_analysis as an
from app.services import ti_ioc as ioc

MD5 = "d41d8cd98f00b204e9800998ecf8427e"


@pytest.mark.parametrize("bad", ["10.0.0.1", "192.168.1.5", "127.0.0.1", "169.254.1.1", "224.0.0.1", "999.1.1.1", "", "::1", "198.51.100.7"])
def test_non_routable_ips_are_never_iocs(bad):
    assert ioc.normalize("ip", bad) is None


def test_normalization_and_defang():
    assert ioc.normalize("ip", "45[.]33[.]32[.]156") == "45.33.32.156"
    assert ioc.normalize("domain", "Evil-Example.COM.") == "evil-example.com"
    assert ioc.normalize("domain", "host.local") is None and ioc.normalize("domain", "payload.exe") is None
    assert ioc.normalize("url", "hxxp://Bad.example.org/a?b=1#frag") == "http://bad.example.org/a?b=1"
    assert ioc.normalize("url", "ftp://x.com") is None and ioc.normalize("url", "http://10.1.1.1/x") is None
    assert ioc.normalize("md5", MD5.upper()) == MD5 and ioc.normalize("md5", MD5[:-1]) is None


def test_extract_text_dedupes_and_skips_private_and_filenames():
    r = ioc.extract_text(f"GET http://45.33.32.156/a.php from 45.33.32.156 hash {MD5} dom evil-example.com file x.exe 10.0.0.9")
    assert ("url", "http://45.33.32.156/a.php") in r and ("ip", "45.33.32.156") in r and ("md5", MD5) in r and ("domain", "evil-example.com") in r
    assert not any(v in ("x.exe", "10.0.0.9") for _, v in r) and len(r) == len(set(r))


def test_extract_alert_uses_structured_fields_and_log_text():
    a = ioc.extract_alert({"data": {"srcip": "45.33.32.156", "url": "https://bad.example.org/x"}, "syscheck": {"sha256_after": "a" * 64}, "full_log": "curl evil-example.com"})
    assert {("ip", "45.33.32.156"), ("sha256", "a" * 64), ("domain", "bad.example.org"), ("domain", "evil-example.com")} <= set(a)


def test_provider_scores_and_aggregate():
    assert an.provider_score("virustotal", {"malicious": 10, "suspicious": 2}) == 100 and an.provider_score("virustotal", {}) == 0
    assert an.provider_score("abuseipdb", {"abuse_confidence": 140}) == 100 and an.provider_score("otx", {"pulse_count": 2}) == 40
    g = an.aggregate({"virustotal": {"status": "ok", "score": 60}, "abuseipdb": {"status": "ok", "score": 55}, "otx": {"status": "timeout"}})
    assert (g["score"], g["classification"], g["risk"]) == (65, "suspicious", "medium")
    assert an.aggregate({"virustotal": {"status": "ok", "score": 90}})["risk"] == "critical"


def test_unavailable_feeds_never_produce_a_score():
    u = an.aggregate({"virustotal": {"status": "rate_limited"}, "otx": {"status": "unavailable"}, "abuseipdb": {"status": "timeout"}})
    assert u["score"] is None and u["classification"] == "unknown"
    assert an.aggregate({"virustotal": {"status": "not_found"}})["score"] is None


def test_mitre_only_when_evidence_supports_it():
    f = {"groups": ["authentication_failed"], "src_is_ioc": True, "level": 5, "agent_id": "001", "mitre": []}
    ip = {"type": "ip", "classification": "malicious"}
    assert [m["id"] for m in an.map_mitre(ip, [f, f, f])] == ["T1110"]
    assert an.map_mitre(ip, [f, f]) == []
    assert an.map_mitre({"type": "ip", "classification": "benign"}, [f] * 5) == []
    assert an.map_mitre({"type": "md5", "classification": "malicious"}, [f] * 5) == []
    w = {"groups": ["web", "attack"], "level": 7, "agent_id": "1", "mitre": [{"id": "T1059", "tactic": "Execution", "technique": "Command and Scripting Interpreter"}]}
    assert {m["id"] for m in an.map_mitre({"type": "url", "classification": "suspicious"}, [w])} == {"T1059", "T1190"}


def test_correlation_patterns():
    I = [{"id": 1, "type": "ip", "value": "1.1.1.1", "risk": "high", "score": 75}, {"id": 2, "type": "md5", "value": "x", "risk": "critical", "score": 90}]
    S = [{"ioc_id": 1, "alert_id": "A", "agent_id": "001", "ts": "t1"}, {"ioc_id": 1, "alert_id": "B", "agent_id": "002", "ts": "t2"},
         {"ioc_id": 2, "alert_id": "A", "agent_id": "001", "ts": "t1"}]
    p = an.correlate(I, S)
    assert {x["pattern"] for x in p} == {"multi_host", "linked_iocs"} and p[0]["risk"] == "critical" and an.correlate(I, []) == []
