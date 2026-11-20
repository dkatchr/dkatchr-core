"""NVDClient: API key travels as the `apiKey` header, never a query param, and
a 404 (a rejected request — NVD answers unknown CVEs with 200 + zero results)
is never cached as a permanent "not found"."""

import json

from dkatchr.clients import nvd as nvd_mod
from dkatchr.clients.nvd import NVDClient


class _Resp:
    def __init__(self, status, payload=None):
        self.status_code = status
        self._payload = payload or {}
        self.text = json.dumps(self._payload)
        self.headers = {}

    def json(self):
        return self._payload


def _client(tmp_path, monkeypatch, responses, calls, api_key="k-123"):
    def fake_get(url, params=None, headers=None, timeout=None):
        calls.append({"params": dict(params or {}), "headers": dict(headers or {})})
        return responses.pop(0)
    monkeypatch.setattr(nvd_mod.requests, "get", fake_get)
    c = NVDClient(cache_dir=str(tmp_path), api_key=api_key)
    c.limiter.acquire = lambda *a, **k: None
    return c


def test_api_key_sent_as_header_not_query_param(tmp_path, monkeypatch):
    calls = []
    rec = {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2021-44228"}}]}
    c = _client(tmp_path, monkeypatch, [_Resp(200, rec)], calls)
    assert c.get_cve("CVE-2021-44228") == rec
    assert calls[0]["headers"] == {"apiKey": "k-123"}
    assert "apiKey" not in calls[0]["params"]


def test_no_key_sends_no_header(tmp_path, monkeypatch):
    calls = []
    c = _client(tmp_path, monkeypatch, [_Resp(200, {"totalResults": 0, "vulnerabilities": []})],
                calls, api_key=None)
    c.get_cve("CVE-2099-0001")
    assert calls[0]["headers"] == {}


def test_404_is_not_cached(tmp_path, monkeypatch):
    calls = []
    rec = {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2020-1"}}]}
    c = _client(tmp_path, monkeypatch, [_Resp(404), _Resp(200, rec)], calls)
    assert c.get_cve("CVE-2020-1") is None
    assert c.get_cve("CVE-2020-1") == rec          # retried, not a cached "not found"
    assert len(calls) == 2


def test_legacy_not_found_sentinel_is_refetched(tmp_path, monkeypatch):
    calls = []
    rec = {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2020-2"}}]}
    c = _client(tmp_path, monkeypatch, [_Resp(200, rec)], calls)
    with open(c._cve_path("CVE-2020-2"), "w") as fh:
        json.dump({"not_found": True}, fh)
    assert c.get_cve("CVE-2020-2") == rec
    assert c.get_cve("CVE-2020-2") == rec          # now a real cache hit
    assert len(calls) == 1
