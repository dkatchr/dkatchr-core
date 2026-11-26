"""KEVClient.recent(): newest catalog additions, from cache or download, never raises."""
import json
import time

from dkatchr.clients import kev as kev_mod
from dkatchr.clients.kev import KEVClient

CATALOG = {"vulnerabilities": [
    {"cveID": "CVE-2024-1", "vulnerabilityName": "Old bug", "vendorProject": "Acme",
     "product": "Widget", "dateAdded": "2024-01-02", "knownRansomwareCampaignUse": "Unknown"},
    {"cveID": "CVE-2026-9", "vulnerabilityName": "New bug", "vendorProject": "Acme",
     "product": "Gadget", "dateAdded": "2026-11-20", "knownRansomwareCampaignUse": "Known"},
    {"cveID": "CVE-2026-3", "vulnerabilityName": "Same day", "dateAdded": "2026-11-20"},
    {"vulnerabilityName": "no id"},
]}


def _write_cache(tmp_path, data, fetched_at):
    (tmp_path / "kev_catalog.json").write_text(json.dumps(data))
    (tmp_path / "kev_meta.json").write_text(json.dumps({"fetched_at": fetched_at}))


def test_recent_from_fresh_cache(tmp_path):
    _write_cache(tmp_path, CATALOG, int(time.time()))
    c = KEVClient(str(tmp_path))
    rows = c.recent(2)
    assert [r["cve_id"] for r in rows] == ["CVE-2026-9", "CVE-2026-3"]
    assert rows[0] == {"cve_id": "CVE-2026-9", "name": "New bug", "vendor": "Acme",
                       "product": "Gadget", "date_added": "2026-11-20", "known_ransomware": True}
    assert c.load() == {"CVE-2024-1", "CVE-2026-9", "CVE-2026-3"}


def test_recent_from_download(tmp_path, monkeypatch):
    class Resp:
        def raise_for_status(self): pass
        def json(self): return CATALOG
    monkeypatch.setattr(kev_mod.requests, "get", lambda *a, **k: Resp())
    c = KEVClient(str(tmp_path))
    assert c.recent(1)[0]["cve_id"] == "CVE-2026-9"
    assert (tmp_path / "kev_catalog.json").exists()


def test_recent_stale_cache_when_download_fails(tmp_path, monkeypatch):
    _write_cache(tmp_path, CATALOG, 0)
    def boom(*a, **k): raise OSError("offline")
    monkeypatch.setattr(kev_mod.requests, "get", boom)
    assert len(KEVClient(str(tmp_path)).recent(10)) == 3


def test_recent_empty_when_nothing_available(tmp_path, monkeypatch):
    def boom(*a, **k): raise OSError("offline")
    monkeypatch.setattr(kev_mod.requests, "get", boom)
    c = KEVClient(str(tmp_path))
    assert c.recent() == [] and c.load() == set()
