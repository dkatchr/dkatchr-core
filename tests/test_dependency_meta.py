"""DependencyMetaClient parsing + caching (no network)."""

from dkatchr.clients import dependency_meta as dm
from dkatchr.clients.dependency_meta import (
    DependencyMetaClient, parse_go_mod_requires, parse_requires_dist,
)


def test_parse_requires_dist_marks_conditional_requirements():
    meta = ("Name: requests\nRequires-Dist: certifi (>=2017.4.17)\n"
            "Requires-Dist: PySocks!=1.5.7,>=1.5.6; extra == 'socks'\n"
            "Requires-Dist: pywin32; sys_platform == 'win32'\n"
            "Requires-Dist: charset_normalizer<4,>=2\n"
            "Requires-Dist: idna; extra == 'x'\nRequires-Dist: idna\n")
    assert parse_requires_dist(meta) == [("PySocks", True), ("certifi", False),
                                         ("charset_normalizer", False), ("idna", False),
                                         ("pywin32", True)]


def test_parse_go_mod():
    gm = ("module x\n\nrequire github.com/a/b v1.0.0\n\nrequire (\n"
          "\tgithub.com/c/d v1.2.0 // indirect\n\tgolang.org/x/net v0.1.0\n)\n")
    assert parse_go_mod_requires(gm) == ["github.com/a/b", "github.com/c/d", "golang.org/x/net"]


class _Resp:
    def __init__(self, status, payload=None, text=""):
        self.status_code, self._p, self.text = status, payload, text

    def json(self):
        return self._p

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(self.status_code)


def test_pypi_uses_pep658_and_caches(tmp_path, monkeypatch):
    calls = []

    def fake_get(self, eco, url, stream=False):
        calls.append(url)
        if url.endswith("/json"):
            return _Resp(200, {"urls": [{"packagetype": "bdist_wheel", "filename": "r-1-py3-none-any.whl",
                                         "url": "https://files/r.whl"}]})
        return _Resp(200, text="Requires-Dist: certifi\n")
    monkeypatch.setattr(DependencyMetaClient, "_get", fake_get)
    c = DependencyMetaClient(str(tmp_path))
    assert c.get_dependencies("PyPI", "requests", "2.31.0") == [("certifi", False)]
    assert calls[-1] == "https://files/r.whl.metadata"
    n = len(calls)
    assert c.get_dependencies("PyPI", "requests", "2.31.0") == [("certifi", False)]
    assert len(calls) == n                                   # permanent cache hit


def test_sdist_only_is_unknown_and_transient_failure_not_cached(tmp_path, monkeypatch):
    monkeypatch.setattr(DependencyMetaClient, "_get",
                        lambda self, eco, url, stream=False: _Resp(200, {"urls": [{"packagetype": "sdist"}]}))
    c = DependencyMetaClient(str(tmp_path))
    assert c.get_dependencies("PyPI", "pycrypto", "2.6.1") is None
    monkeypatch.setattr(DependencyMetaClient, "_get",
                        lambda self, eco, url, stream=False: (_ for _ in ()).throw(OSError("net down")))
    assert c.get_dependencies("PyPI", "other", "1.0") is None
    monkeypatch.setattr(DependencyMetaClient, "_get",
                        lambda self, eco, url, stream=False: _Resp(200, {"urls": [
                            {"packagetype": "bdist_wheel", "url": "u", "filename": "o-none-any.whl"}]})
                        if url.endswith("/json") else _Resp(200, text=""))
    assert c.get_dependencies("PyPI", "other", "1.0") == []  # retried, not stuck at the failure


def test_unsupported_ecosystem_is_unknown(tmp_path):
    assert DependencyMetaClient(str(tmp_path)).get_dependencies("Maven", "a:b", "1") is None


def test_go_escaping():
    assert dm._go_escape("github.com/Azure/x") == "github.com/!azure/x"
