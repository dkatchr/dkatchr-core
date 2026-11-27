"""A dropped download is retried instead of marking the whole repo UNKNOWN (0.8.7)."""
import io

import dkatchr.core.reachability as reach
from dkatchr.core.reachability import _transient_tarball_failure, enrich_reachability
from dkatchr.storage.reachability_cache import ReachabilityCache
from tests.test_reachability_graph import _GitHub, _Stream, _resolver, _rows


class _Dropped(_Stream):
    """Breaks after a few bytes, like 'Connection reset by peer' mid-download."""
    def read(self, n=-1):
        if self.tell() > 10:
            raise ConnectionResetError(54, "Connection reset by peer")
        return super().read(min(n, 11) if n and n > 0 else 11)


class _Flaky(_GitHub):
    def __init__(self, files, failures, how="stream"):
        super().__init__(files)
        self.failures, self.how = failures, how

    def open_repo_tarball_stream(self, repo, ref=None, on_progress=None):
        stream, _ = super().open_repo_tarball_stream(repo, ref, on_progress)
        if self.calls <= self.failures:
            if self.how == "http":
                return None, "http_502"
            if self.how == "404":
                return None, "http_404"
            return _Dropped(stream.getvalue()), None
        return stream, None


def _run(tmp_path, monkeypatch, gh, events=None):
    monkeypatch.setattr(reach, "REACHABILITY_TARBALL_RETRY_BACKOFF", 0)
    _resolver(monkeypatch, {"requests": ["requests"]})
    rows = _rows("requests")
    enrich_reachability(rows, "o/r", "sha", gh, ReachabilityCache(str(tmp_path)), str(tmp_path),
                        on_progress=(events.append if events is not None else None))
    return rows[0]


def test_dropped_stream_is_retried(tmp_path, monkeypatch):
    events = []
    gh = _Flaky({"app.py": "import requests\n"}, failures=1)
    row = _run(tmp_path, monkeypatch, gh, events)
    assert gh.calls == 2 and row["reachability"] == "REACHABLE"
    assert any(e.get("phase") == "tarball_retry" for e in events)
    assert not any(e.get("phase") == "tarball_failed" for e in events)


def test_5xx_retried_then_gives_up(tmp_path, monkeypatch):
    gh = _Flaky({"app.py": "import requests\n"}, failures=99, how="http")
    row = _run(tmp_path, monkeypatch, gh)
    assert gh.calls == reach.REACHABILITY_TARBALL_ATTEMPTS
    assert row["reachability"] == "UNKNOWN" and "http_502" in row["reachability_evidence"]


def test_permanent_failure_not_retried(tmp_path, monkeypatch):
    gh = _Flaky({"app.py": "import requests\n"}, failures=99, how="404")
    assert _run(tmp_path, monkeypatch, gh)["reachability"] == "UNKNOWN"
    assert gh.calls == 1


def test_transient_classifier():
    assert _transient_tarball_failure("stream_error: ProtocolError: Connection broken")
    assert _transient_tarball_failure("network_error: ReadTimeout")
    assert _transient_tarball_failure("http_503") and _transient_tarball_failure("http_429")
    assert not _transient_tarball_failure("http_404")
    assert not _transient_tarball_failure("tarball_too_large: 6 GB")
