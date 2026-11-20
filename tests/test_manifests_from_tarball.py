"""Monorepos: manifests come from ONE repo tarball instead of one contents-API
call each; small repos and anything missing from the tarball use per-file calls."""

import io
import tarfile

from dkatchr.core.scanner import Scanner


class _Stream(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def _tarball(files: dict[str, str]) -> _Stream:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(f"acme-mono-abc123/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return _Stream(buf.getvalue())


class _GitHub:
    def __init__(self, n, missing_from_tar=()):
        self.paths = [f"mod{i}/package.json" for i in range(n)]
        self.files = {p: '{"dependencies": {"lodash": "4.17.21"}}' for p in self.paths}
        self.missing = set(missing_from_tar)
        self.fetched, self.tarballs = [], 0

    def get_branch_sha(self, owner, repo, branch):
        return "abc123"

    def get_repo_tree(self, owner, repo, sha):
        return [{"type": "blob", "path": p} for p in self.paths]

    def fetch_file(self, owner, repo, path, ref):
        self.fetched.append(path)
        return self.files[path]

    def open_repo_tarball_stream(self, full_name, ref="HEAD", on_progress=None):
        self.tarballs += 1
        return _tarball({p: t for p, t in self.files.items() if p not in self.missing}), "ok"


class _Cache:
    def read(self, *a):
        return None

    def get_index_sha(self, *a):
        return None

    def write(self, *a):
        pass


def _scan(gh, size_kb):
    s = Scanner(github=gh, cache=_Cache(), package_config={})
    repo = {"owner": {"login": "acme"}, "name": "mono", "full_name": "acme/mono",
            "default_branch": "main", "size": size_kb}
    return s.scan_repo(repo, "[1/1]", full_rescan=True)


def test_monorepo_reads_manifests_from_one_tarball():
    gh = _GitHub(40, missing_from_tar={"mod7/package.json"})
    result = _scan(gh, size_kb=50_000)
    assert gh.tarballs == 1
    assert gh.fetched == ["mod7/package.json"]               # only what the tarball lacked
    assert len({r["file"] for r in result["inventory"]}) >= 1


def test_small_repo_uses_per_file_calls():
    gh = _GitHub(5)
    _scan(gh, size_kb=50_000)
    assert gh.tarballs == 0 and len(gh.fetched) == 5


def test_huge_repo_uses_per_file_calls():
    gh = _GitHub(40)
    _scan(gh, size_kb=10 * 1024 * 1024)
    assert gh.tarballs == 0 and len(gh.fetched) == 40
