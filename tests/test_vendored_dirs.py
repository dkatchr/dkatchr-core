"""Committed third-party code is not the repo's own use of a package (0.8.6)."""
import io
import tarfile

import ahocorasick

from dkatchr.core.reachability import _grep_tar_stream, _is_third_party
from dkatchr.parsers.runtime import is_runtime_source


def _tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf


def test_is_third_party():
    assert _is_third_party("root/svc/vendor/golang.org/x/net/proxy/proxy.go")
    assert _is_third_party("root/web/node_modules/lodash/index.js")
    assert not _is_third_party("root/cmd/setup.go")
    assert not _is_third_party("vendor/app.go")          # archive root named vendor
    assert not _is_third_party("root/vendor.go")


def test_vendored_import_does_not_count():
    pattern = '"golang.org/x/crypto/ssh"'
    auto = ahocorasick.Automaton()
    auto.add_word(pattern, pattern)
    auto.make_automaton()
    files = {"root/svc/vendor/github.com/a/b/c.go": f"import {pattern}\n",
             "root/cmd/main.go": "package main\n"}
    hits = _grep_tar_stream(_tar(files), auto, [pattern], exclude_test_files=True,
                            allow_early_exit=False)
    assert not hits.get(pattern)
    files["root/cmd/main.go"] = f"import {pattern}\n"
    hits = _grep_tar_stream(_tar(files), auto, [pattern], exclude_test_files=True,
                            allow_early_exit=False)
    assert [h.split("/", 1)[1] for h in hits[pattern]] == ["cmd/main.go"]


def test_runtime_parser_uses_the_shared_list():
    assert not is_runtime_source("node_modules/x/package.json")
    assert is_runtime_source("package.json")
