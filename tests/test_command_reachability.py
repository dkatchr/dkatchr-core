"""Packages used by RUNNING their program, not importing it: OCRmyPDF called
as a subprocess from Ruby made pillow (its dependency) look unused."""

import io
import tarfile

import ahocorasick

from dkatchr.clients.resolvers.pypi import console_scripts
from dkatchr.clients.resolvers.rubygems import gemspec_executables
from dkatchr.core.reachability import _grep_tar_stream, build_command_patterns


def test_console_scripts():
    text = "[console_scripts]\nocrmypdf = ocrmypdf.__main__:run\n\n[gui_scripts]\nviewer = x:y\n[pytest11]\nplug = a:b\n"
    assert console_scripts(text) == ["ocrmypdf", "viewer"]


def test_gemspec_executables():
    meta = "--- !ruby/object:Gem::Specification\nname: puma\nexecutables:\n- puma\n- pumactl\nextensions: []\n"
    assert gemspec_executables(meta) == ["puma", "pumactl"]
    assert gemspec_executables("name: x\nexecutables: []\n") == []


def test_command_patterns_skip_short_names():
    quoted, bare = build_command_patterns(["ocrmypdf", "tox"])
    assert '"ocrmypdf"' in quoted and " ocrmypdf " in bare
    assert not any("tox" in p for p in quoted + bare)


def _tar(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    buf.seek(0)
    return buf


def _grep(files, patterns, quoted, bare):
    auto = ahocorasick.Automaton()
    for p in patterns:
        auto.add_word(p, p)
    auto.make_automaton()
    return _grep_tar_stream(_tar(files), auto, patterns, exclude_test_files=True,
                            allow_early_exit=False,
                            command_patterns=frozenset(quoted + bare),
                            bare_command_patterns=frozenset(bare))


def test_invocations_count_where_programs_run():
    quoted, bare = build_command_patterns(["ocrmypdf"])
    patterns = ["import ocrmypdf"] + quoted + bare   # "import ocrmypdf" is an IMPORT pattern
    m = _grep({
        "r/lib/ocr/command.rb": 'EXECUTABLE = "ocrmypdf"\n',              # quoted, source -> counts
        "r/docker/Dockerfile": "RUN ocrmypdf --version\n",                 # bare, command file -> counts
        "r/README.md": "We run ocrmypdf on PDFs.\n",                       # not scanned
        "r/app/notes.py": "# ocrmypdf is great \n",                         # bare in source -> ignored
        "r/files/requirements.txt": '"ocrmypdf"\n',                         # manifest -> ignored
        "r/ci/build.sh": "import ocrmypdf.helpers\n",                       # import pattern in a shell file -> ignored
    }, patterns, quoted, bare)
    hits = {f for p in patterns for f in m[p]}
    assert hits == {"r/lib/ocr/command.rb", "r/docker/Dockerfile"}
