"""Maven / NuGet import names keep their real package depth (0.8.5).

A two-segment cut made parquet-avro resolve to `org.apache` and Scrutor to
`Microsoft.Extensions` (via referenced types), so nearly every Java / .NET
finding looked reachable.
"""
import io
import json
import os
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from unittest import mock

from dkatchr.clients.resolvers import ImportNameResolver
from dkatchr.clients.resolvers import nuget as nuget_mod
from dkatchr.clients.resolvers.maven import MavenResolver, class_package, collapse_packages
from dkatchr.core.reachability import build_import_patterns


def _jar(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


class MavenDepthTest(unittest.TestCase):
    def test_class_package(self):
        self.assertEqual(class_package("org/apache/parquet/avro/AvroReadSupport.class"),
                         "org.apache.parquet.avro")
        self.assertEqual(class_package("okhttp3/Address.class"), "okhttp3")
        self.assertIsNone(class_package("Foo.class"))
        self.assertIsNone(class_package("META-INF/versions/9/org/x/Y.class"))
        self.assertIsNone(class_package("org/x/module-info.class"))

    def test_collapse_keeps_shallowest(self):
        self.assertEqual(collapse_packages({"a.b.c", "a.b.c.d", "a.b.e", "x.y"}),
                         ["a.b.c", "a.b.e", "x.y"])

    def test_class_path_fallback_full_depth(self):
        jar = _jar({"org/apache/parquet/avro/A.class": "", "org/apache/parquet/avro/io/B.class": "",
                    "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"})
        r = MavenResolver()
        with mock.patch.object(r, "_download_bytes", return_value=jar):
            names, source = r.resolve("org.apache.parquet:parquet-avro", "1.10.0")
        self.assertEqual((names, source), (["org.apache.parquet.avro"], "jar_class_paths"))

    def test_broad_pattern_no_longer_matches_unrelated_import(self):
        patterns = build_import_patterns(["org.apache.parquet.avro"], "maven")
        line = "import org.apache.nifi.action.component.details.ComponentDetails;"
        self.assertFalse(any(p in line for p in patterns))
        self.assertTrue(any(p in "import org.apache.parquet.avro.AvroParquetWriter;" for p in patterns))


class NuGetOwnTypesTest(unittest.TestCase):
    def test_filter_keeps_depth_and_drops_embedded(self):
        got = nuget_mod._filter_namespaces(
            {"Microsoft.Extensions.Configuration.Json", "Microsoft.Extensions.Configuration",
             "Microsoft.CodeAnalysis", "FxResources.Microsoft.Extensions", "System.Text", "<Module>"},
            "Microsoft.Extensions.Configuration.Json")
        self.assertEqual(got, {"Microsoft.Extensions.Configuration"})

    def test_roslyn_keeps_its_namespace(self):
        self.assertEqual(nuget_mod._filter_namespaces({"Microsoft.CodeAnalysis"}, "Microsoft.CodeAnalysis.Common"),
                         {"Microsoft.CodeAnalysis"})

    def test_only_typedef_table_is_read(self):
        def table(*names):
            return SimpleNamespace(table_rows=[SimpleNamespace(string_stream_references={"TypeNamespace": n}) for n in names])
        pe = SimpleNamespace(metadata_tables_lookup={"TypeDef": table("Scrutor"),
                                                     "TypeRef": table("Microsoft.Extensions.Logging")},
                             get_string=lambda a: a)
        self.assertEqual(nuget_mod._extract_namespaces(b"", lambda _b: pe), {"Scrutor"})


class CacheRevisionTest(unittest.TestCase):
    def test_old_maven_entry_is_a_miss_but_pypi_entry_still_hits(self):
        with tempfile.TemporaryDirectory() as d:
            res = ImportNameResolver(cache_dir=d)
            for eco, pkg, names in (("maven", "g:a", ["org.apache"]), ("pypi", "requests", ["requests"])):
                path = res._cache_path(pkg, eco)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                json.dump({"schema": 2, "ecosystem": eco, "package": pkg, "import_names": names}, open(path, "w"))
            self.assertIsNone(res._cache_read("g:a", "maven"))
            self.assertEqual(res._cache_read("requests", "pypi"), ["requests"])


if __name__ == "__main__":
    unittest.main()
