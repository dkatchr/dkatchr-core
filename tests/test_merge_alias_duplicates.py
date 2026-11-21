"""The same bug published by two databases (GHSA + PYSEC, GHSA + GO) is one
finding, not two."""

from dkatchr.core.osv_enrichment import merge_alias_duplicates, osv_rows_for_repo


def _rec(vid, aliases=(), **kw):
    return {"id": vid, "aliases": list(aliases), **kw}


def test_ghsa_and_pysec_for_one_cve_merge_into_ghsa():
    ghsa = _rec("GHSA-3wvg", ["CVE-2021-27922"], severity=[{"type": "CVSS_V3", "score": "x"}],
                database_specific={"cwe_ids": ["CWE-400"]})
    pysec = _rec("PYSEC-2021-41", ["CVE-2021-27922", "GHSA-3wvg"], summary="pillow DoS",
                 affected=[{"package": {"name": "pillow"}, "ranges": []}])
    out = merge_alias_duplicates([pysec, ghsa], "PyPI")
    assert len(out) == 1
    m = out[0]
    assert m["id"] == "GHSA-3wvg"
    assert m["aliases"] == ["CVE-2021-27922", "PYSEC-2021-41"]
    assert m["summary"] == "pillow DoS"                       # filled from PYSEC
    assert m["database_specific"]["cwe_ids"] == ["CWE-400"]
    assert len(m["affected"]) == 1
    assert "aliases" in ghsa and ghsa["aliases"] == ["CVE-2021-27922"]   # input untouched


def test_shared_cve_without_cross_reference_still_merges():
    out = merge_alias_duplicates([_rec("GHSA-a", ["CVE-1"]), _rec("PYSEC-1", ["CVE-1"])], "PyPI")
    assert [r["id"] for r in out] == ["GHSA-a"]


def test_go_keeps_the_go_record_and_malware_keeps_mal():
    out = merge_alias_duplicates([_rec("GHSA-g", ["CVE-9"]), _rec("GO-2024-1", ["CVE-9", "GHSA-g"])], "Go")
    assert out[0]["id"] == "GO-2024-1" and "GHSA-g" in out[0]["aliases"]
    out = merge_alias_duplicates([_rec("GHSA-m", ["MAL-2024-7"]), _rec("MAL-2024-7")], "npm")
    assert out[0]["id"] == "MAL-2024-7"


def test_distinct_bugs_stay_separate_and_chains_merge():
    out = merge_alias_duplicates([_rec("GHSA-1", ["CVE-1"]), _rec("GHSA-2", ["CVE-2"])], "PyPI")
    assert len(out) == 2
    chain = [_rec("GHSA-1", ["CVE-1"]), _rec("PYSEC-1", ["CVE-1", "BIT-1"]), _rec("BIT-1")]
    assert len(merge_alias_duplicates(chain, "PyPI")) == 1


def test_one_row_per_bug_in_repo_output():
    merged = merge_alias_duplicates([_rec("GHSA-a", ["CVE-1"]), _rec("PYSEC-1", ["CVE-1"])], "PyPI")
    dep = {"file": "requirements.txt", "ecosystem": "PyPI", "package": "pillow",
           "version": "7.2.0", "version_source": "declared", "origin": "registry"}
    rows = osv_rows_for_repo("o/r", [dep], {("PyPI", "pillow", "7.2.0"): merged})
    assert [(r["vuln_id"], r["aliases"]) for r in rows] == [("GHSA-a", "CVE-1,PYSEC-1")]
