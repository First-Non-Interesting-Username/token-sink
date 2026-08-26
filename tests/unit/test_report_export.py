"""Report export tests (issue #236, PLAN §10.6/§13 view 7)."""

from __future__ import annotations

import json

import pytest

from findings.report_export import ExportError, export_report, import_bundle

FINDING = {
    "finding_uuid": "aaaaaaaa-1111-4111-8111-111111111111",
    "title": "Reflected XSS in search parameter",
    "severity": "high",
    "category": "xss",
    "summary": "The q parameter reflects unescaped input.",
    "reproduction": "GET /search?q=<script>alert(1)</script>",
    "impact": "Session takeover of in-scope test users.",
}


def base_evidence():
    return [
        ("http_exchange.txt", b"GET /search?q=%3Cscript%3E HTTP/1.1\n200 OK"),
        ("screenshot.png", b"\x89PNG-fake-binary-bytes"),
    ]


class TestExport:
    def test_markdown_contains_core_sections(self):
        bundle = export_report(FINDING, base_evidence())
        md = bundle.markdown
        for section in ("## Summary", "## Reproduction", "## Impact", "## Evidence"):
            assert section in md
        assert "Reflected XSS" in md
        assert "`http_exchange.txt`" in md

    def test_json_sidecar_matches_markdown_content(self):
        bundle = export_report(FINDING, [])
        assert bundle.report_json["title"] == FINDING["title"]
        assert bundle.report_json["evidence"] == []
        assert len(bundle.report_json["manifest_sha256"]) == 64

    def test_manifest_has_checksums(self):
        bundle = export_report(FINDING, base_evidence())
        names = [f["filename"] for f in bundle.manifest["files"]]
        assert names == ["http_exchange.txt", "screenshot.png"]
        for entry in bundle.manifest["files"]:
            assert len(entry["sha256"]) == 64
            assert entry["size"] > 0


class TestRedactionBeforeExport:
    def test_secret_in_summary_is_redacted(self):
        finding = {
            **FINDING,
            # A live-looking AWS key embedded by a careless agent.
            "summary": "Leaked key AKIAIOSFODNN7EXAMPLE in config.",
        }
        bundle = export_report(finding, [])
        assert "AKIAIOSFODNN7EXAMPLE" not in bundle.markdown
        assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(bundle.report_json)
        assert "[REDACTED:" in bundle.markdown

    def test_secret_in_attachment_is_redacted(self):
        blob = b"Authorization: Bearer ghp_example0000000000000000"  # fake example token, not real

        bundle = export_report(FINDING, [("transcript.txt", blob)])
        assert b"ghp_AAAAAAAA" not in bundle.attachments[0].content
        assert b"[REDACTED:" in bundle.attachments[0].content


class TestRoundTrip:
    def test_bundle_reimports_cleanly(self):
        bundle = export_report(FINDING, base_evidence())
        report = import_bundle(bundle.files())
        assert report["finding_uuid"] == FINDING["finding_uuid"]
        assert report["title"] == FINDING["title"]

    def test_tampered_attachment_fails_import(self):
        bundle = export_report(FINDING, [("a.txt", b"hello")])
        files = bundle.files()
        files["evidence/a.txt"] = b"tampered"
        with pytest.raises(ExportError, match="checksum mismatch"):
            import_bundle(files)

    def test_missing_required_file_fails_import(self):
        with pytest.raises(ExportError, match="missing required file"):
            import_bundle({"report.md": b"x"})

    def test_manifest_referencing_absent_file_fails(self):
        bundle = export_report(FINDING, [("a.txt", b"data")])
        files = bundle.files()
        del files["evidence/a.txt"]
        with pytest.raises(ExportError, match="missing file"):
            import_bundle(files)


class TestValidation:
    def test_requires_finding_uuid(self):
        with pytest.raises(ExportError, match="finding_uuid"):
            export_report({"title": "no id"}, [])

    def test_files_mapping_complete(self):
        bundle = export_report(FINDING, [("a.txt", b"d")])
        files = bundle.files()
        assert set(files) == {
            "report.md",
            "report.json",
            "evidence/manifest.json",
            "evidence/a.txt",
        }
