"""Tests for the hash-chained tamper-evident AuditLog primitive."""
import json

import pytest

from cognis_mil.audit import AuditLog


def test_empty_log_verifies(tmp_path):
    log = AuditLog(tmp_path / "a.log")
    ok, msg = log.verify()
    assert ok
    assert "Empty" in msg


def test_append_returns_entry_with_hash(tmp_path):
    log = AuditLog(tmp_path / "a.log")
    e = log.append({"action": "scan"})
    assert "hash" in e
    assert e["prev"] == "GENESIS"


def test_chain_links_prev_to_hash(tmp_path):
    log = AuditLog(tmp_path / "a.log")
    e1 = log.append({"n": 1})
    e2 = log.append({"n": 2})
    assert e2["prev"] == e1["hash"]


def test_verify_intact_chain(tmp_path):
    log = AuditLog(tmp_path / "a.log")
    for i in range(5):
        log.append({"n": i})
    ok, msg = log.verify()
    assert ok
    assert "5 entries" in msg


def test_verify_detects_body_tamper(tmp_path):
    p = tmp_path / "a.log"
    log = AuditLog(p)
    log.append({"action": "scan"})
    log.append({"action": "approve"})
    lines = p.read_text().splitlines()
    lines[0] = lines[0].replace("scan", "HACKED")
    p.write_text("\n".join(lines) + "\n")
    ok, msg = log.verify()
    assert not ok
    assert "mismatch" in msg.lower()


def test_verify_detects_deleted_line(tmp_path):
    p = tmp_path / "a.log"
    log = AuditLog(p)
    log.append({"n": 1})
    log.append({"n": 2})
    log.append({"n": 3})
    lines = p.read_text().splitlines()
    del lines[1]  # remove middle entry -> prev linkage breaks
    p.write_text("\n".join(lines) + "\n")
    ok, _ = log.verify()
    assert not ok


def test_verify_detects_reordered_lines(tmp_path):
    p = tmp_path / "a.log"
    log = AuditLog(p)
    log.append({"n": 1})
    log.append({"n": 2})
    lines = p.read_text().splitlines()
    lines.reverse()
    p.write_text("\n".join(lines) + "\n")
    ok, _ = log.verify()
    assert not ok


def test_verify_detects_non_json_line(tmp_path):
    p = tmp_path / "a.log"
    log = AuditLog(p)
    log.append({"n": 1})
    with open(p, "a") as f:
        f.write("this is not json\n")
    ok, msg = log.verify()
    assert not ok
    assert "JSON" in msg


def test_append_creates_parent_dir(tmp_path):
    log = AuditLog(tmp_path / "nested" / "deep" / "a.log")
    log.append({"x": 1})
    assert (tmp_path / "nested" / "deep" / "a.log").exists()


def test_appended_lines_are_json(tmp_path):
    p = tmp_path / "a.log"
    log = AuditLog(p)
    log.append({"action": "scan", "meta": {"host": "web01"}})
    for line in p.read_text().splitlines():
        json.loads(line)  # each line must be valid JSON


def test_event_payload_preserved(tmp_path):
    p = tmp_path / "a.log"
    log = AuditLog(p)
    log.append({"actor": "isso", "action": "poam", "id": "web01-001"})
    entry = json.loads(p.read_text().splitlines()[-1])
    assert entry["event"]["id"] == "web01-001"


def test_reopen_continues_chain(tmp_path):
    p = tmp_path / "a.log"
    AuditLog(p).append({"n": 1})
    log2 = AuditLog(p)  # fresh object, same file
    e = log2.append({"n": 2})
    assert e["prev"] != "GENESIS"
    ok, _ = log2.verify()
    assert ok
