"""Daemon-path tests: agent-side enqueue is local-only and writes RAW inputs; the daemon
re-derives + re-validates and fails closed. All offline (no Chrome, no gh)."""
import json
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gptc  # noqa: E402


def _args(**kw):
    base = dict(task="", title="c", role="", link=[], kind="consult", conversation="",
                allow_nolink=False, out="", rid="r1", timeout=10, allow_gist=False)
    base.update(kw)
    return types.SimpleNamespace(**base)


def _boom(_slug):
    raise AssertionError("gate_local must not touch the network")


def test_gate_local_catches_secret_without_network():
    ok, reason = gptc.gate_local("token sk-ant-api03-" + "A" * 20, ["a/b"])
    assert not ok and "secret-like" in reason


def test_gate_local_resolves_without_calling_gh(monkeypatch):
    monkeypatch.setattr(gptc, "_repo_is_public", _boom)
    ok, res = gptc.gate_local("review this", ["a/b"])
    assert ok and res[0]["slug"] == "a/b"


def test_enqueue_writes_raw_job(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "_repo_is_public", _boom)  # enqueue must not call it
    assert gptc.cmd_enqueue(_args(task="review it", link=["a/b"], rid="r1")) == 0
    job = json.loads((tmp_path / "spool" / "pending" / "r1.json").read_text())
    # RAW inputs only — no rendered prompt, no derived slugs
    assert job["kind"] == "consult" and job["links"] == ["a/b"] and job["task"] == "review it"
    assert "prompt" not in job and "slugs" not in job


def test_enqueue_refuses_secret_locally(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    assert gptc.cmd_enqueue(_args(task="ctx sk_live_" + "1" * 20, link=["a/b"], rid="r2")) == 2
    assert not (tmp_path / "spool" / "pending" / "r2.json").exists()


def test_enqueue_followup_needs_link_or_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    a = _args(kind="followup", task="round 2", link=[], conversation="cid", rid="r5")
    assert gptc.cmd_enqueue(a) == 2  # no link, no --allow-nolink
    a2 = _args(kind="followup", task="round 2", link=[], conversation="cid",
               rid="r6", allow_nolink=True)
    assert gptc.cmd_enqueue(a2) == 0


def _raw(**kw):
    base = dict(rid="j", kind="consult", task="clean", title="t", role="r",
                links=["a/b"], allow_nolink=False, allow_gist=False,
                conversation_id=None, timeout=10, out="/tmp/x.txt")
    base.update(kw)
    return base


def test_daemon_refuses_private_repo(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: False)
    gptc._ensure_spool()
    gptc._process_job(_raw(rid="r3", out=str(tmp_path / "ans.txt")))
    st = json.loads((tmp_path / "spool" / "status" / "r3.json").read_text())
    assert st["state"] == "refused" and "public" in st["reason"]


def test_daemon_rescans_raw_inputs_for_secret(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: True)
    gptc._ensure_spool()
    gptc._process_job(_raw(rid="r4", task="leak sk-ant-api03-" + "A" * 20,
                           out=str(tmp_path / "a.txt")))
    st = json.loads((tmp_path / "spool" / "status" / "r4.json").read_text())
    assert st["state"] == "refused"


def test_daemon_refuses_forged_kind(tmp_path, monkeypatch):
    """GPT finding #1: any kind other than consult/followup must not slip past the link
    checks and get sent. Now rejected outright."""
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: True)
    gptc._ensure_spool()
    gptc._process_job({"rid": "r7", "kind": "anything",
                       "prompt": "private base64 payload", "slugs": []})
    st = json.loads((tmp_path / "spool" / "status" / "r7.json").read_text())
    assert st["state"] == "refused" and "bad kind" in st["reason"]


def test_daemon_refuses_unknown_fields(tmp_path, monkeypatch):
    """A forged job smuggling a pre-rendered 'prompt' field is rejected (strict schema)."""
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: True)
    gptc._ensure_spool()
    gptc._process_job(_raw(rid="r8", prompt="agent-supplied rendered payload"))
    st = json.loads((tmp_path / "spool" / "status" / "r8.json").read_text())
    assert st["state"] == "refused" and "unknown job fields" in st["reason"]
