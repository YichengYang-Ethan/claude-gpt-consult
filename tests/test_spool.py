"""Daemon-path tests: agent-side enqueue is local-only and writes RAW inputs; the daemon
re-derives + re-validates against a strict schema/grammar and fails closed. All offline."""
import json
import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gptc  # noqa: E402


def _args(**kw):
    base = dict(task="", title="c", role="", link=[], kind="consult", conversation="",
                allow_nolink=False, out="", rid="aaaaaaaa", timeout=10, allow_gist=False)
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
    assert gptc.cmd_enqueue(_args(task="review it", link=["a/b"], rid="a1a1a1a1")) == 0
    job = json.loads((tmp_path / "spool" / "pending" / "a1a1a1a1.json").read_text())
    # RAW inputs only — no rendered prompt, no derived slugs
    assert job["kind"] == "consult" and job["links"] == ["a/b"] and job["task"] == "review it"
    assert "prompt" not in job and "slugs" not in job


def test_enqueue_rejects_nonhex_rid(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    assert gptc.cmd_enqueue(_args(task="x", link=["a/b"], rid="not-hex!")) == 2


def test_enqueue_refuses_secret_locally(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    assert gptc.cmd_enqueue(_args(task="ctx sk_live_" + "1" * 20, link=["a/b"], rid="a2a2a2a2")) == 2
    assert not (tmp_path / "spool" / "pending" / "a2a2a2a2.json").exists()


def test_enqueue_followup_needs_link_or_flag(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    a = _args(kind="followup", task="round 2", link=[], conversation="cid", rid="a5a5a5a5")
    assert gptc.cmd_enqueue(a) == 2  # no link, no --allow-nolink
    a2 = _args(kind="followup", task="round 2", link=[], conversation="c" * 20,
               rid="a6a6a6a6", allow_nolink=True)
    assert gptc.cmd_enqueue(a2) == 0


def _raw(**kw):
    base = dict(rid="deadbeef", kind="consult", task="clean", title="t", role="r",
                links=["a/b"], allow_nolink=False, allow_gist=False,
                conversation_id=None, timeout=10, out="/tmp/x.txt")
    base.update(kw)
    return base


def test_daemon_refuses_private_repo(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: False)
    gptc._ensure_spool()
    gptc._process_job(_raw(rid="cccccccc", out=str(tmp_path / "ans.txt")))
    st = json.loads((tmp_path / "spool" / "status" / "cccccccc.json").read_text())
    assert st["state"] == "refused" and "public" in st["reason"]


def test_daemon_rescans_raw_inputs_for_secret(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: True)
    gptc._ensure_spool()
    gptc._process_job(_raw(rid="dddddddd", task="leak sk-ant-api03-" + "A" * 20,
                           out=str(tmp_path / "a.txt")))
    st = json.loads((tmp_path / "spool" / "status" / "dddddddd.json").read_text())
    assert st["state"] == "refused"


def test_daemon_refuses_forged_kind(tmp_path, monkeypatch):
    """GPT finding #1: any kind other than consult/followup must be rejected outright."""
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: True)
    gptc._ensure_spool()
    gptc._process_job({"rid": "eeeeeeee", "kind": "anything",
                       "prompt": "private base64 payload", "slugs": []})
    st = json.loads((tmp_path / "spool" / "status" / "eeeeeeee.json").read_text())
    assert st["state"] == "refused" and "bad kind" in st["reason"]


def test_daemon_refuses_extra_or_missing_fields(tmp_path, monkeypatch):
    """A forged job smuggling a pre-rendered 'prompt' field fails the exact-keys schema."""
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: True)
    gptc._ensure_spool()
    gptc._process_job(_raw(rid="ffffffff", prompt="agent-supplied rendered payload"))
    st = json.loads((tmp_path / "spool" / "status" / "ffffffff.json").read_text())
    assert st["state"] == "refused" and "keys must be exactly" in st["reason"]


def test_daemon_refuses_nonhex_rid_silently(tmp_path, monkeypatch):
    """GPT finding: rid is injected into the prompt; a non-hex rid (which could carry
    newline-smuggled secrets) is dropped before anything is sent or a status written."""
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: True)
    gptc._ensure_spool()
    gptc._process_job(_raw(rid="abc\nAPI_KEY=sk-ant-leak\nabc"))
    # nothing addressable was written
    assert not list((tmp_path / "spool" / "status").glob("*.json"))


def test_daemon_refuses_bad_conversation_id(tmp_path, monkeypatch):
    """GPT finding: conversation_id must pass its grammar BEFORE it is built into a URL."""
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: True)
    gptc._ensure_spool()
    gptc._process_job(_raw(rid="12345678", kind="followup",
                           conversation_id="abcdef0123456789?leak=DATA"))
    st = json.loads((tmp_path / "spool" / "status" / "12345678.json").read_text())
    assert st["state"] == "refused" and "conversation_id" in st["reason"]


# --- link canonicalization (path-tail smuggling closed) ----------------------
def test_link_path_tail_is_refused():
    ok, reason = gptc.resolve_link("https://github.com/python/cpython/blob/main/BASE64DATA")
    assert not ok and "unsupported GitHub URL shape" in reason


def test_link_repo_pull_commit_canonicalize():
    for link, kind in [("https://github.com/o/r", "repo"),
                       ("https://github.com/o/r/pull/42", "pr"),
                       ("https://github.com/o/r/commit/" + "a" * 40, "commit")]:
        ok, info = gptc.resolve_link(link)
        assert ok and info["kind"] == kind and "?" not in info["url"]


def test_conv_id_url_must_be_exact_host():
    assert gptc.conv_id_from_url("https://evil.example/?next=/c/0123456789abcdef") is None
    assert gptc.conv_id_from_url("https://chatgpt.com/c/0123456789abcdef") == "0123456789abcdef"


# --- covert-channel guard: object must EXIST, gists refused (GPT round-5 finding) --------
def test_gate_public_refuses_gist():
    ok, reason = gptc.gate_public([{"slug": None, "url": "https://gist.github.com/a/b", "kind": "gist"}])
    assert not ok and "gist" in reason


def test_gate_public_refuses_fake_commit(monkeypatch):
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: True)
    monkeypatch.setattr(gptc, "_gh_ok", lambda p: False)  # object not found
    ok, reason = gptc.gate_public([{"slug": "o/r", "url": "u", "kind": "commit", "ref": "a" * 40}])
    assert not ok and "covert-channel guard" in reason


def test_gate_public_allows_real_pr(monkeypatch):
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: True)
    monkeypatch.setattr(gptc, "_gh_ok", lambda p: True)  # object exists
    ok, res = gptc.gate_public([{"slug": "o/r", "url": "u", "kind": "pr", "ref": "42"}])
    assert ok
