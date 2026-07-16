"""Tests for the session-tier (Chat=Pro / Work=strongest) + private-repo opt-in + the
daemon heartbeat fix. Live-CDP actuation is not unit-testable; the gate, schema, fail-closed
control flow, and heartbeat plumbing are. All offline."""
import json
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gptc  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_mode_env(monkeypatch):
    """Tier resolution reads GPTC_MODE / GPTC_DEFAULT_MODE from the env; keep tests hermetic."""
    monkeypatch.delenv("GPTC_MODE", raising=False)
    monkeypatch.delenv("GPTC_DEFAULT_MODE", raising=False)


# --------------------------------------------------------------------------- #
# tier resolution — a strong tier is enforced (GPTC_MODE pin > --mode > default chat)
# --------------------------------------------------------------------------- #
def test_resolve_mode_defaults_to_chat_pro():
    assert gptc._resolve_mode(None) == "chat"
    assert gptc._resolve_mode("") == "chat"


def test_resolve_mode_uses_caller_flag():
    assert gptc._resolve_mode("work") == "work"


def test_resolve_mode_env_hard_pins_over_flag(monkeypatch):
    monkeypatch.setenv("GPTC_MODE", "work")
    assert gptc._resolve_mode("chat") == "work"   # pin overrides an agent's weaker choice
    assert gptc._resolve_mode(None) == "work"


def test_resolve_mode_default_env_moves_the_floor(monkeypatch):
    monkeypatch.setenv("GPTC_DEFAULT_MODE", "work")
    assert gptc._resolve_mode(None) == "work"
    assert gptc._resolve_mode("chat") == "chat"   # explicit flag still wins over the default


# --------------------------------------------------------------------------- #
# private-repo opt-in at the network gate
# --------------------------------------------------------------------------- #
def test_private_repo_refused_without_flag(monkeypatch):
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: False)
    ok, reason = gptc.gate_public([{"slug": "me/secret", "url": "u", "kind": "repo"}])
    assert not ok and "public" in reason


def test_private_repo_allowed_with_flag_but_must_exist(monkeypatch):
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: False)  # never consulted
    monkeypatch.setattr(gptc, "_gh_ok", lambda p: True)            # repo exists (authed gh)
    ok, res = gptc.gate_public([{"slug": "me/secret", "url": "u", "kind": "repo"}],
                               allow_private=True)
    assert ok


def test_private_flag_still_rejects_nonexistent_repo(monkeypatch):
    monkeypatch.setattr(gptc, "_gh_ok", lambda p: False)  # repo not found even for the owner
    ok, reason = gptc.gate_public([{"slug": "me/nope", "url": "u", "kind": "repo"}],
                                  allow_private=True)
    assert not ok and "not found" in reason


def test_private_gate_still_secret_scans(monkeypatch):
    # allow_private drops the PUBLIC check, never the secret scan
    ok, reason = gptc.gate("token sk-ant-api03-" + "A" * 20, ["me/secret"], allow_private=True)
    assert not ok and "secret-like" in reason


# --------------------------------------------------------------------------- #
# daemon schema: mode + private are validated at the boundary
# --------------------------------------------------------------------------- #
def _raw(**kw):
    base = dict(rid="deadbeef", kind="consult", task="clean", title="t", role="r",
                links=["a/b"], allow_nolink=False, allow_gist=False,
                conversation_id=None, timeout=10, out="answer.txt", mode=None, private=False)
    base.update(kw)
    return base


def _status(tmp_path, rid):
    return json.loads((tmp_path / "spool" / "status" / f"{rid}.json").read_text())


def test_daemon_refuses_bad_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    gptc._ensure_spool()
    gptc._process_job(_raw(rid="10101010", mode="turbo"))
    st = _status(tmp_path, "10101010")
    assert st["state"] == "refused" and "mode must be" in st["reason"]


def test_daemon_refuses_nonbool_private(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    gptc._ensure_spool()
    gptc._process_job(_raw(rid="20202020", private="yes"))
    st = _status(tmp_path, "20202020")
    assert st["state"] == "refused" and "private must be a boolean" in st["reason"]


def test_daemon_refuses_followup_with_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    gptc._ensure_spool()
    gptc._process_job(_raw(rid="30303030", kind="followup",
                           conversation_id="a" * 20, mode="work"))
    st = _status(tmp_path, "30303030")
    assert st["state"] == "refused" and "inherits its thread" in st["reason"]


def test_daemon_private_job_passes_gate_and_sends(tmp_path, monkeypatch):
    """A private=True job with a private (but existing) repo clears the gate and reaches
    send — the deliberate opt-in. Send path is stubbed (no Chrome in a unit test)."""
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "ANSWER_DIR", str(tmp_path))         # so out stays contained
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: False)  # it's private
    monkeypatch.setattr(gptc, "_gh_ok", lambda p: True)            # but it exists
    sent = {}

    class _P:
        def close(self):
            pass

    def _open(mode=None):
        sent["mode"] = mode
        return _P()

    monkeypatch.setattr(gptc, "open_new_chat", _open)
    monkeypatch.setattr(gptc, "type_and_send", lambda *a, **k: None)
    monkeypatch.setattr(gptc, "capture_conversation_id", lambda *a, **k: "b" * 20)
    monkeypatch.setattr(gptc, "poll_answer",
                        lambda page, rid, t, poll, **k: ("done", "ANSWER", "sol", page))
    gptc._ensure_spool()
    gptc._process_job(_raw(rid="40404040", private=True, mode="work",
                           out=str(tmp_path / "ans.txt")))
    st = _status(tmp_path, "40404040")
    assert st["state"] == "done" and sent["mode"] == "work"
    assert (tmp_path / "ans.txt").read_text() == "ANSWER"


def test_enqueue_carries_mode_and_private(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: (_ for _ in ()).throw(AssertionError()))
    a = types.SimpleNamespace(task="review", title="t", role="", link=["me/secret"],
                              kind="consult", conversation="", allow_nolink=False, out="",
                              rid="50505050", timeout=10, allow_gist=False,
                              mode="work", private=True)
    assert gptc.cmd_enqueue(a) == 0
    job = json.loads((tmp_path / "spool" / "pending" / "50505050.json").read_text())
    assert job["mode"] == "work" and job["private"] is True
    assert set(job) == gptc._JOB_KEYS  # exact schema, no drift


# --------------------------------------------------------------------------- #
# configure_session: verified actuation, fail closed on drift
# --------------------------------------------------------------------------- #
class _LeafPage:
    """Minimal page for the mode helper (_set_mode)."""
    def __init__(self, mode_after="Work", radios=2, radio="clicked"):
        self.mode_after, self.radios, self.radio = mode_after, radios, radio

    def eval(self, expr):
        if "rs[i].click()" in expr:                    # _select_mode_js (has rs.length too)
            return self.radio
        if "data-state" in expr and "'on'" in expr:    # _READ_MODE_JS (has rs.length too)
            return self.mode_after
        if 'role="radio"' in expr and ".length" in expr:  # _RADIOS_COUNT_JS (pure count)
            return self.radios
        return None


class _WorkPage:
    """Page for _set_work_ultra: open Effort submenu, pick Ultra, confirm row + Sol pill."""
    def __init__(self, submenu="opened", radios=6, pick="picked", row="Effort Ultra",
                 pill="5.6 Sol Ultra"):
        self.submenu, self.radios, self.pick, self.row, self.pill = \
            submenu, radios, pick, row, pill

    def eval(self, expr):
        if "PointerEvent" in expr and "Effort" in expr:     # open effort submenu
            return self.submenu
        if "menuitemradio" in expr and ".click()" in expr:  # pick effort tier
            return self.pick
        if "menuitemradio" in expr:                         # count
            return self.radios
        if "__composer-pill" in expr:                       # committed pill label (family+effort)
            return self.pill
        if "Escape" in expr:
            return None
        if "Effort" in expr:                                # effort row label read
            return self.row
        return None


def test_set_mode_confirms_switch(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    assert gptc._set_mode(_LeafPage(mode_after="Work"), "Work") is True


def test_set_mode_fails_when_not_confirmed(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    assert gptc._set_mode(_LeafPage(mode_after="Chat"), "Work") is False  # asked Work, got Chat


def test_set_mode_fails_when_toggle_absent(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    assert gptc._set_mode(_LeafPage(radios=0), "Work") is False


def test_set_work_ultra_picks_ultra(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    assert gptc._set_work_ultra(_WorkPage()) is True


def test_set_work_ultra_fails_when_submenu_absent(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    assert gptc._set_work_ultra(_WorkPage(submenu="no-effort")) is False


def test_set_work_ultra_fails_when_tier_absent(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    assert gptc._set_work_ultra(_WorkPage(pick="no-item")) is False


def test_set_work_ultra_fails_when_not_confirmed(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)  # pick claims ok, row didn't update
    assert gptc._set_work_ultra(_WorkPage(row="Effort Extra High")) is False


def test_set_work_ultra_fails_when_family_not_sol(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)  # effort=Ultra but model is not Sol
    assert gptc._set_work_ultra(_WorkPage(pill="GPT-5.5 Ultra")) is False


def _patch_helpers(monkeypatch, **overrides):
    vals = dict(_set_mode=True, _open_model_picker=True, _set_chat_pro=True, _set_work_ultra=True)
    vals.update(overrides)
    for name, v in vals.items():
        monkeypatch.setattr(gptc, name, (lambda val: (lambda *a, **k: val))(v))


class _EscPage:
    def eval(self, expr):
        return None


def test_configure_session_keep_is_the_only_noop(monkeypatch):
    calls = []
    monkeypatch.setattr(gptc, "_set_mode", lambda *a, **k: calls.append(1) or True)
    gptc.configure_session(_EscPage(), "keep")   # explicit opt-out — leave the tab as-is
    assert calls == []


def test_configure_session_default_enforces_chat_pro(monkeypatch):
    # a forgotten --mode (None) must NOT be a no-op — it actuates the strong default (Pro)
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    _patch_helpers(monkeypatch)
    called = {}
    monkeypatch.setattr(gptc, "_set_chat_pro", lambda p: called.setdefault("chat", True) or True)
    monkeypatch.setattr(gptc, "_set_work_ultra", lambda p: called.setdefault("work", True) or True)
    gptc.configure_session(_EscPage(), None)
    assert called == {"chat": True}  # defaulted to Pro, not left as-is, not Ultra


def test_configure_session_unknown_mode_is_setup_error():
    with pytest.raises(SystemExit) as ei:
        gptc.configure_session(_EscPage(), "ultra")
    assert ei.value.code == 2


def test_configure_session_work_success(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    _patch_helpers(monkeypatch)
    gptc.configure_session(_EscPage(), "work")  # must not raise


def test_configure_session_fail_closed_on_mode(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    _patch_helpers(monkeypatch, _set_mode=False)
    with pytest.raises(SystemExit) as ei:
        gptc.configure_session(_EscPage(), "work")
    assert ei.value.code == 3


def test_configure_session_fail_closed_on_work_model(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    _patch_helpers(monkeypatch, _set_work_ultra=False)
    with pytest.raises(SystemExit) as ei:
        gptc.configure_session(_EscPage(), "work")
    assert ei.value.code == 3


def test_configure_session_fail_closed_on_chat_model(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    _patch_helpers(monkeypatch, _set_chat_pro=False)
    with pytest.raises(SystemExit) as ei:
        gptc.configure_session(_EscPage(), "chat")
    assert ei.value.code == 3


# --------------------------------------------------------------------------- #
# heartbeat: poll_answer pings the callback each tick (the daemon-liveness fix)
# --------------------------------------------------------------------------- #
class _DonePage:
    def eval(self, expr):
        return json.dumps({"state": "done", "text": "BODY", "model": "m", "generating": False})
    def close(self):
        pass


def test_poll_answer_calls_heartbeat_each_tick(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    beats = {"n": 0}
    state, text, model, _ = gptc.poll_answer(
        _DonePage(), "abcd1234", timeout=5, poll=0.0,
        heartbeat_cb=lambda: beats.__setitem__("n", beats["n"] + 1))
    assert state == "done" and text == "BODY"
    assert beats["n"] >= 1  # heartbeat kept fresh while waiting


def test_touch_heartbeat_writes_fresh(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    gptc._ensure_spool()
    gptc._touch_heartbeat()
    assert gptc._daemon_alive() is True


# --------------------------------------------------------------------------- #
# #0: interactive paths must validate --rid (it lands in the OUTBOUND prompt but is
# not part of the text the gate secret-scans)
# --------------------------------------------------------------------------- #
def test_prep_consult_rejects_nonhex_rid():
    a = types.SimpleNamespace(rid="deadbeef\nsk-ant-api03-" + "A" * 20, role="", title="t",
                              task="review", link=["owner/repo"], allow_gist=False, private=False)
    with pytest.raises(SystemExit) as ei:
        gptc._prep_consult(a)
    assert ei.value.code == 2


def test_followup_rejects_nonhex_rid():
    a = types.SimpleNamespace(rid="x\nsk-ant-api03-" + "A" * 20, conversation="a" * 20,
                              task="r", link=["a/b"], allow_nolink=False, allow_gist=False,
                              private=False, out="", timeout=10)
    assert gptc.cmd_followup(a) == 2


# --------------------------------------------------------------------------- #
# #3: dot-segment / percent-encoded traversal slugs are refused (they'd normalize to a
# different `gh api` endpoint and pass the --private existence check)
# --------------------------------------------------------------------------- #
def test_slug_traversal_refused():
    for bad in ["../rate_limit", "owner/..", "./x", "..%2f", "a/."]:
        ok, _ = gptc.resolve_link(bad)
        assert not ok, bad


def test_slug_normal_still_ok():
    for good in ["python/cpython", "my-org/my.repo_2", "a/b"]:
        ok, info = gptc.resolve_link(good)
        assert ok and info["kind"] == "repo", good


def test_slug_ok_unit():
    assert gptc._slug_ok("owner/repo") and not gptc._slug_ok("../repo") \
        and not gptc._slug_ok("owner/..") and not gptc._slug_ok("a/%2e")


# --------------------------------------------------------------------------- #
# #5: a fail-closed tier error closes the tab instead of leaking it
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# #1: mode-aware generous timeouts (Pro/Ultra legitimately run tens of minutes)
# --------------------------------------------------------------------------- #
def test_default_timeout_mode_aware():
    assert gptc._default_timeout("work") == 3000
    assert gptc._default_timeout("chat") == 1800
    assert gptc._default_timeout(None) == 1800


def test_resolve_timeout_explicit_wins_and_clamps():
    assert gptc._resolve_timeout(types.SimpleNamespace(timeout=None, mode="work")) == 3000
    assert gptc._resolve_timeout(types.SimpleNamespace(timeout=None, mode="")) == 1800
    assert gptc._resolve_timeout(types.SimpleNamespace(timeout=50, mode="work")) == 50
    assert gptc._resolve_timeout(types.SimpleNamespace(timeout=99999, mode="work")) == 3600


# --------------------------------------------------------------------------- #
# #2: unwrapped-answer salvage on timeout (don't lose a long reasoning result)
# --------------------------------------------------------------------------- #
class _SalvagePage:
    def __init__(self, found=True, text="PARTIAL ANSWER"):
        self.found, self.text = found, text

    def eval(self, expr):
        if "found" in expr:  # _salvage_js
            return json.dumps({"found": self.found, "text": self.text,
                               "model": "sol", "generating": True})
        return json.dumps({"state": "generating", "generating": True})  # _extract_js

    def close(self):
        pass


def test_poll_answer_salvages_unwrapped_on_timeout(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    state, text, model, _ = gptc.poll_answer(_SalvagePage(), "abcd1234", timeout=0, poll=0.0)
    assert state == "salvaged" and text == "PARTIAL ANSWER" and model == "sol"


def test_poll_answer_plain_timeout_when_nothing_to_salvage(monkeypatch):
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    state, text, _, _ = gptc.poll_answer(_SalvagePage(found=False), "abcd1234",
                                         timeout=0, poll=0.0)
    assert state == "timeout" and text is None


def test_daemon_writes_partial_on_salvage(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "ANSWER_DIR", str(tmp_path))
    monkeypatch.setattr(gptc, "_repo_is_public", lambda s: True)

    class _P:
        def close(self):
            pass

    monkeypatch.setattr(gptc, "open_new_chat", lambda mode=None: _P())
    monkeypatch.setattr(gptc, "type_and_send", lambda *a, **k: None)
    monkeypatch.setattr(gptc, "capture_conversation_id", lambda *a, **k: "b" * 20)
    monkeypatch.setattr(gptc, "poll_answer",
                        lambda page, rid, t, poll, **k: ("salvaged", "PARTIAL", "sol", page))
    gptc._ensure_spool()
    gptc._process_job(_raw(rid="70707070", out="answer.txt"))
    st = _status(tmp_path, "70707070")
    assert st["state"] == "salvaged" and st["out"].endswith(".partial")
    assert Path(st["out"]).read_text() == "PARTIAL"


def test_await_returns_5_on_salvaged(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "_hard_deadline", lambda *_: None)  # don't arm SIGALRM in tests
    gptc._ensure_spool()
    gptc._write_status("80808080", {"state": "salvaged", "out": "/x.partial", "model": "sol"})
    a = types.SimpleNamespace(rid="80808080", out="", timeout=5, poll=0.0)
    assert gptc.cmd_await(a) == 5


def test_open_new_chat_closes_tab_on_configure_failure(monkeypatch):
    closed = {"target": 0, "client": 0}

    class _P:
        def close_target(self):
            closed["target"] += 1

        def close(self):
            closed["client"] += 1

    monkeypatch.setattr(gptc, "_chrome_up", lambda: True)
    monkeypatch.setattr(gptc, "open_tab", lambda url: _P())
    monkeypatch.setattr(gptc, "_wait_composer", lambda page: True)
    monkeypatch.setattr(gptc, "configure_session",
                        lambda page, mode: (_ for _ in ()).throw(SystemExit(3)))
    with pytest.raises(SystemExit) as ei:
        gptc.open_new_chat("work")
    assert ei.value.code == 3
    assert closed["target"] == 1 and closed["client"] == 1  # tab + socket cleaned up


# --------------------------------------------------------------------------- #
# daemon auto-start (gptc watch --detach) — starting the local process is allowed;
# login is not (credentials), and it still needs Chrome up
# --------------------------------------------------------------------------- #
def test_watch_detach_noop_when_already_running(monkeypatch):
    monkeypatch.setattr(gptc, "_daemon_alive", lambda: True)
    assert gptc._start_watch_detached() == 0


def test_watch_detach_fails_when_chrome_down(monkeypatch):
    monkeypatch.setattr(gptc, "_daemon_alive", lambda: False)
    monkeypatch.setattr(gptc, "_chrome_up", lambda: False)
    assert gptc._start_watch_detached() == 2


def test_watch_detach_spawns_and_waits(tmp_path, monkeypatch):
    monkeypatch.setattr(gptc, "SPOOL_DIR", str(tmp_path / "spool"))
    monkeypatch.setattr(gptc, "STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(gptc, "_chrome_up", lambda: True)
    monkeypatch.setattr(gptc.time, "sleep", lambda *_: None)
    seen = {"popen": 0}
    monkeypatch.setattr(gptc.subprocess, "Popen",
                        lambda *a, **k: seen.__setitem__("popen", seen["popen"] + 1))
    alive = {"n": 0}

    def _alive():  # False on the pre-check, True once the (stubbed) child is "up"
        alive["n"] += 1
        return alive["n"] > 1

    monkeypatch.setattr(gptc, "_daemon_alive", _alive)
    assert gptc._start_watch_detached() == 0 and seen["popen"] == 1
