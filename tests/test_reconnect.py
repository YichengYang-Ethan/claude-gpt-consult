"""Reconnect tests: poll_answer must survive a transient CDP websocket drop by
re-attaching to the conversation (bounded, fail-closed), and the emitted commands'
hard deadline must be enforced in-process (no GNU `timeout` dependency)."""
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
from websocket import WebSocketConnectionClosedException

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gptc  # noqa: E402

CID = "2222222222222222"


def _done(text="ANSWER", model="gpt-5"):
    return json.dumps({"state": "done", "text": text, "generating": False, "model": model})


def _thinking():
    return json.dumps({"state": "thinking"})


class _ScriptedPage:
    """eval() pops the next scripted item — raise it if it's an exception, return it
    otherwise; the last item repeats once the script is exhausted."""

    def __init__(self, script):
        self.script = list(script)
        self.evals = 0
        self.closed = False

    def eval(self, expr):
        self.evals += 1
        item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
        if isinstance(item, BaseException):
            raise item
        return item

    def close(self):
        self.closed = True


@pytest.fixture
def no_sleep(monkeypatch):
    slept = []
    monkeypatch.setattr(time, "sleep", lambda s: slept.append(s))
    return slept


def test_poll_answer_survives_ws_drop_and_reattaches(monkeypatch, no_sleep):
    stale = _ScriptedPage([WebSocketConnectionClosedException("lost")])
    live = _ScriptedPage([_done()])
    calls = []

    def fake_find(cid):
        calls.append(cid)
        return live

    monkeypatch.setattr(gptc, "find_conversation_page", fake_find)
    state, answer, model, page = gptc.poll_answer(stale, "deadbeef", 30, 0, conversation_id=CID)
    assert (state, answer, model) == ("done", "ANSWER", "gpt-5")
    assert page is live            # caller gets the LIVE page back
    assert stale.closed            # dead client detached
    assert calls == [CID]          # re-attached once, to the exact conversation


def test_poll_answer_gives_up_after_bounded_reconnects(monkeypatch, no_sleep):
    calls = []

    def fake_find(cid):
        calls.append(cid)
        return _ScriptedPage([WebSocketConnectionClosedException("still down")])

    monkeypatch.setattr(gptc, "find_conversation_page", fake_find)
    stale = _ScriptedPage([WebSocketConnectionClosedException("lost")])
    with pytest.raises(SystemExit) as ei:
        gptc.poll_answer(stale, "deadbeef", 30, 0, conversation_id=CID)
    assert ei.value.code == 2
    assert len(calls) == len(gptc._RECONNECT_BACKOFF)


def test_poll_answer_backoff_is_bounded(monkeypatch, no_sleep):
    monkeypatch.setattr(gptc, "find_conversation_page",
                        lambda cid: _ScriptedPage([WebSocketConnectionClosedException("down")]))
    stale = _ScriptedPage([WebSocketConnectionClosedException("lost")])
    with pytest.raises(SystemExit):
        gptc.poll_answer(stale, "deadbeef", 30, 0, conversation_id=CID)
    assert [s for s in no_sleep if s] == list(gptc._RECONNECT_BACKOFF)


def test_poll_answer_fail_closed_when_conversation_gone(monkeypatch, no_sleep):
    def gone(cid):
        raise SystemExit(2)  # find_conversation_page's genuine-loss behavior

    monkeypatch.setattr(gptc, "find_conversation_page", gone)
    stale = _ScriptedPage([WebSocketConnectionClosedException("lost")])
    with pytest.raises(SystemExit) as ei:
        gptc.poll_answer(stale, "deadbeef", 30, 0, conversation_id=CID)
    assert ei.value.code == 2
    assert stale.closed


def test_poll_answer_no_reconnect_without_conversation_id(monkeypatch, no_sleep):
    def bomb(cid):
        raise AssertionError("must not re-attach without a conversation id")

    monkeypatch.setattr(gptc, "find_conversation_page", bomb)
    stale = _ScriptedPage([WebSocketConnectionClosedException("lost")])
    with pytest.raises(SystemExit) as ei:
        gptc.poll_answer(stale, "deadbeef", 30, 0)
    assert ei.value.code == 2


def test_poll_answer_catches_connection_reset(monkeypatch, no_sleep):
    live = _ScriptedPage([_done()])
    monkeypatch.setattr(gptc, "find_conversation_page", lambda cid: live)
    stale = _ScriptedPage([ConnectionResetError()])
    state, answer, _, page = gptc.poll_answer(stale, "deadbeef", 30, 0, conversation_id=CID)
    assert (state, answer, page) == ("done", "ANSWER", live)


def test_poll_answer_resets_stability_after_reconnect(monkeypatch, no_sleep):
    # a done-sighting BEFORE the drop must not pair with the first sighting after it
    stale = _ScriptedPage([_done("T"), WebSocketConnectionClosedException("lost")])
    live = _ScriptedPage([_done("T")])
    monkeypatch.setattr(gptc, "find_conversation_page", lambda cid: live)
    state, answer, _, _ = gptc.poll_answer(stale, "deadbeef", 30, 0, conversation_id=CID)
    assert (state, answer) == ("done", "T")
    assert live.evals == 2  # stability re-proven entirely on the new connection


def test_poll_answer_retry_budget_resets_after_success(monkeypatch, no_sleep):
    # 4 one-drop outages, each healed by a successful poll: more total drops than the
    # per-outage budget, yet it must still succeed (budget is per-outage, not lifetime)
    pages = [_ScriptedPage([_thinking(), WebSocketConnectionClosedException("drop")])
             for _ in range(3)] + [_ScriptedPage([_done()])]
    calls = []

    def fake_find(cid):
        calls.append(cid)
        return pages[len(calls) - 1]

    monkeypatch.setattr(gptc, "find_conversation_page", fake_find)
    stale = _ScriptedPage([WebSocketConnectionClosedException("drop")])
    state, answer, _, page = gptc.poll_answer(stale, "deadbeef", 30, 0, conversation_id=CID)
    assert (state, answer) == ("done", "ANSWER")
    assert len(calls) == 4
    assert len(calls) > len(gptc._RECONNECT_BACKOFF)
    assert page is pages[-1]


def test_hard_deadline_fires():
    t0 = time.time()
    p = subprocess.run(
        [sys.executable, "-c", "import gptc, time; gptc._hard_deadline(1); time.sleep(10)"],
        cwd=str(Path(__file__).resolve().parents[1]), capture_output=True, text=True, timeout=8)
    assert p.returncode == 4  # the documented no-answer-in-time exit code
    assert time.time() - t0 < 5
    assert "hard deadline exceeded" in p.stderr
