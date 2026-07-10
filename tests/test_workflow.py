"""Workflow-plumbing tests: conversation-id parsing, prompt rendering, identity guards."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gptc  # noqa: E402


def test_conv_id_from_plain_chat_url():
    url = "https://chatgpt.com/c/67f0a1b2-3c4d-5e6f-7a8b-9c0d1e2f3a4b"
    assert gptc.conv_id_from_url(url) == "67f0a1b2-3c4d-5e6f-7a8b-9c0d1e2f3a4b"


def test_conv_id_from_project_scoped_url():
    url = "https://chatgpt.com/g/g-p-abc123-proj/c/67f0a1b2-3c4d-5e6f-7a8b-9c0d1e2f3a4b"
    assert gptc.conv_id_from_url(url) == "67f0a1b2-3c4d-5e6f-7a8b-9c0d1e2f3a4b"


def test_conv_id_none_on_new_chat():
    assert gptc.conv_id_from_url("https://chatgpt.com/") is None
    assert gptc.conv_id_from_url(None) is None


def test_rendered_prompt_carries_matched_sentinels():
    rid = "beef1234"
    prompt = gptc.render_prompt(rid, "T", "You are X.", "do the thing",
                               [{"url": "https://github.com/a/b", "kind": "repo"}])
    assert f"BEGIN_RESPONSE:{rid}" in prompt and f"END_RESPONSE:{rid}" in prompt
    # round-trips through the parser when the model echoes the contract
    faux = f"thinking\nBEGIN_RESPONSE:{rid}\nthe answer\nEND_RESPONSE:{rid}"
    assert gptc.sentinel_parse(faux, rid) == "the answer"


def test_followup_prompt_wraps_sentinels():
    rid = "cafe5678"
    p = gptc.render_followup(rid, "here are local results", [])
    assert f"BEGIN_RESPONSE:{rid}" in p and f"END_RESPONSE:{rid}" in p


# --- #4 identity guards -------------------------------------------------------
def test_find_conversation_page_rejects_bad_id_before_chrome():
    # grammar check runs first, so no Chrome is needed to reject a smuggling id
    for bad in ("unknown", "abcdef0123456789?leak=DATA", "", "../../etc"):
        with pytest.raises(SystemExit):
            gptc.find_conversation_page(bad)


class _FakePage:
    def __init__(self, href):
        self._href = href

    def eval(self, expr):
        if "location.href" in expr:
            return self._href
        return "sent" if "send-button" in expr else "typed"


def test_type_and_send_rejects_conversation_drift():
    # attached tab is now on a DIFFERENT conversation than expected -> fail closed
    page = _FakePage("https://chatgpt.com/c/1111111111111111")
    with pytest.raises(SystemExit):
        gptc.type_and_send(page, "hi", expected_conversation="2222222222222222")


def test_type_and_send_allows_matching_conversation():
    page = _FakePage("https://chatgpt.com/c/2222222222222222")
    gptc.type_and_send(page, "hi", expected_conversation="2222222222222222")  # no raise


def test_type_and_send_new_chat_skips_identity_check():
    # new-chat path (expected_conversation=None) must not require a /c/ url
    page = _FakePage("https://chatgpt.com/")
    gptc.type_and_send(page, "hi")  # no raise
