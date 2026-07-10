"""Workflow-plumbing tests: conversation-id parsing and prompt rendering."""
import sys
from pathlib import Path

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
