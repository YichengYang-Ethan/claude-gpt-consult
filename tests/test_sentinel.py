"""Sentinel-parser tests: completion detection must be exact and fence-aware."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gptc  # noqa: E402

RID = "abcd1234"


def test_tilde_fence_does_not_desync():
    # a ~~~ block quoting END must not close the answer early (delimiter-aware fences)
    txt = (f"BEGIN_RESPONSE:{RID}\nreal answer\n~~~\nEND_RESPONSE:{RID}\n~~~\n"
           f"still the answer\nEND_RESPONSE:{RID}")
    out = gptc.sentinel_parse(txt, RID)
    assert out is not None and "still the answer" in out and "real answer" in out


def test_four_backtick_fence_tracked():
    txt = (f"BEGIN_RESPONSE:{RID}\n````\ncode with ``` inside\n````\n"
           f"after\nEND_RESPONSE:{RID}")
    out = gptc.sentinel_parse(txt, RID)
    assert out is not None and "after" in out and "code with ``` inside" in out


def test_model_downgrade_warning():
    assert gptc.model_downgrade_warning("gpt-5-6-thinking", "thinking") is None
    assert gptc.model_downgrade_warning("gpt-5-6-mini", "thinking") is not None
    assert gptc.model_downgrade_warning(None, "thinking") is None
    assert gptc.model_downgrade_warning("gpt-5-6-mini", "") is None


def test_clean_wrapped_answer():
    txt = f"thinking...\nBEGIN_RESPONSE:{RID}\nHere is the answer.\nLine two.\nEND_RESPONSE:{RID}\ntrailing"
    assert gptc.sentinel_parse(txt, RID) == "Here is the answer.\nLine two."


def test_missing_end_returns_none():
    txt = f"BEGIN_RESPONSE:{RID}\npartial answer still streaming"
    assert gptc.sentinel_parse(txt, RID) is None


def test_no_sentinel_returns_none():
    assert gptc.sentinel_parse("just some text with no markers", RID) is None


def test_wrong_rid_returns_none():
    txt = f"BEGIN_RESPONSE:zzzz\nnot ours\nEND_RESPONSE:zzzz"
    assert gptc.sentinel_parse(txt, RID) is None


def test_sentinel_inside_code_fence_is_ignored():
    # a model quoting the sentinel inside a fence must NOT falsely close the answer
    txt = (
        f"BEGIN_RESPONSE:{RID}\n"
        "Example of the protocol:\n"
        "```\n"
        f"BEGIN_RESPONSE:{RID}\n"
        f"END_RESPONSE:{RID}\n"
        "```\n"
        "That was just an example.\n"
        f"END_RESPONSE:{RID}"
    )
    out = gptc.sentinel_parse(txt, RID)
    assert out is not None
    assert "That was just an example." in out
    assert "Example of the protocol:" in out


def test_answer_body_preserves_inner_fences():
    txt = (
        f"BEGIN_RESPONSE:{RID}\n"
        "Use this snippet:\n"
        "```python\n"
        "print('hi')\n"
        "```\n"
        f"END_RESPONSE:{RID}"
    )
    out = gptc.sentinel_parse(txt, RID)
    assert "print('hi')" in out and "```python" in out
