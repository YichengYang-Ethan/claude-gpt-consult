"""Egress-gate tests. The gate is the security heart, so it is the most-tested part.
No network: _repo_is_public is monkeypatched."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gptc  # noqa: E402


def _public(monkeypatch, is_public=True):
    monkeypatch.setattr(gptc, "_repo_is_public", lambda slug: is_public)


def test_clean_public_link_passes(monkeypatch):
    _public(monkeypatch)
    ok, res = gptc.gate("review this repo for bugs", ["torvalds/linux"])
    assert ok and res[0]["slug"] == "torvalds/linux"


def test_no_link_refused(monkeypatch):
    _public(monkeypatch)
    ok, reason = gptc.gate("just answer this", [])
    assert not ok and "no public code link" in reason


def test_private_repo_refused(monkeypatch):
    _public(monkeypatch, is_public=False)
    ok, reason = gptc.gate("look at this", ["me/secret-repo"])
    assert not ok and "not gh-confirmed public" in reason


def test_non_github_link_refused(monkeypatch):
    _public(monkeypatch)
    ok, reason = gptc.gate("see", ["https://gitlab.com/me/x"])
    assert not ok and "GitHub" in reason


def test_gist_refused_by_default(monkeypatch):
    _public(monkeypatch)
    ok, reason = gptc.gate("see", ["https://gist.github.com/me/abc123"])
    assert not ok and "gist" in reason


# --- secret shapes the field commonly misses must be caught -------------------
# Fixtures are assembled from fragments so this test file contains no literal
# secret-shaped string — that keeps repo secret-scanners / pre-commit hooks from
# false-positiving on our own test corpus. At runtime each `join` yields the full
# secret the gate must catch.
_j = "".join
SECRETS = [
    _j(["sk-", "ant-api03-", "AbCdEf0123456789xyz"]),          # Anthropic  # gitleaks:allow
    _j(["sk", "_live_", "51AbCdEfGhIjKlMnOpQrStUv"]),          # Stripe live  # gitleaks:allow
    _j(["postgres://admin:", "Sup3rSecret", "@db.internal:5432/app"]),  # conn string  # gitleaks:allow
    _j(["https://user:", "hunter2pass", "@internal.example.com"]),      # basic-auth  # gitleaks:allow
    _j(["password = '", "correct-horse-battery", "'"]),        # assignment  # gitleaks:allow
    _j(["AKIA", "IOSFODNN7", "EXAMPLE"]),                      # AWS example  # gitleaks:allow
    _j(["ghp", "_016abcdefghijklmn", "opqrstuvwxyz012345"]),   # GitHub PAT  # gitleaks:allow
    "-----BEGIN RSA PRIVATE KEY-----",                         # key header  # gitleaks:allow
]


def test_secret_shapes_are_refused(monkeypatch):
    _public(monkeypatch)
    for s in SECRETS:
        prompt = f"here is context: {s}\nplease review"
        ok, reason = gptc.gate(prompt, ["torvalds/linux"])
        assert not ok and "secret-like" in reason, f"MISSED secret: {s!r}"


def test_clean_prose_not_flagged_as_secret(monkeypatch):
    _public(monkeypatch)
    # ordinary technical prose must not false-positive
    ok, _ = gptc.gate("The password reset flow calls the token endpoint over TLS.",
                      ["torvalds/linux"])
    assert ok
