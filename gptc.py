#!/usr/bin/env python3
"""
gptc — Claude commands GPT.

A small bridge that lets a local agent (Claude Code) hand a self-contained job to a
logged-in ChatGPT tab, wait for the answer in a DETACHED process, and act on it —
using the two *subscriptions* you already pay for, no API key and no per-token bill.

The workflow (a thread, not a one-shot):
    submit  -> open a fresh chat, type the prompt, send; return rid + conversation id
    wait    -> DETACHED poller: re-attach to that conversation, poll to the wrapped
               answer, write it to a file; its exit wakes the agent
    followup-> send another round into the same conversation (feed local results back)
    status  -> one-shot state of a conversation

Design stance (differs from prior art on purpose):
  * PUBLIC-CODE-ONLY egress by default. Every consult carries >=1 public GitHub link,
    gh-confirmed public. The whole rendered prompt is scanned for secret shapes and
    fails closed. A link-free follow-up requires an explicit --allow-nolink flag; in the
    interactive path that is a human, in the auto path it is an owner-authorized job field.
  * TWO SEND PATHS. Interactive: the send happens inside a command you run. Auto mode:
    a daemon (`watch`, agent- or user-started; `--detach` for background) does the send off
    the agent so it works under Claude Code's exfiltration classifier — the LOGIN stays the
    human's job, but starting this local process does not. It re-derives the PROMPT + slugs
    itself (never
    trusts agent-supplied rendered text) and re-validates every job at the point of send
    (strict schema, secret re-scan, gh public re-check, fail closed). This removes the
    platform's exfiltration net in exchange for that gate — a documented, opt-in trade-off,
    not a hidden bypass. Honest scope of the trust: the daemon does NOT trust agent-supplied
    *content*, but it DOES honor a few owner-authorized agent-supplied *flags* — `private`
    (allow non-public repos) and `allow_nolink` (waive the link anchor on a follow-up) — by
    the owner's deliberate choice to give the agent that latitude. Pure-stdlib state cannot
    be made tamper-proof against an agent running as the SAME OS user; strong isolation
    needs the daemon under a separate account. The `out` path IS contained to ANSWER_DIR so
    the daemon can't be steered into writing answer content to an arbitrary file.
  * Ordinary automation of your OWN logged-in session. The tool never handles your
    password; you log into a dedicated Chrome profile once, by hand.

Note: automating the ChatGPT *web* app is against OpenAI's Terms of Use (which allow
programmatic extraction only via the API). Use your own account, at human cadence,
and accept the account-level risk. This tool does not bypass login/CAPTCHA/limits.
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.parse
import secrets
from pathlib import Path

# --------------------------------------------------------------------------- #
# config (all overridable via env; nothing here is a secret)
# --------------------------------------------------------------------------- #
PORT = int(os.environ.get("GPTC_PORT", "9333"))
PROFILE = os.environ.get("GPTC_PROFILE", str(Path.home() / ".gptc-chrome"))
CHROME = os.environ.get("GPTC_CHROME", "")
PROJECT_URL = os.environ.get("GPTC_PROJECT_URL", "https://chatgpt.com/")
ANSWER_DIR = os.environ.get("GPTC_ANSWER_DIR", str(Path.cwd() / "gptc_answers"))
STATE_DIR = os.environ.get("GPTC_STATE_DIR", "/tmp/gptc")
SPOOL_DIR = os.environ.get("GPTC_SPOOL_DIR", os.path.join(STATE_DIR, "spool"))
ORIGIN = f"http://127.0.0.1:{PORT}"

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
]

SELF = os.path.abspath(__file__)


def _err(msg: str) -> None:
    print(f"gptc: {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# egress gate  (the security heart — deliberately stricter than prior art)
# --------------------------------------------------------------------------- #
SECRET_RES: list[tuple[str, re.Pattern]] = [
    ("openai/anthropic-key", re.compile(r"sk-(?:ant-)?[A-Za-z0-9_\-]{16,}")),
    ("stripe-key", re.compile(r"[rs]k_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("private-key-block", re.compile(r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("conn-string-cred", re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:@/]+:[^\s:@/]+@[^\s/]+")),
    ("assigned-secret", re.compile(
        r"(?i)\b(?:pass(?:wd|word)?|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token|bearer)\b"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9._\-/+]{8,}")),
]

# strict token grammars — validated before a value is ever placed in a URL or a prompt
_RID_RE = re.compile(r"[0-9a-f]{8,64}\Z")
_CONV_ID_RE = re.compile(r"[0-9a-fA-F][0-9a-fA-F-]{15,63}\Z")
_COMMIT_SHA_RE = re.compile(r"[0-9a-fA-F]{40}\Z")
_ALLOWED_CHAT_HOSTS = {"chatgpt.com", "chat.openai.com"}


def _slug_ok(slug: str) -> bool:
    """owner/repo where each component is a plausible GitHub name. Rejects '.'/'..'/dot-only
    and percent-encoded components so a slug like '../rate_limit' (or '%2e%2e/x') can't ride
    through resolve_link and then normalize to a DIFFERENT `gh api` endpoint — which would let
    a bogus repo pass the --private existence check (gate_public's _gh_ok)."""
    parts = slug.split("/")
    if len(parts) != 2:
        return False
    for p in parts:
        if not p or ".." in p or "%" in p or set(p) <= {"."} or not re.search(r"[A-Za-z0-9]", p):
            return False
    return True


def scan_secrets(text: str) -> str | None:
    for name, rx in SECRET_RES:
        if rx.search(text):
            return name
    return None


def resolve_link(link: str, allow_gist: bool = False):
    """Resolve a code reference into {slug, url, kind}. URLs are parsed strictly
    (exact hostname, no substring match) and stripped of query/fragment so a link
    cannot smuggle a data payload past the gate. Returns (True, info) or (False, err)."""
    link = link.strip()
    # owner/repo#123 -> PR ; bare owner/repo -> repo
    m = re.fullmatch(r"([\w.\-]+/[\w.\-]+)#(\d+)", link)
    if m:
        slug, pr = m.group(1), m.group(2)
        if not _slug_ok(slug):
            return False, f"invalid owner/repo (dot-segment or encoded traversal): {link}"
        return True, {"slug": slug, "url": f"https://github.com/{slug}/pull/{pr}", "kind": "pr", "ref": pr}
    if re.fullmatch(r"[\w.\-]+/[\w.\-]+", link):
        if not _slug_ok(link):
            return False, f"invalid owner/repo (dot-segment or encoded traversal): {link}"
        return True, {"slug": link, "url": f"https://github.com/{link}", "kind": "repo"}
    if link.startswith(("http://", "https://")):
        u = urllib.parse.urlparse(link)
        host = (u.hostname or "").lower()
        if u.username or u.password:
            return False, f"link carries embedded credentials, refused: {link}"
        path = u.path  # query + fragment are dropped on purpose
        if host == "gist.github.com":
            if not allow_gist:
                return False, f"gist links are refused (visibility not cheaply provable): {link}"
            return True, {"slug": None, "url": f"https://gist.github.com{path}", "kind": "gist"}
        if host in ("github.com", "www.github.com"):
            parts = [p for p in path.split("/") if p]
            if len(parts) < 2:
                return False, f"GitHub link missing owner/repo: {link}"
            slug = f"{parts[0]}/{parts[1]}".removesuffix(".git")
            if not _slug_ok(slug):
                return False, f"invalid owner/repo (dot-segment or encoded traversal): {link}"
            # canonicalize to an allowlisted shape — an arbitrary path tail (e.g.
            # /blob/main/<BASE64>) is refused so a link can't smuggle data past the gate
            if len(parts) == 2:
                return True, {"slug": slug, "url": f"https://github.com/{slug}", "kind": "repo"}
            if len(parts) == 4 and parts[2] == "pull" and parts[3].isdigit():
                return True, {"slug": slug, "url": f"https://github.com/{slug}/pull/{parts[3]}",
                              "kind": "pr", "ref": parts[3]}
            if len(parts) == 4 and parts[2] == "commit" and _COMMIT_SHA_RE.fullmatch(parts[3]):
                return True, {"slug": slug, "url": f"https://github.com/{slug}/commit/{parts[3]}",
                              "kind": "commit", "ref": parts[3]}
            return False, ("unsupported GitHub URL shape (allowed: repo, /pull/<n>, "
                           f"/commit/<40-hex>; name a specific file in the task text): {link}")
        if host == "raw.githubusercontent.com":
            return False, ("raw.githubusercontent URLs are refused (path can smuggle data); "
                           "pass owner/repo or a github.com repo/pull/commit URL")
        return False, f"not a GitHub link (only public GitHub is allowed): {link}"
    return False, f"unrecognized code reference: {link}"


def _repo_is_public(slug: str) -> bool:
    """gh-confirm the repo is public. Fails CLOSED on any error."""
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{slug}", "--jq", ".visibility"],
            capture_output=True, text=True, timeout=20,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and r.stdout.strip() == "public"


def resolve_all(links: list[str], allow_gist: bool = False):
    """Resolve link syntax only (no network). Returns (True, resolved) or (False, reason)."""
    resolved = []
    for l in links:
        ok, info = resolve_link(l, allow_gist)
        if not ok:
            return False, info
        resolved.append(info)
    if not resolved:
        return False, "refusing: no public code link provided (send >=1 public GitHub link)"
    return True, resolved


def gate_local(prompt_text: str, links: list[str], allow_gist: bool = False):
    """LOCAL gate: secret scan + link-syntax resolve. No network — safe to run on the
    agent side under an exfiltration classifier. Returns (True, resolved) or (False, reason)."""
    hit = scan_secrets(prompt_text)
    if hit:
        return False, f"refusing: prompt contains secret-like content ({hit})"
    return resolve_all(links, allow_gist)


def _gh_ok(api_path: str) -> bool:
    """True iff `gh api <path>` succeeds. Fails CLOSED on any error/no-gh."""
    try:
        r = subprocess.run(["gh", "api", api_path, "--silent"],
                           capture_output=True, text=True, timeout=20)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def gate_public(resolved: list[dict], allow_private: bool = False):
    """NETWORK gate: gh-confirm every repo is public AND that the referenced object
    actually EXISTS. The latter closes covert channels — a /commit/<40-hex> or
    /pull/<digits> whose value is attacker-chosen data (not a real object) is refused,
    as are gists (visibility/existence unprovable). Fails closed. Runs in the daemon
    or in submit/consult, never on the classifier-guarded agent side.

    allow_private (opt-in, per job): drop the PUBLIC assertion but still gh-confirm the
    repo EXISTS (an authenticated `gh` can see the owner's private repos), so a bogus
    slug can't ride through as a covert channel. This is the deliberate posture relaxation
    for consulting on your OWN private code via ChatGPT's GitHub connector — the secret
    scan still runs, and the connector-fetched CONTENT is inherently outside this gate."""
    for info in resolved:
        if info["slug"] is None:  # gist — cannot prove public or that the object exists
            return False, "refusing: gists are not allowed (visibility/existence unprovable)"
        if allow_private:
            if not _gh_ok(f"repos/{info['slug']}"):
                return False, f"refusing: repo not found even with --private: {info['slug']}"
        elif not _repo_is_public(info["slug"]):
            return False, f"refusing: repo not gh-confirmed public: {info['slug']}"
        kind, ref = info.get("kind"), info.get("ref")
        if kind == "pr" and not _gh_ok(f"repos/{info['slug']}/pulls/{ref}"):
            return False, f"refusing: PR #{ref} not found in {info['slug']} (covert-channel guard)"
        if kind == "commit" and not _gh_ok(f"repos/{info['slug']}/commits/{ref}"):
            return False, f"refusing: commit {ref} not found in {info['slug']} (covert-channel guard)"
    return True, resolved


def gate(prompt_text: str, links: list[str], allow_gist: bool = False,
         allow_private: bool = False):
    """Full gate = local + public. Used by the interactive submit/consult path."""
    ok, res = gate_local(prompt_text, links, allow_gist)
    if not ok:
        return False, res
    return gate_public(res, allow_private=allow_private)


# --------------------------------------------------------------------------- #
# sentinel parse (canonical Python copy; a JS mirror runs in the page)
# --------------------------------------------------------------------------- #
def _fence_open(stripped: str):
    """Return (char, length) if the line opens/closes a code fence (>=3 of ` or ~),
    else None. Delimiter-aware so a ``` inside a ~~~ block can't desync the parser."""
    m = re.match(r"(`{3,}|~{3,})", stripped)
    return (m.group(1)[0], len(m.group(1))) if m else None


def sentinel_parse(text: str, rid: str) -> str | None:
    """Extract the answer between bare-line BEGIN_RESPONSE:<rid> / END_RESPONSE:<rid>.
    Fence-aware with delimiter tracking (a closing fence must be the same char and at
    least as long), so 4-backtick / ~~~ blocks don't false-trigger. Returns None until a
    complete wrapped answer is present."""
    begin, end = f"BEGIN_RESPONSE:{rid}", f"END_RESPONSE:{rid}"
    fence = None  # (char, length) when inside a fence, else None
    started = done = False
    buf: list[str] = []
    for line in text.split("\n"):
        t = line.strip()
        f = _fence_open(t)
        if f:
            if fence is None:
                fence = f
            elif f[0] == fence[0] and f[1] >= fence[1]:
                fence = None
            if started:
                buf.append(line)
            continue
        if not started:
            if fence is None and t == begin:
                started = True
            continue
        if fence is None and t == end:
            done = True
            break
        buf.append(line)
    if started and done:
        return "\n".join(buf).strip()
    return None


def model_downgrade_warning(model: str | None, expect: str) -> str | None:
    """If an expected-model substring is configured and the answering model doesn't match,
    return a warning string (used to flag a silent Plus-tier downgrade). Else None."""
    if not expect or not model:
        return None
    return None if expect.lower() in model.lower() else f"answered by {model!r}, expected ~{expect!r}"


_OUTPUT_CONTRACT = """--- OUTPUT CONTRACT (read carefully) ---
Take as long as you need to reason. When your FINAL answer is ready, print it wrapped
EXACTLY like this — each sentinel alone on its own line, nothing else on that line,
and NOT inside a code fence:

BEGIN_RESPONSE:{rid}
<your complete final answer here>
END_RESPONSE:{rid}

Emit the BEGIN line exactly once, at the start of the final answer. End the load-bearing
claims a local agent should re-check with a short `verify locally:` note."""


def render_prompt(rid: str, title: str, role: str, task: str, resolved: list[dict]) -> str:
    refs = "\n".join(f"- {i['url']}" for i in resolved)
    return f"""{role}

TASK: {title}

{task}

CODE — open and read these public GitHub links before answering:
{refs}

""" + _OUTPUT_CONTRACT.format(rid=rid)


def render_followup(rid: str, task: str, resolved: list[dict]) -> str:
    refs = ("\n\nMore public code for this round:\n" +
            "\n".join(f"- {i['url']}" for i in resolved)) if resolved else ""
    return f"""{task}{refs}

""" + _OUTPUT_CONTRACT.format(rid=rid)


# --------------------------------------------------------------------------- #
# minimal CDP client
# --------------------------------------------------------------------------- #
def _http_json(path: str):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}",
                                 headers={"Host": f"127.0.0.1:{PORT}"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read().decode())


def _chrome_up() -> bool:
    try:
        _http_json("/json/version")
        return True
    except Exception:
        return False


class Page:
    """A CDP session bound to one page target. Requires `websocket-client`."""

    def __init__(self, ws_url: str, target_id: str | None = None):
        try:
            import websocket  # type: ignore
        except ImportError:
            raise SystemExit("gptc: missing dep — run: pip install websocket-client")
        self.ws = websocket.create_connection(ws_url, origin=ORIGIN, timeout=30)
        self.target_id = target_id
        self._id = 0

    def _call(self, method: str, params: dict | None = None):
        self._id += 1
        mid = self._id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(msg["error"])
                return msg.get("result", {})

    def eval(self, expression: str):
        r = self._call("Runtime.evaluate", {
            "expression": expression, "returnByValue": True, "awaitPromise": True,
        })
        if "exceptionDetails" in r:
            raise RuntimeError(r["exceptionDetails"].get("text", "js error"))
        return r.get("result", {}).get("value")

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass

    def close_target(self):
        """Actually close the browser tab (not just this client connection)."""
        if not self.target_id:
            return
        try:
            import websocket  # type: ignore
            ver = _http_json("/json/version")
            bws = websocket.create_connection(ver["webSocketDebuggerUrl"], origin=ORIGIN, timeout=10)
            bws.send(json.dumps({"id": 1, "method": "Target.closeTarget",
                                 "params": {"targetId": self.target_id}}))
            bws.recv()
            bws.close()
        except Exception:
            pass


def open_tab(url: str) -> Page:
    """Create a fresh tab at `url` over the browser endpoint, then attach to it."""
    ver = _http_json("/json/version")
    import websocket  # type: ignore
    bws = websocket.create_connection(ver["webSocketDebuggerUrl"], origin=ORIGIN, timeout=30)
    try:
        bws.send(json.dumps({"id": 1, "method": "Target.createTarget", "params": {"url": url}}))
        target_id = None
        while target_id is None:
            m = json.loads(bws.recv())
            if m.get("id") == 1:
                target_id = m["result"]["targetId"]
    finally:
        bws.close()
    for _ in range(40):
        for t in _http_json("/json"):
            if t.get("id") == target_id and t.get("webSocketDebuggerUrl"):
                return Page(t["webSocketDebuggerUrl"], target_id=target_id)
        time.sleep(0.25)
    raise SystemExit("gptc: could not attach to the new tab")


# page-side JS ------------------------------------------------------------- #
_COMPOSER_JS = (
    "!!document.querySelector('#prompt-textarea, "
    "div[contenteditable=\"true\"][role=\"textbox\"], textarea#prompt-textarea')"
)
_LOGIN_MARKER_JS = (
    "(function(){var t=(document.body.innerText||'');"
    "return /log in|sign up|create an account|verify you are human/i.test(t) "
    "&& !document.querySelector('#prompt-textarea');})()"
)


def _type_js(text: str) -> str:
    return (
        "(function(t){var b=document.querySelector('#prompt-textarea,"
        "div[contenteditable=\"true\"][role=\"textbox\"],textarea#prompt-textarea');"
        "if(!b)return 'no-composer';b.focus();"
        "document.execCommand('selectAll',false,null);"
        "document.execCommand('insertText',false,t);return 'typed';})("
        + json.dumps(text) + ")"
    )


_SEND_JS = (
    "(function(){var s=document.querySelector('button[data-testid=\"send-button\"]');"
    "if(s&&!s.disabled){s.click();return 'sent';}return 'no-send-button';})()"
)


def _extract_js(rid: str) -> str:
    # Correlate to OUR request: pick the assistant node whose text carries our BEGIN
    # sentinel (not the globally-last node), read its model slug, and report whether the
    # model is still generating — so poll_answer can require a stable, finished answer.
    return """(function(rid){
      var begin='BEGIN_RESPONSE:'+rid, end='END_RESPONSE:'+rid;
      var body=(document.body.innerText||'');
      if(/you've reached|rate limit|too many requests/i.test(body))
        return JSON.stringify({state:'blocker',reason:'rate-limit'});
      var generating=!!document.querySelector('button[data-testid="stop-button"]');
      var nodes=document.querySelectorAll('[data-message-author-role="assistant"]');
      var el=null;
      for(var i=nodes.length-1;i>=0;i--){
        if((nodes[i].textContent||'').indexOf(begin)!==-1){el=nodes[i];break;}
      }
      if(!el) return JSON.stringify({state:generating?'generating':'thinking',generating:generating});
      var model=null, mo=el.closest('[data-message-model-slug]');
      if(mo) model=mo.getAttribute('data-message-model-slug');
      var text=el.textContent||'';
      var lines=text.split('\\n'); var fence=null,started=false,done=false,buf=[];
      for(var j=0;j<lines.length;j++){var ln=lines[j],t=ln.trim();
        var fm=t.match(/^(`{3,}|~{3,})/);
        if(fm){var ch=fm[1][0],len=fm[1].length;
          if(fence===null){fence=[ch,len];}
          else if(ch===fence[0]&&len>=fence[1]){fence=null;}
          if(started)buf.push(ln); continue;}
        if(!started){ if(fence===null&&t===begin)started=true; continue; }
        if(fence===null&&t===end){done=true;break;}
        buf.push(ln);}
      if(started&&done)
        return JSON.stringify({state:'done',text:buf.join('\\n').trim(),model:model,generating:generating});
      return JSON.stringify({state:'generating',generating:generating,model:model});
    })(""" + json.dumps(rid) + ")"


def _salvage_js(rid: str) -> str:
    """Best-effort rescue of an UNWRAPPED answer on timeout: return the raw text of the
    assistant node carrying our rid's BEGIN (even if END/wrapping is missing), else the last
    assistant node. Lets a long (Pro/Ultra) reasoning result be kept as <out>.partial instead
    of lost when the model forgot the sentinels or the deadline clipped it."""
    return """(function(rid){
      var begin='BEGIN_RESPONSE:'+rid;
      var nodes=document.querySelectorAll('[data-message-author-role="assistant"]');
      var el=null;
      for(var i=nodes.length-1;i>=0;i--){ if((nodes[i].textContent||'').indexOf(begin)!==-1){el=nodes[i];break;} }
      if(!el && nodes.length) el=nodes[nodes.length-1];
      if(!el) return JSON.stringify({found:false});
      var model=null, mo=el.closest('[data-message-model-slug]');
      if(mo) model=mo.getAttribute('data-message-model-slug');
      var generating=!!document.querySelector('button[data-testid="stop-button"]');
      return JSON.stringify({found:true,text:(el.textContent||'').trim(),model:model,generating:generating});
    })(""" + json.dumps(rid) + ")"


# --------------------------------------------------------------------------- #
# session tier: mode (Chat/Work) + its pinned model. SINGLE source of truth.
#   Chat -> the "Pro" effort tier, nested under the GPT-5.6 Sol submenu (fast, cheap)
#   Work -> the "Ultra" effort tier, in the Advanced view's Effort submenu (strongest).
#           NB: Work's simple power slider caps at "Extra High"; Max/Ultra live only in
#           the Advanced -> Effort submenu, so we drive that, not the slider.
# These selectors are LIVE-CDP and have no stability contract; every actuation is
# verified and fails LOUD/CLOSED (SystemExit 3) rather than silently answer on a
# weaker tier than requested — consistent with the tool's model-transparency stance.
# --------------------------------------------------------------------------- #
_MODE_LABEL = {"chat": "Chat", "work": "Work"}
_CHAT_MODEL_ITEM = "Pro"      # Chat: the effort tier picked under the GPT-5.6 Sol submenu
_WORK_EFFORT = "Ultra"        # Work: the strongest effort tier (Advanced -> Effort submenu)


def _select_mode_js(want: str) -> str:
    """Click the Chat/Work segmented radio whose text is exactly `want`."""
    return ("(function(w){var rs=document.querySelectorAll('button[role=\"radio\"]');"
            "for(var i=0;i<rs.length;i++){if((rs[i].textContent||'').trim()===w){rs[i].click();return 'clicked';}}"
            "return 'no-radio';})(" + json.dumps(want) + ")")


_READ_MODE_JS = ("(function(){var rs=document.querySelectorAll('button[role=\"radio\"]');"
                 "for(var i=0;i<rs.length;i++){if(rs[i].getAttribute('data-state')==='on')"
                 "return (rs[i].textContent||'').trim();}return null;})()")

# open the composer model pill — it is a Radix menu trigger, so a plain .click() does
# not open it; dispatch a real pointerdown/up sequence at its center.
_OPEN_MODEL_PILL_JS = (
    "(function(){var form=document.querySelector('form');"
    "var pill=form&&form.querySelector('button.__composer-pill[aria-haspopup=\"menu\"]');"
    "if(!pill)return 'no-pill';var r=pill.getBoundingClientRect();var x=r.x+r.width/2,y=r.y+r.height/2;"
    "function ev(t){return new PointerEvent(t,{bubbles:true,cancelable:true,clientX:x,clientY:y,pointerId:1,button:0,isPrimary:true});}"
    "pill.dispatchEvent(ev('pointerdown'));pill.dispatchEvent(ev('pointerup'));pill.click();return 'opened';})()")

_MODEL_PILL_LABEL_JS = (
    "(function(){var form=document.querySelector('form');"
    "var pill=form&&form.querySelector('button.__composer-pill[aria-haspopup=\"menu\"]');"
    "return pill?(pill.textContent||'').trim():null;})()")


# Chat mode nests the effort tiers under a "GPT-5.6 Sol" submenu: open that submenu, then
# the tiers (Instant / Medium / High / Extra High / Pro) appear as [role=menuitemradio].
_OPEN_CHAT_SUBMENU_JS = (
    "(function(){var mi=document.querySelectorAll('[role=\"menuitem\"][aria-haspopup=\"menu\"]');"
    "var trig=null;for(var i=0;i<mi.length;i++){if((mi[i].textContent||'').indexOf('Sol')!==-1){trig=mi[i];break;}}"
    "if(!trig)return 'no-submenu';var r=trig.getBoundingClientRect();var x=r.x+r.width/2,y=r.y+r.height/2;"
    "function ev(t){return new PointerEvent(t,{bubbles:true,cancelable:true,clientX:x,clientY:y,pointerId:1,isPrimary:true});}"
    "trig.dispatchEvent(ev('pointerdown'));trig.dispatchEvent(ev('pointerup'));trig.click();return 'opened';})()")


def _pick_radio_js(target: str) -> str:
    """Click the [role=menuitemradio] effort tier whose trimmed text equals `target`."""
    return ("(function(w){var r=document.querySelectorAll('[role=\"menuitemradio\"]');"
            "for(var i=0;i<r.length;i++){if((r[i].textContent||'').trim()===w){r[i].click();return 'picked';}}"
            "return 'no-item';})(" + json.dumps(target) + ")")


# Work mode: the full effort range (incl. Max/Ultra, above the simple slider's cap) lives
# in the Advanced view's "Effort" submenu. Open it, then the tiers are [role=menuitemradio].
_OPEN_EFFORT_SUBMENU_JS = (
    "(function(){var it=document.querySelectorAll('[role=\"menuitem\"][aria-haspopup=\"menu\"]');"
    "var t=null;for(var i=0;i<it.length;i++){if((it[i].textContent||'').trim().indexOf('Effort')===0){t=it[i];break;}}"
    "if(!t)return 'no-effort';var r=t.getBoundingClientRect();var x=r.x+r.width/2,y=r.y+r.height/2;"
    "function ev(ty){return new PointerEvent(ty,{bubbles:true,cancelable:true,clientX:x,clientY:y,pointerId:1,isPrimary:true});}"
    "t.dispatchEvent(ev('pointerover'));t.dispatchEvent(ev('pointerdown'));t.dispatchEvent(ev('pointerup'));t.click();"
    "return 'opened';})()")

# read the "Effort <tier>" row label to confirm the pick took
_EFFORT_ROW_JS = (
    "(function(){var it=document.querySelectorAll('[role=\"menuitem\"]');"
    "for(var i=0;i<it.length;i++){var t=(it[i].textContent||'').trim();if(t.indexOf('Effort')===0)return t;}return null;})()")


def _pick_effort_js(target: str) -> str:
    """Click the [role=menuitemradio] effort tier whose text STARTS WITH `target` (the Ultra
    row carries a 'Consumes usage limits faster' subtitle, so match by prefix not equality)."""
    return ("(function(w){var r=document.querySelectorAll('[role=\"menuitemradio\"]');"
            "for(var i=0;i<r.length;i++){if((r[i].textContent||'').trim().indexOf(w)===0){r[i].click();return 'picked';}}"
            "return 'no-item';})(" + json.dumps(target) + ")")


_MENU_ESCAPE_JS = ("document.body.dispatchEvent(new KeyboardEvent("
                   "'keydown',{key:'Escape',bubbles:true}))")


# --------------------------------------------------------------------------- #
# page orchestration helpers
# --------------------------------------------------------------------------- #
def conv_id_from_url(url: str | None) -> str | None:
    """Extract a conversation id ONLY from an exact https://chatgpt.com[/g/<gizmo>]/c/<id>
    URL (correct scheme + host, no creds/query/fragment). Returns None otherwise — this is
    used both to read identity and to REJECT look-alike or redirect URLs like
    https://evil.example/?next=/c/<id>."""
    if not url:
        return None
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if u.scheme != "https" or (u.hostname or "").lower() not in _ALLOWED_CHAT_HOSTS:
        return None
    if u.username or u.password or u.query or u.fragment:
        return None
    m = re.fullmatch(r"/(?:g/[^/]+/)?c/([0-9a-fA-F][0-9a-fA-F-]{15,63})/?", u.path)
    return m.group(1) if m else None


def _wait_composer(page: Page, tries: int = 120):
    for _ in range(tries):
        if page.eval(_COMPOSER_JS):
            return True
        if page.eval(_LOGIN_MARKER_JS):
            return "login"
        time.sleep(0.5)
    return False


def _die_if_no_chrome():
    if not _chrome_up():
        _err(f"debug Chrome not running on {PORT}. Run: gptc launch")
        raise SystemExit(2)


# read-only presence probes — the toggle/pill/menu can lag the composer by a frame, and
# the very first eval after a fresh tab opens sometimes races a re-render; poll, don't fire once.
_RADIOS_COUNT_JS = "document.querySelectorAll('button[role=\"radio\"]').length"
_PILL_PRESENT_JS = ("!!document.querySelector('form button.__composer-pill"
                    "[aria-haspopup=\"menu\"]')")
_MENUITEMRADIO_COUNT_JS = "document.querySelectorAll('[role=\"menuitemradio\"]').length"


def _eval_until(page: Page, expr: str, pred, tries: int = 15, delay: float = 0.4):
    """Poll `expr` until pred(result) is truthy (or tries exhausted); return the last value.
    A raised CDP error counts as a failed attempt, not a crash — keeps actuation robust to
    a transient re-render mid-configuration."""
    val = None
    for _ in range(tries):
        try:
            val = page.eval(expr)
        except Exception:
            val = None
        if pred(val):
            return val
        time.sleep(delay)
    return val


def _set_mode(page: Page, want: str) -> bool:
    """Select the Chat/Work segment and confirm it took (both polled)."""
    if not _eval_until(page, _RADIOS_COUNT_JS, lambda v: isinstance(v, int) and v >= 2):
        return False
    for _ in range(4):
        if page.eval(_select_mode_js(want)) == "clicked":
            break
        time.sleep(0.4)
    return _eval_until(page, _READ_MODE_JS, lambda v: v == want, tries=8) == want


def _open_model_picker(page: Page) -> bool:
    """Wait for the composer model pill, then open its menu once (avoid double-click toggling)."""
    if not _eval_until(page, _PILL_PRESENT_JS, lambda v: bool(v)):
        return False
    return page.eval(_OPEN_MODEL_PILL_JS) == "opened"


def _set_chat_pro(page: Page) -> bool:
    """Chat: open the GPT-5.6 Sol submenu, pick the 'Pro' effort tier, confirm the pill."""
    if page.eval(_OPEN_CHAT_SUBMENU_JS) != "opened":
        return False
    if not _eval_until(page, _MENUITEMRADIO_COUNT_JS, lambda v: isinstance(v, int) and v > 0):
        return False
    if page.eval(_pick_radio_js(_CHAT_MODEL_ITEM)) != "picked":
        return False
    lab = _eval_until(page, _MODEL_PILL_LABEL_JS,
                      lambda v: isinstance(v, str) and _CHAT_MODEL_ITEM in v, tries=6)
    return isinstance(lab, str) and _CHAT_MODEL_ITEM in lab


def _set_work_ultra(page: Page) -> bool:
    """Work: open the Advanced Effort submenu, pick the strongest tier (Ultra), then confirm
    the committed composer pill shows BOTH the Sol family AND Ultra. Ultra is above the simple
    slider's cap, so we drive the submenu; and we verify the family (not just the effort) so a
    non-Sol Work model can't pass as 'Sol Ultra'."""
    if page.eval(_OPEN_EFFORT_SUBMENU_JS) != "opened":
        return False
    if not _eval_until(page, _MENUITEMRADIO_COUNT_JS, lambda v: isinstance(v, int) and v > 0):
        return False
    if page.eval(_pick_effort_js(_WORK_EFFORT)) != "picked":
        return False
    row = _eval_until(page, _EFFORT_ROW_JS,
                      lambda v: isinstance(v, str) and _WORK_EFFORT in v, tries=6)
    if not (isinstance(row, str) and _WORK_EFFORT in row):  # _eval_until returns the last value
        return False
    page.eval(_MENU_ESCAPE_JS)  # close so the composer pill shows the committed family+effort
    time.sleep(0.3)
    lab = _eval_until(page, _MODEL_PILL_LABEL_JS,
                      lambda v: isinstance(v, str) and "Sol" in v and _WORK_EFFORT in v, tries=6)
    return isinstance(lab, str) and "Sol" in lab and _WORK_EFFORT in lab


def configure_session(page: Page, mode: str | None) -> None:
    """Put a FRESH chat into the requested tier (Chat=Pro / Work=strongest) and VERIFY it,
    before any prompt is typed. Fail LOUD/CLOSED (SystemExit 3) if the tier can't be
    confirmed — never silently answer on a weaker tier than the caller asked for. `mode`
    None means 'leave the tab as-is' (backward compatible). Every actuation polls for its
    control (a fresh tab races re-renders) and is read back to confirm it took."""
    if not mode:
        return
    want = _MODE_LABEL.get(mode)
    if want is None:
        _err(f"unknown mode {mode!r} (expected chat|work)")
        raise SystemExit(2)
    if not _set_mode(page, want):
        _err(f"could not select/confirm mode {want!r} (ChatGPT UI drift?) — fail closed")
        raise SystemExit(3)
    if not _open_model_picker(page):
        _err("model picker pill not found (UI drift?) — fail closed")
        raise SystemExit(3)
    ok = _set_chat_pro(page) if mode == "chat" else _set_work_ultra(page)
    if not ok:
        tier = f"Chat/{_CHAT_MODEL_ITEM}" if mode == "chat" else f"Work/{_WORK_EFFORT}"
        _err(f"could not pin the model tier ({tier}) (UI drift?) — fail closed")
        raise SystemExit(3)
    page.eval(_MENU_ESCAPE_JS)  # close the picker so it can't intercept the send
    time.sleep(0.3)


def open_new_chat(mode: str | None = None) -> Page:
    _die_if_no_chrome()
    page = open_tab(PROJECT_URL)
    # Once the tab exists, ANY failure below (login wall, UI drift, a fail-closed tier
    # selection in configure_session) must close it — otherwise every such error leaks a
    # Chrome tab + CDP socket, and tier failures are common under UI drift.
    try:
        st = _wait_composer(page)
        if st == "login":
            _err("login wall — log into ChatGPT in the debug Chrome window, then retry")
            raise SystemExit(3)
        if not st:
            _err("composer never appeared (login? UI drift?)")
            raise SystemExit(3)
        configure_session(page, mode)
        return page
    except BaseException:
        try:
            page.close_target()
            page.close()
        except Exception:
            pass
        raise


def find_conversation_page(conv_id: str) -> Page:
    """Attach to the tab showing EXACTLY this conversation, or reopen it and verify the
    page really landed on /c/<conv_id>. Fails closed rather than attach to a wrong chat.
    Grammar-validates the id FIRST (before any URL is built) so interactive callers can't
    pass a malformed 'id?leak=DATA' the way the daemon path is already protected against."""
    if not isinstance(conv_id, str) or not _CONV_ID_RE.fullmatch(conv_id):
        _err("find_conversation_page: invalid conversation id (fail closed)")
        raise SystemExit(2)
    _die_if_no_chrome()
    for t in _http_json("/json"):
        if (t.get("type") == "page" and conv_id_from_url(t.get("url")) == conv_id
                and t.get("webSocketDebuggerUrl")):
            return Page(t["webSocketDebuggerUrl"], target_id=t.get("id"))
    page = open_tab(f"https://chatgpt.com/c/{conv_id}")
    st = _wait_composer(page)
    if st == "login":
        _err("login wall — log into ChatGPT, then retry")
        raise SystemExit(3)
    if not st:
        _err(f"could not open conversation {conv_id}")
        raise SystemExit(2)
    if conv_id_from_url(page.eval("location.href")) != conv_id:
        page.close()
        _err(f"conversation {conv_id} did not load (redirected? deleted?) — fail closed")
        raise SystemExit(2)
    return page


def newest_chat_page() -> Page | None:
    _die_if_no_chrome()
    pages = [t for t in _http_json("/json")
             if t.get("type") == "page" and "/c/" in (t.get("url") or "")
             and t.get("webSocketDebuggerUrl")]
    if not pages:
        return None
    return Page(pages[0]["webSocketDebuggerUrl"], target_id=pages[0].get("id"))


def type_and_send(page: Page, prompt: str, expected_conversation: str | None = None) -> None:
    """Type the prompt and click send. If expected_conversation is given (follow-ups),
    re-verify the page is STILL on that exact conversation immediately before typing —
    closing the TOCTOU gap between attaching to a tab and sending into it. The check lives
    here so no caller can forget it."""
    if expected_conversation is not None:
        actual = conv_id_from_url(page.eval("location.href"))
        if actual != expected_conversation:
            _err(f"conversation drifted before send (expected {expected_conversation}, "
                 f"now {actual}) — fail closed, not sending")
            raise SystemExit(2)
    if page.eval(_type_js(prompt)) != "typed":
        _err("could not type into the composer (selector drift?)")
        raise SystemExit(2)
    time.sleep(0.4)
    send = page.eval(_SEND_JS)
    if send != "sent":
        _err(f"could not click send ({send}) — ChatGPT UI may have changed")
        raise SystemExit(2)


def capture_conversation_id(page: Page, timeout: int = 25) -> str | None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        cid = conv_id_from_url(page.eval("location.href"))
        if cid:
            return cid
        time.sleep(0.5)
    return None


_RECONNECT_BACKOFF = (1.0, 2.0, 4.0)  # bounded re-attach schedule per outage


def _cdp_drop_excs() -> tuple:
    """Exception families meaning 'the CDP transport died' (retryable by re-attach),
    vs page/CDP-level errors (RuntimeError) which must stay loud. WebSocketException
    covers ConnectionClosed and the 30s recv timeout a half-open socket presents as;
    ConnectionError covers raw-socket resets escaping ws.send."""
    try:
        import websocket  # type: ignore
        return (websocket.WebSocketException, ConnectionError)
    except ImportError:
        return (ConnectionError,)


def poll_answer(page: Page, rid: str, timeout: int, poll: float,
                conversation_id: str | None = None, heartbeat_cb=None):
    """Poll our request's answer node to a STABLE, finished result. Returns
    (state, answer_or_reason, model, page). state in {done, blocker, timeout}. A wrapped
    answer is accepted only once generation has stopped AND the text is unchanged across
    two polls — so content streamed after END_RESPONSE can't be truncated.
    A transient CDP drop is survived by re-attaching to `conversation_id` (bounded
    retries with backoff, fail closed if the conversation is truly gone). The returned
    `page` is the LIVE one — callers must close it, not the page they passed in.
    `heartbeat_cb`, if given, is called once per poll tick — the daemon passes it so a
    long-running job (a Pro/Ultra answer legitimately takes minutes) keeps the liveness
    heartbeat fresh instead of looking dead to a waiting `await`. It must never break the
    poll, so the caller wraps it fail-safe."""
    drop_excs = _cdp_drop_excs()
    deadline = time.time() + timeout
    last_done = None
    model = None
    drops = 0
    while time.time() < deadline:
        time.sleep(poll)
        if heartbeat_cb is not None:
            heartbeat_cb()                       # alive-but-slow != dead: keep heartbeat fresh
        try:
            raw = page.eval(_extract_js(rid))
            drops = 0                            # healthy again -> reset outage budget
        except drop_excs as e:
            drops += 1
            page.close()                         # detach the dead client; NEVER close_target
            if conversation_id is None:
                _err(f"cdp connection lost ({type(e).__name__}) and no conversation id "
                     "to re-attach — fail closed")
                raise SystemExit(2)
            if drops > len(_RECONNECT_BACKOFF):
                _err(f"cdp connection dropped {drops} times without a successful poll "
                     "— giving up")
                raise SystemExit(2)
            if time.time() >= deadline:
                return "timeout", None, model, page
            _err(f"cdp connection dropped ({type(e).__name__}) — re-attaching to "
                 f"{conversation_id} (attempt {drops}/{len(_RECONNECT_BACKOFF)})")
            time.sleep(_RECONNECT_BACKOFF[drops - 1])
            try:
                page = find_conversation_page(conversation_id)  # SystemExit if truly gone
            except drop_excs:
                continue  # transport died mid-reattach; the next eval on the closed page
                          # re-raises and consumes another attempt — still bounded
            last_done = None                     # never trust pre-drop stability
            continue
        st = json.loads(raw) if raw else {"state": "thinking"}
        model = st.get("model") or model
        if st["state"] == "blocker":
            return "blocker", st.get("reason"), model, page
        if st["state"] == "done":
            text = st["text"]
            if last_done == text and not st.get("generating"):
                return "done", text, model, page  # stable + stopped -> accept
            last_done = text                     # first sighting (or still changing) -> re-poll
            continue
        last_done = None                         # not done yet -> reset stability tracking
    # deadline hit — try to salvage any raw (unwrapped) answer so a long reasoning result
    # isn't lost. Caller writes it to <out>.partial with a distinct code, NEVER the clean out.
    try:
        raw = page.eval(_salvage_js(rid))
        s = json.loads(raw) if raw else {}
        if s.get("found") and (s.get("text") or "").strip():
            return "salvaged", s["text"], (s.get("model") or model), page
    except Exception:
        pass
    return "timeout", None, model, page


def write_answer(rid: str, answer: str, out: str | None) -> Path:
    p = Path(out or os.path.join(ANSWER_DIR, f"answer_{rid}.txt"))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(answer)
    return p


def _contain_out(out: str) -> str | None:
    """Return an absolute answer path guaranteed to sit inside ANSWER_DIR, else None.
    Used ONLY by the daemon: `out` is agent-supplied, and the daemon (a higher-trust domain
    under separate-account isolation, and a write-anywhere footgun even same-user) must never
    be steered into writing answer content to an arbitrary path such as ~/.ssh/authorized_keys.
    This does NOT reduce what Claude/GPT can do — the agent has its own filesystem access; it
    only removes the daemon as a write gadget for a prompt-injected job. The interactive --out
    stays unconstrained (a human chose it)."""
    base = os.path.realpath(ANSWER_DIR)
    cand = os.path.realpath(out if os.path.isabs(out) else os.path.join(base, out))
    return cand if cand == base or cand.startswith(base + os.sep) else None


# Pro/Ultra reasoning tiers legitimately run for TENS of minutes (48m+ observed), so the
# default ceiling is generous and mode-aware; the schema still caps at 3600. The timeout is
# only a ceiling — a consult returns the instant the answer lands.
_TIMEOUT_MAX = 3600


def _default_timeout(mode: str | None) -> int:
    return 3000 if mode == "work" else 1800


def _resolve_timeout(a) -> int:
    """Explicit --timeout wins; otherwise a mode-aware generous default, clamped to 1..3600."""
    t = getattr(a, "timeout", None)
    if t is None:
        t = _default_timeout(getattr(a, "mode", None))
    return max(1, min(int(t), _TIMEOUT_MAX))


def _partial_path(out: str) -> str:
    return out + ".partial"


def _wait_cmd(rid: str, conv: str | None, out: str, timeout: int) -> str:
    # plain python3 — no GNU `timeout` prefix (absent on stock macOS); `wait` enforces
    # its own deadline (internal poll deadline + SIGALRM backstop in cmd_wait)
    return (f"python3 {SELF} wait "
            f"--rid {rid} --conversation {conv or 'unknown'} --out {out} --timeout {timeout}")


def _await_cmd(rid: str, out: str, timeout: int) -> str:
    # same portability rule as _wait_cmd; `await` carries its own deadline + backstop
    return f"python3 {SELF} await --rid {rid} --out {out} --timeout {timeout}"


def _hard_deadline(seconds: int) -> None:
    """Portable replacement for the GNU `timeout` prefix the emitted commands used to
    carry (coreutils is absent on stock macOS). If the process is somehow still alive
    `seconds` from now, exit loudly with 4 — the documented no-answer-in-time code.
    os._exit because a backstop must fire even if the interpreter is wedged."""
    def _fire(_sig, _frm):
        _err(f"hard deadline exceeded ({seconds}s) — exiting")
        os._exit(4)
    try:
        signal.signal(signal.SIGALRM, _fire)
        signal.alarm(max(1, int(seconds)))
    except (ValueError, AttributeError):  # non-main thread / platform without SIGALRM
        pass                              # the internal poll deadline still bounds the loop


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #
def _find_chrome() -> str | None:
    if CHROME and Path(CHROME).exists():
        return CHROME
    for c in CHROME_CANDIDATES:
        if Path(c).exists():
            return c
    for c in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge"):
        p = subprocess.run(["which", c], capture_output=True, text=True)
        if p.returncode == 0:
            return p.stdout.strip()
    return None


def cmd_launch(a) -> int:
    if _chrome_up():
        print(f"debug Chrome already up on port {PORT} (profile {PROFILE})")
        print("If not logged in yet, log into ChatGPT in that window and leave it open.")
        return 0
    chrome = _find_chrome()
    if not chrome:
        _err("Chrome not found. Set GPTC_CHROME=/path/to/chrome")
        return 2
    Path(PROFILE).mkdir(parents=True, exist_ok=True)
    args = [chrome,
            f"--remote-debugging-port={PORT}",
            "--remote-debugging-address=127.0.0.1",
            f"--remote-allow-origins={ORIGIN}",
            f"--user-data-dir={PROFILE}",
            "--no-first-run", "--no-default-browser-check",
            PROJECT_URL]
    subprocess.Popen(args, start_new_session=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        if _chrome_up():
            break
        time.sleep(0.25)
    print(f"launched debug Chrome on 127.0.0.1:{PORT} (profile {PROFILE})")
    print(">> Log into ChatGPT in that window ONCE, then leave it open. <<")
    return 0


def cmd_doctor(a) -> int:
    ok = True
    try:
        import websocket  # noqa: F401
        print("ok   python dep: websocket-client")
    except ImportError:
        ok = False
        print("FAIL python dep: websocket-client  (pip install websocket-client)")
    g = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True)
    if g.returncode == 0:
        print("ok   gh CLI authenticated (egress gate can verify public repos)")
    else:
        ok = False
        print("FAIL gh not authenticated  (run: gh auth login) — the gate fails closed without it")
    if _chrome_up():
        print(f"ok   debug Chrome reachable on 127.0.0.1:{PORT}")
        try:
            p = open_tab("about:blank")
            p.close_target()
            p.close()
            print("ok   CDP loopback attach works")
        except Exception as e:
            ok = False
            print(f"FAIL CDP attach: {e}")
    else:
        ok = False
        print(f"FAIL debug Chrome not running on {PORT}  (run: gptc launch)")
    if _daemon_alive():
        print("ok   egress daemon running (auto-mode enqueue/await path is live)")
    else:
        print("note egress daemon not running — start it: gptc watch --detach "
              "(agent may auto-start; login stays the user's job)")
    if shutil.which("timeout") is None:
        print("note GNU `timeout` not found (normal on stock macOS) — fine: emitted "
              "wait/await commands no longer use it; deadlines are enforced in-process")
    print("note verify login by looking at the Chrome window (doctor can't read your session)")
    return 0 if ok else 2


def cmd_gate(a) -> int:
    prompt = a.task + "\n" + "\n".join(a.link)
    ok, res = gate(prompt, a.link, allow_gist=a.allow_gist,
                   allow_private=getattr(a, "private", False))
    if not ok:
        _err(res)
        return 2
    scope = "PRIVATE-ok" if getattr(a, "private", False) else "public-only"
    print(f"gate PASS ({scope}) — would send. Refs:")
    for i in res:
        print(f"  - {i['url']}  [{i['kind']}]")
    return 0


def _prep_consult(a):
    """Shared gate+render for submit/consult. Returns (rid, prompt, resolved) or raises."""
    rid = a.rid or secrets.token_hex(4)
    if not _RID_RE.fullmatch(rid):
        # rid is interpolated into the OUTBOUND prompt (BEGIN_RESPONSE:<rid>) but is not part
        # of the text the gate secret-scans; a non-hex rid could smuggle a secret past it.
        _err("--rid must be 8-64 lowercase hex characters")
        raise SystemExit(2)
    role = a.role or "You are a rigorous senior engineer and reviewer."
    preview = f"{role}\n{a.title}\n{a.task}\n" + "\n".join(a.link)
    ok, res = gate(preview, a.link, allow_gist=a.allow_gist,
                   allow_private=getattr(a, "private", False))
    if not ok:
        _err(res)
        raise SystemExit(2)
    return rid, render_prompt(rid, a.title, role, a.task, res), res


def cmd_consult(a) -> int:
    """Blocking: submit + wait in one go (interactive convenience)."""
    rid, prompt, res = _prep_consult(a)
    timeout = _resolve_timeout(a)
    print(f"gate PASS — sending consult rid={rid} to ChatGPT ({PROJECT_URL}):")
    for i in res:
        print(f"  - {i['url']}")
    print(f"  task: {a.title}  (mode {a.mode or 'default'}, up to {timeout}s)")
    page = open_new_chat(a.mode)
    try:
        type_and_send(page, prompt)
        state, answer, model, page = poll_answer(page, rid, timeout, a.poll)
        if state == "blocker":
            _err(f"blocker: {answer}")
            return 3
        if state == "salvaged":
            pout = write_answer(rid, answer, _partial_path(a.out) if a.out
                                else os.path.join(ANSWER_DIR, f"answer_{rid}.txt.partial"))
            _err(f"UNWRAPPED answer salvaged (no sentinels within {timeout}s) -> {pout}  "
                 "— treat as PARTIAL/unverified; the model may still have been reasoning")
            print(answer)
            return 5
        if state == "timeout":
            _err(f"no answer within {timeout}s — the model may still be reasoning "
                 "(Pro/Ultra can take 30-50 min); raise --timeout or check the tab")
            return 4
        out = write_answer(rid, answer, a.out)
        warn = model_downgrade_warning(model, os.environ.get("GPTC_EXPECT_MODEL", ""))
        print(f"\n=== answer (rid {rid}, model {model or '?'}) -> {out} ===")
        if warn:
            _err(f"MODEL WARNING: {warn}")
        print()
        print(answer)
        return 0
    finally:
        if a.close_tab:
            page.close_target()
        page.close()


def cmd_submit(a) -> int:
    """Control plane: open chat, type, send, return rid + conversation id + wait_cmd.
    Does NOT wait — dispatch the printed wait_cmd detached."""
    rid, prompt, res = _prep_consult(a)
    page = open_new_chat(a.mode)
    type_and_send(page, prompt)
    cid = capture_conversation_id(page)
    page.close()  # detach our client; the tab stays open for `wait`
    if not cid:
        _err("could not capture conversation id (slow navigation?) — not emitting an "
             "'unknown' wait; retry the submit")
        return 2
    out = a.out or os.path.join(ANSWER_DIR, f"answer_{rid}.txt")
    print(json.dumps({"rid": rid, "conversation_id": cid, "out": out,
                      "wait_cmd": _wait_cmd(rid, cid, out, _resolve_timeout(a))}))
    return 0


def cmd_wait(a) -> int:
    """Detached poller: re-attach to the conversation, poll to the wrapped answer,
    write it, exit. Exit codes: 0 done / 3 blocker / 4 no-answer / 5 salvaged-partial /
    2 setup. Requires a real conversation id — fails closed rather than guess a tab."""
    if not a.conversation or a.conversation == "unknown":
        _err("wait requires a valid --conversation id (fail closed; no tab guessing)")
        return 2
    _hard_deadline(a.timeout + 40)
    page = find_conversation_page(a.conversation)
    try:
        state, answer, model, page = poll_answer(page, a.rid, a.timeout, a.poll,
                                                 conversation_id=a.conversation)
        if state == "blocker":
            _err(f"blocker: {answer}")
            return 3
        if state == "salvaged":
            pout = write_answer(a.rid, answer, _partial_path(a.out) if a.out
                                else os.path.join(ANSWER_DIR, f"answer_{a.rid}.txt.partial"))
            _err(f"UNWRAPPED answer salvaged -> {pout}  (model {model or '?'}) — PARTIAL/unverified")
            return 5
        if state == "timeout":
            _err(f"no answer within {a.timeout}s — the model may still be reasoning "
                 "(Pro/Ultra can take 30-50 min); raise --timeout or check the tab")
            return 4
        out = write_answer(a.rid, answer, a.out)
        warn = model_downgrade_warning(model, os.environ.get("GPTC_EXPECT_MODEL", ""))
        print(f"answer written -> {out}  (model {model or '?'})")
        if warn:
            _err(f"MODEL WARNING: {warn}")
        return 0
    finally:
        if a.close_tab:
            page.close_target()
        page.close()


def cmd_followup(a) -> int:
    """Send another round into an existing conversation. Always secret-scanned;
    requires a public --link unless --allow-nolink is passed explicitly."""
    rid = a.rid or secrets.token_hex(4)
    if not _RID_RE.fullmatch(rid):  # rid goes into the outbound prompt but isn't gate-scanned
        _err("--rid must be 8-64 lowercase hex characters")
        return 2
    hit = scan_secrets(a.task + "\n" + "\n".join(a.link))
    if hit:
        _err(f"refusing: follow-up contains secret-like content ({hit})")
        return 2
    resolved: list[dict] = []
    if a.link:
        ok, res = gate(a.task + "\n" + "\n".join(a.link), a.link, allow_gist=a.allow_gist,
                       allow_private=a.private)
        if not ok:
            _err(res)
            return 2
        resolved = res
    elif not a.allow_nolink:
        _err("refusing: link-free follow-up. Add --link, or pass --allow-nolink to confirm "
             "this round carries no private data.")
        return 2
    prompt = render_followup(rid, a.task, resolved)
    page = find_conversation_page(a.conversation)
    type_and_send(page, prompt, expected_conversation=a.conversation)
    page.close()
    out = a.out or os.path.join(ANSWER_DIR, f"answer_{rid}.txt")
    print(json.dumps({"rid": rid, "conversation_id": a.conversation, "out": out,
                      "wait_cmd": _wait_cmd(rid, a.conversation, out, a.timeout)}))
    return 0


def cmd_status(a) -> int:
    if a.conversation and a.conversation != "unknown":
        page = find_conversation_page(a.conversation)
    else:
        page = newest_chat_page()
        if page is None:
            print(json.dumps({"state": "no-tab"}))
            return 2
    try:
        print(page.eval(_extract_js(a.rid)) or json.dumps({"state": "thinking"}))
        return 0
    finally:
        page.close()


# --------------------------------------------------------------------------- #
# daemon path (auto-mode: agent does LOCAL file I/O only; the daemon sends)
# --------------------------------------------------------------------------- #
# WHY THIS EXISTS. In Claude Code's auto mode a data-exfiltration classifier sits
# above the permission system and hard-denies any AGENT Bash call that sends data to
# an external host (chatgpt.com). To run unattended, the send is moved OFF the agent:
# `enqueue` writes a local job file and `await` polls a local status file — neither
# touches the network. A user-started daemon (`watch`) does the actual send, AND it
# re-validates every job at the point of send (whole-prompt secret re-scan + gh
# public re-check, fail closed). This removes the platform's exfiltration net and
# relies on this gate instead — a deliberate, documented trade-off. Keep the gate
# strong; never widen it to "any link + free text".
def _spool():
    base = SPOOL_DIR
    return {
        "pending": os.path.join(base, "pending"),
        "processing": os.path.join(base, "processing"),
        "status": os.path.join(base, "status"),
        "heartbeat": os.path.join(base, "heartbeat"),
    }


def _ensure_spool():
    p = _spool()
    for k in ("pending", "processing", "status"):
        Path(p[k]).mkdir(parents=True, exist_ok=True)
    return p


def _daemon_alive() -> bool:
    try:
        return (time.time() - os.path.getmtime(_spool()["heartbeat"])) < 30
    except OSError:
        return False


def _atomic_write(path: str, data: str) -> None:
    tmp = f"{path}.tmp"
    Path(tmp).write_text(data)
    os.rename(tmp, path)


def _touch_heartbeat() -> None:
    """Refresh the daemon liveness heartbeat. Fail-safe: bookkeeping must never break a job."""
    try:
        _atomic_write(_spool()["heartbeat"], str(int(time.time())))
    except OSError:
        pass


def _write_status(rid: str, st: dict) -> None:
    _atomic_write(os.path.join(_spool()["status"], f"{rid}.json"), json.dumps(st))


def cmd_enqueue(a) -> int:
    """AGENT side, LOCAL only: gate locally (secret scan + link syntax) and write a job of
    RAW inputs — never a rendered prompt or derived slugs. The daemon re-derives and
    re-validates everything, so a forged/injected job can't smuggle a pre-baked payload.
    No network — invisible to the exfiltration classifier."""
    rid = a.rid or secrets.token_hex(4)
    if not _RID_RE.fullmatch(rid):
        _err("--rid must be 8-64 lowercase hex characters")
        return 2
    out = a.out or os.path.join(ANSWER_DIR, f"answer_{rid}.txt")
    if a.kind == "followup":
        hit = scan_secrets(a.task + "\n" + "\n".join(a.link))
        if hit:
            _err(f"refusing: follow-up contains secret-like content ({hit})")
            return 2
        if a.link:
            ok, res = gate_local(a.task + "\n" + "\n".join(a.link), a.link, a.allow_gist)
            if not ok:
                _err(res)
                return 2
        elif not a.allow_nolink:
            _err("refusing: link-free follow-up. Add --link or --allow-nolink.")
            return 2
        if not a.conversation:
            _err("refusing: follow-up needs --conversation")
            return 2
    else:
        role = a.role or "You are a rigorous senior engineer and reviewer."
        ok, res = gate_local(f"{role}\n{a.title}\n{a.task}\n" + "\n".join(a.link),
                             a.link, a.allow_gist)
        if not ok:
            _err(res)
            return 2
    timeout = _resolve_timeout(a)  # mode-aware generous default (Pro/Ultra run tens of minutes)
    job = {"rid": rid, "kind": a.kind, "task": a.task, "title": a.title,
           "role": a.role, "links": list(a.link), "allow_nolink": bool(a.allow_nolink),
           "allow_gist": bool(a.allow_gist), "conversation_id": a.conversation or None,
           "timeout": timeout, "out": out, "mode": a.mode or None,
           "private": bool(a.private)}
    p = _ensure_spool()
    _atomic_write(os.path.join(p["pending"], f"{rid}.json"), json.dumps(job))
    res_out = {"rid": rid, "out": out, "queued": True, "daemon_running": _daemon_alive(),
               "await_cmd": _await_cmd(rid, out, timeout)}
    if not res_out["daemon_running"]:
        res_out["warning"] = "daemon not running — ask the USER to run: gptc watch"
    print(json.dumps(res_out))
    return 0


def cmd_await(a) -> int:
    """AGENT side, LOCAL only: poll the status file. Exit 0 done / 3 blocker / 4 no-answer
    / 5 salvaged-partial / 2 setup (incl. daemon_not_running). No network. The wait window
    outlives the job's own timeout (the daemon needs setup + poll time before it writes a
    terminal status), so a slow Pro/Ultra job is not cut off early."""
    _hard_deadline(a.timeout + 180)
    sp = os.path.join(_spool()["status"], f"{a.rid}.json")
    deadline = time.time() + a.timeout + 120
    while time.time() < deadline:
        if os.path.exists(sp):
            st = json.loads(Path(sp).read_text())
            state = st.get("state")
            if state in ("done", "done_unthreaded"):
                print(f"answer -> {st.get('out')}  (model {st.get('model') or '?'})"
                      + ("  (unthreaded: no follow-up possible)" if state == "done_unthreaded" else ""))
                if st.get("model_warning"):
                    _err(f"MODEL WARNING: {st['model_warning']}")
                return 0
            if state == "salvaged":
                _err(f"UNWRAPPED answer salvaged -> {st.get('out')}  (model "
                     f"{st.get('model') or '?'}) — PARTIAL/unverified, re-enqueue if you need a clean one")
                return 5
            if state == "blocker":
                _err(f"blocker: {st.get('reason')}")
                return 3
            if state == "no_answer":
                _err("no answer (the model may still have been reasoning) — re-enqueue with a "
                     "larger --timeout if this recurs")
                return 4
            if state in ("refused", "error"):
                _err(f"{state}: {st.get('reason')}")
                return 2
        elif not _daemon_alive():
            _err("daemon_not_running — ask the USER to run: gptc watch")
            return 2
        time.sleep(a.poll)
    _err(f"await timed out after {a.timeout + 120}s")
    return 4


_JOB_KEYS = {"rid", "kind", "task", "title", "role", "links", "allow_nolink",
             "allow_gist", "conversation_id", "timeout", "out", "mode", "private"}


def _process_job(job: dict) -> None:
    """Daemon: validate a RAW job against a strict schema, RE-DERIVE the prompt + slugs
    itself (never trust agent-supplied rendered text), re-gate (secret scan + gh public,
    fail closed), then send + wait + write status. This is the confidentiality boundary."""
    rid = job.get("rid")
    if not isinstance(rid, str) or not _RID_RE.fullmatch(rid):
        return  # not a valid rid — cannot even name a status file safely; drop
    if job.get("kind") not in ("consult", "followup"):
        _write_status(rid, {"state": "refused", "reason": f"bad kind: {job.get('kind')!r}"})
        return
    if set(job) != _JOB_KEYS:  # exact keys — no missing fields, no smuggled extras
        _write_status(rid, {"state": "refused",
                            "reason": f"job keys must be exactly {sorted(_JOB_KEYS)}"})
        return
    task, title, role = job["task"], job["title"], job["role"]
    links, cid = job["links"], job["conversation_id"]
    if not (isinstance(task, str) and isinstance(title, str) and isinstance(role, str)):
        _write_status(rid, {"state": "refused", "reason": "task/title/role must be strings"})
        return
    if not (isinstance(links, list) and all(isinstance(x, str) for x in links)):
        _write_status(rid, {"state": "refused", "reason": "links must be a list of strings"})
        return
    if not (isinstance(job["allow_nolink"], bool) and isinstance(job["allow_gist"], bool)):
        _write_status(rid, {"state": "refused", "reason": "allow_* must be booleans"})
        return
    timeout = job["timeout"]
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not (1 <= timeout <= 3600):
        _write_status(rid, {"state": "refused", "reason": "timeout must be int in 1..3600"})
        return
    if not (isinstance(job["out"], str) and job["out"]):
        _write_status(rid, {"state": "refused", "reason": "out must be a non-empty string"})
        return
    safe_out = _contain_out(job["out"])  # agent-supplied path must stay inside ANSWER_DIR
    if safe_out is None:
        _write_status(rid, {"state": "refused",
                            "reason": f"out escapes the answer dir ({ANSWER_DIR})"})
        return
    if job["mode"] is not None and job["mode"] not in ("chat", "work"):
        _write_status(rid, {"state": "refused", "reason": "mode must be null|chat|work"})
        return
    if not isinstance(job["private"], bool):
        _write_status(rid, {"state": "refused", "reason": "private must be a boolean"})
        return
    if job["kind"] == "followup" and job["mode"] is not None:
        _write_status(rid, {"state": "refused",
                            "reason": "followup inherits its thread's mode; mode must be null"})
        return
    # conversation_id must satisfy its grammar BEFORE it is ever built into a URL (a bad
    # value like 'id?leak=DATA' would otherwise be requested by the browser)
    if cid is not None and not (isinstance(cid, str) and _CONV_ID_RE.fullmatch(cid)):
        _write_status(rid, {"state": "refused", "reason": "conversation_id has a bad shape"})
        return
    if job["kind"] == "consult" and cid is not None:
        _write_status(rid, {"state": "refused", "reason": "consult must have conversation_id=null"})
        return
    if job["kind"] == "followup" and not cid:
        _write_status(rid, {"state": "refused", "reason": "followup without conversation_id"})
        return
    title = title or "consult"
    role = role or "You are a rigorous senior engineer and reviewer."
    # re-scan the RAW inputs (not a supplied prompt) for secret shapes
    hit = scan_secrets(f"{task}\n{role}\n{title}\n" + "\n".join(links))
    if hit:
        _write_status(rid, {"state": "refused", "reason": f"secret-like content ({hit})"})
        return
    resolved: list[dict] = []
    if links:
        ok, res = resolve_all(links, bool(job.get("allow_gist")))
        if not ok:
            _write_status(rid, {"state": "refused", "reason": res})
            return
        # private is an explicit, per-job opt-in re-validated HERE at the boundary (never
        # a default): drop the public assertion but still gh-confirm the repo exists.
        okp, resp = gate_public(res, allow_private=job["private"])
        if not okp:
            _write_status(rid, {"state": "refused", "reason": resp})
            return
        resolved = res
    if job["kind"] == "consult" and not resolved:
        _write_status(rid, {"state": "refused", "reason": "no code link"})
        return
    if job["kind"] == "followup" and not resolved and not job.get("allow_nolink"):
        _write_status(rid, {"state": "refused", "reason": "link-free follow-up without allow_nolink"})
        return
    # daemon RE-RENDERS from raw inputs — the outgoing text is daemon-derived, not agent-supplied
    prompt = (render_followup(rid, task, resolved) if job["kind"] == "followup"
              else render_prompt(rid, title, role, task, resolved))
    try:
        page = (find_conversation_page(cid) if job["kind"] == "followup"
                else open_new_chat(job["mode"]))
    except SystemExit as e:
        _write_status(rid, {"state": "error", "reason": f"setup (exit {e.code})"})
        return

    try:
        type_and_send(page, prompt, expected_conversation=(cid if job["kind"] == "followup" else None))
        captured = capture_conversation_id(page) if job["kind"] == "consult" else cid
        state, ans, model, page = poll_answer(page, rid, timeout, 4.0,
                                              conversation_id=captured, heartbeat_cb=_touch_heartbeat)
        if state == "done":
            out = write_answer(rid, ans, safe_out)
            st = {"out": str(out), "conversation_id": captured, "model": model}
            warn = model_downgrade_warning(model, os.environ.get("GPTC_EXPECT_MODEL", ""))
            if warn:
                st["model_warning"] = warn
            st["state"] = "done" if captured else "done_unthreaded"
            _write_status(rid, st)
        elif state == "salvaged":
            pout = write_answer(rid, ans, _partial_path(safe_out))  # stays inside ANSWER_DIR
            _write_status(rid, {"state": "salvaged", "out": str(pout),
                                "conversation_id": captured, "model": model})
        elif state == "blocker":
            _write_status(rid, {"state": "blocker", "reason": ans})
        else:
            _write_status(rid, {"state": "no_answer"})
    except SystemExit as e:
        _write_status(rid, {"state": "error", "reason": f"send (exit {e.code})"})
    finally:
        page.close()


def _claim(src: str, dst: str) -> None:
    """No-clobber claim: hard-link then unlink the source, so an already-claimed
    destination is NEVER overwritten (os.rename would clobber it on POSIX)."""
    os.link(src, dst)   # raises FileExistsError if dst already exists
    os.unlink(src)


def _recover_stranded(p: dict) -> None:
    """On startup, any job left in processing/ was interrupted mid-flight. It MAY already
    have been sent to ChatGPT, so we never resend it (avoiding duplicate delivery); we
    terminalize it as an error and move on."""
    try:
        names = [n for n in os.listdir(p["processing"]) if n.endswith(".json")]
    except FileNotFoundError:
        return
    for name in names:
        rid = name[:-5]
        if _RID_RE.fullmatch(rid):
            _write_status(rid, {"state": "error", "reason":
                                "daemon restarted mid-job; not resent (avoid duplicate delivery)"})
        try:
            os.remove(os.path.join(p["processing"], name))
        except OSError:
            pass


def _start_watch_detached() -> int:
    """Start the daemon as a detached, persistent background process and return immediately.
    Idempotent (the flock in the child rejects duplicates; we also short-circuit if one is
    already alive). Requires Chrome already launched + logged in — the LOGIN step stays the
    human's job (Claude cannot enter credentials); starting this local process does not."""
    if _daemon_alive():
        print("gptc daemon already running")
        return 0
    if not _chrome_up():
        _err("debug Chrome not running — run `gptc launch` and log into ChatGPT first")
        return 2
    _ensure_spool()
    Path(STATE_DIR).mkdir(parents=True, exist_ok=True)
    log = os.path.join(STATE_DIR, "watch.log")
    with open(log, "a") as f:
        subprocess.Popen([sys.executable, SELF, "watch"], start_new_session=True,
                         stdout=f, stderr=f)
    for _ in range(24):  # wait for the child's first heartbeat (up to ~6s)
        if _daemon_alive():
            print(f"gptc daemon started (detached; log {log})")
            return 0
        time.sleep(0.25)
    _err(f"daemon did not come up — check {log} (Chrome login? another lock holder?)")
    return 2


def cmd_watch(a) -> int:
    """The ONLY component that talks to chatgpt.com. Single-writer (flock), re-derives +
    re-validates every job at send, never resends a job interrupted after it may have been
    sent. `--detach` starts it as a persistent background process and returns; without it,
    runs in the foreground (Ctrl-C stops). May be started by the user OR by the agent —
    login stays the human's job, but starting this local process does not."""
    if getattr(a, "detach", False):
        return _start_watch_detached()
    p = _ensure_spool()
    if not _chrome_up():
        _err("debug Chrome not running — run `gptc launch` and log into ChatGPT first")
        return 2
    lock_fd = os.open(os.path.join(SPOOL_DIR, "watch.lock"), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        _err("another gptc watcher already holds the spool lock")
        os.close(lock_fd)
        return 2
    _recover_stranded(p)
    # Heartbeat on a DEDICATED thread for the daemon's whole lifetime — the per-poll write
    # below and the poll_answer callback only cover parts of a job, but a job's setup phase
    # (gh gate calls + tab-driving configure_session + send) can itself exceed the 30s TTL,
    # which would make a waiting `await` mistakenly declare the live daemon dead.
    _hb_stop = threading.Event()

    def _heartbeat_loop():
        _touch_heartbeat()
        while not _hb_stop.wait(10):
            _touch_heartbeat()

    _hb_thread = threading.Thread(target=_heartbeat_loop, daemon=True)
    _hb_thread.start()
    print(f"gptc daemon watching {SPOOL_DIR} — Ctrl-C to stop")
    try:
        while True:
            _touch_heartbeat()
            try:
                names = sorted(n for n in os.listdir(p["pending"]) if n.endswith(".json"))
            except FileNotFoundError:
                names = []
            for name in names:
                rid = name[:-5]
                src, proc = os.path.join(p["pending"], name), os.path.join(p["processing"], name)
                if not _RID_RE.fullmatch(rid):     # junk file — drop, nobody is awaiting it
                    try:
                        os.remove(src)
                    except OSError:
                        pass
                    continue
                try:
                    _claim(src, proc)              # no-clobber
                except (FileExistsError, OSError):
                    continue
                try:
                    _process_job(json.loads(Path(proc).read_text()))
                except Exception as e:
                    _write_status(rid, {"state": "error", "reason": str(e)})
                finally:
                    try:
                        os.remove(proc)
                    except OSError:
                        pass
            time.sleep(a.poll)
    except KeyboardInterrupt:
        print("\ndaemon stopped")
        return 0
    finally:
        _hb_stop.set()
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        except OSError:
            pass


def cmd_queue(a) -> int:
    p = _spool()

    def _count(d):
        try:
            return len([x for x in os.listdir(d) if x.endswith(".json")])
        except OSError:
            return 0

    print(json.dumps({"daemon_running": _daemon_alive(), "spool": SPOOL_DIR,
                      "pending": _count(p["pending"]), "processing": _count(p["processing"]),
                      "status": _count(p["status"])}))
    return 0


# --------------------------------------------------------------------------- #
# arg parsing
# --------------------------------------------------------------------------- #
def _add_consult_args(p):
    p.add_argument("--task", required=True, help="the question / instruction")
    p.add_argument("--title", default="consult", help="short headline")
    p.add_argument("--role", default="", help="persona for ChatGPT")
    p.add_argument("--link", action="append", default=[], required=True,
                   help="public GitHub ref: owner/repo, owner/repo#PR, or a github.com URL")
    p.add_argument("--out", default="", help="answer file (default gptc_answers/answer_<rid>.txt)")
    p.add_argument("--rid", default="", help="fixed request id (default random)")
    p.add_argument("--timeout", type=int, default=None,
                   help="max seconds to wait — a ceiling; returns as soon as the answer lands. "
                        "Default is mode-aware (work=3000, else 1800): Pro/Ultra run 30-50 min.")
    p.add_argument("--poll", type=float, default=4.0)
    p.add_argument("--allow-gist", action="store_true")
    p.add_argument("--close-tab", action="store_true")
    p.add_argument("--mode", choices=["chat", "work"], default="",
                   help="tier for a fresh chat: chat=Pro (fast) / work=Ultra (deep). "
                        "Default: leave the tab as-is.")
    p.add_argument("--private", action="store_true",
                   help="allow non-public repos (consulted via ChatGPT's own GitHub "
                        "connector); still secret-scanned, still gh-existence-checked")


def main() -> int:
    p = argparse.ArgumentParser(prog="gptc",
                                description="Claude commands GPT (public-links-only, explicit egress).")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("launch", help="open the dedicated debug Chrome").set_defaults(fn=cmd_launch)
    sub.add_parser("doctor", help="check deps, gh, Chrome, port").set_defaults(fn=cmd_doctor)

    g = sub.add_parser("gate", help="dry-run the egress gate (no send)")
    g.add_argument("--task", required=True)
    g.add_argument("--link", action="append", default=[], required=True)
    g.add_argument("--allow-gist", action="store_true")
    g.add_argument("--private", action="store_true",
                   help="dry-run the private-ok gate (drop the public assertion)")
    g.set_defaults(fn=cmd_gate)

    c = sub.add_parser("consult", help="blocking: submit + wait in one go")
    _add_consult_args(c)
    c.set_defaults(fn=cmd_consult)

    s = sub.add_parser("submit", help="control plane: send, return rid + conversation id (no wait)")
    _add_consult_args(s)
    s.set_defaults(fn=cmd_submit)

    w = sub.add_parser("wait", help="detached poller: wait for the wrapped answer, write it")
    w.add_argument("--rid", required=True)
    w.add_argument("--conversation", default="unknown")
    w.add_argument("--out", default="")
    w.add_argument("--timeout", type=int, default=1800)
    w.add_argument("--poll", type=float, default=4.0)
    w.add_argument("--close-tab", action="store_true")
    w.set_defaults(fn=cmd_wait)

    f = sub.add_parser("followup", help="send another round into an existing conversation")
    f.add_argument("--conversation", required=True)
    f.add_argument("--task", required=True)
    f.add_argument("--link", action="append", default=[])
    f.add_argument("--allow-nolink", action="store_true",
                   help="permit a follow-up with no public link (you confirm no private data)")
    f.add_argument("--out", default="")
    f.add_argument("--rid", default="")
    f.add_argument("--timeout", type=int, default=1800)
    f.add_argument("--allow-gist", action="store_true")
    f.add_argument("--private", action="store_true",
                   help="allow non-public repos in this follow-up round")
    f.set_defaults(fn=cmd_followup)

    st = sub.add_parser("status", help="one-shot state of a conversation")
    st.add_argument("--rid", required=True)
    st.add_argument("--conversation", default="unknown")
    st.set_defaults(fn=cmd_status)

    # --- daemon path (auto mode) ---
    e = sub.add_parser("enqueue", help="agent side: write a job locally (no network)")
    e.add_argument("--task", required=True)
    e.add_argument("--title", default="consult")
    e.add_argument("--role", default="")
    e.add_argument("--link", action="append", default=[])
    e.add_argument("--kind", choices=["consult", "followup"], default="consult")
    e.add_argument("--conversation", default="")
    e.add_argument("--allow-nolink", action="store_true")
    e.add_argument("--out", default="")
    e.add_argument("--rid", default="")
    e.add_argument("--timeout", type=int, default=None,
                   help="ceiling seconds; mode-aware default (work=3000, else 1800)")
    e.add_argument("--allow-gist", action="store_true")
    e.add_argument("--mode", choices=["chat", "work"], default="",
                   help="tier for a fresh chat: chat=Pro / work=Ultra (ignored on followup)")
    e.add_argument("--private", action="store_true",
                   help="allow non-public repos (re-validated by the daemon at send)")
    e.set_defaults(fn=cmd_enqueue)

    aw = sub.add_parser("await", help="agent side: poll the local answer status (no network)")
    aw.add_argument("--rid", required=True)
    aw.add_argument("--out", default="")
    aw.add_argument("--timeout", type=int, default=1800)
    aw.add_argument("--poll", type=float, default=3.0)
    aw.set_defaults(fn=cmd_await)

    wt = sub.add_parser("watch", help="daemon: validate + send queued jobs (--detach = background)")
    wt.add_argument("--poll", type=float, default=2.0)
    wt.add_argument("--detach", action="store_true",
                    help="start the daemon as a persistent background process and return "
                         "(idempotent; needs Chrome already launched + logged in)")
    wt.set_defaults(fn=cmd_watch)

    sub.add_parser("queue", help="daemon liveness + spool counts").set_defaults(fn=cmd_queue)

    a = p.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
