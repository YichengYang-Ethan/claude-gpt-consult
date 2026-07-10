#!/usr/bin/env python3
"""
gptc — Claude commands GPT.

A tiny bridge that lets a local agent (Claude Code) hand a self-contained job to a
logged-in ChatGPT tab, get the wrapped answer back, and act on it — using the two
*subscriptions* you already pay for, no API key and no per-token bill.

Design stance (differs from prior art on purpose):
  * PUBLIC-CODE-ONLY egress. Every consult must reference >=1 public GitHub link,
    gh-confirmed public. The whole rendered prompt is scanned for secret shapes and
    fails closed on a hit. There is no spoofable "follow-up" exemption.
  * EXPLICIT, VISIBLE egress. The network send happens only inside a user-invoked
    `consult`, which prints exactly what it is about to send. We do NOT ship a
    daemon whose purpose is to move the send off the agent so a safety classifier
    can't see it. If you run inside a locked-down agent mode that blocks the send,
    approve it or run `gptc consult` yourself.
  * Ordinary automation of your OWN logged-in session. The tool never handles your
    password; you log into a dedicated Chrome profile once, by hand. It reads only
    the answer text, writes it to a local file you own.

Note: automating the ChatGPT *web* app is against OpenAI's Terms of Use (which allow
programmatic extraction only via the API). Use your own account, at human cadence,
and accept the account-level risk. This tool does not bypass login/CAPTCHA/limits.

Subcommands:
  launch    open the dedicated debug Chrome; log into ChatGPT there once
  doctor    check deps, gh auth, Chrome, port, login
  gate      dry-run the egress gate on a prompt/links (no send)
  consult   gate -> open a fresh chat -> type -> send -> wait -> write answer
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
import secrets
from pathlib import Path

# --------------------------------------------------------------------------- #
# config (all overridable via env; nothing here is a secret)
# --------------------------------------------------------------------------- #
PORT = int(os.environ.get("GPTC_PORT", "9333"))
PROFILE = os.environ.get("GPTC_PROFILE", str(Path.home() / ".gptc-chrome"))
CHROME = os.environ.get("GPTC_CHROME", "")
PROJECT_URL = os.environ.get("GPTC_PROJECT_URL", "https://chatgpt.com/")
STATE_DIR = os.environ.get("GPTC_STATE_DIR", "/tmp/gptc")
ANSWER_DIR = os.environ.get("GPTC_ANSWER_DIR", str(Path.cwd() / "gptc_answers"))
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


def _err(msg: str) -> None:
    print(f"gptc: {msg}", file=sys.stderr)


# --------------------------------------------------------------------------- #
# egress gate  (the security heart — deliberately stricter than prior art)
# --------------------------------------------------------------------------- #
# Secret-SHAPE detectors. Not a promise of completeness — the primary control is
# "public links only + you review what you send". But this catches the common
# credential shapes the field forgets (Anthropic sk-ant-, Stripe sk_live_, and
# any user:pass@host connection string), which a naive `sk-[A-Za-z0-9]{20}`
# regex silently misses.
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
    # user:pass@host — catches postgres://, mongodb://, redis://, https://u:p@...
    ("conn-string-cred", re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:@/]+:[^\s:@/]+@[^\s/]+")),
    # generic assignment: password= / api_key: "..." / bearer <token>
    ("assigned-secret", re.compile(
        r"(?i)\b(?:pass(?:wd|word)?|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token|bearer)\b"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9._\-/+]{8,}")),
]

_GH_URL = re.compile(r"github\.com/([^/\s]+)/([^/\s#?]+)")
_RAW_URL = re.compile(r"raw\.githubusercontent\.com/([^/\s]+)/([^/\s]+)")


def scan_secrets(text: str) -> str | None:
    """Return the name of the first secret shape found, or None if clean."""
    for name, rx in SECRET_RES:
        if rx.search(text):
            return name
    return None


def resolve_link(link: str, allow_gist: bool = False):
    """Normalize a code reference into {slug, url, kind}. Returns (True, info) or
    (False, error). Only GitHub references are accepted (we can prove them public)."""
    link = link.strip()
    if "gist.github.com" in link:
        if not allow_gist:
            return False, f"gist links are refused (visibility not cheaply provable): {link}"
        return True, {"slug": None, "url": link, "kind": "gist"}
    # owner/repo#123  -> PR
    m = re.fullmatch(r"([\w.\-]+/[\w.\-]+)#(\d+)", link)
    if m:
        slug, pr = m.group(1), m.group(2)
        return True, {"slug": slug, "url": f"https://github.com/{slug}/pull/{pr}", "kind": "pr"}
    # bare owner/repo -> whole repo
    if re.fullmatch(r"[\w.\-]+/[\w.\-]+", link):
        return True, {"slug": link, "url": f"https://github.com/{link}", "kind": "repo"}
    # full URL
    if link.startswith("http"):
        m = _GH_URL.search(link) or _RAW_URL.search(link)
        if m:
            slug = f"{m.group(1)}/{m.group(2)}".removesuffix(".git")
            return True, {"slug": slug, "url": link, "kind": "url"}
        return False, f"not a GitHub link (only public GitHub is allowed): {link}"
    return False, f"unrecognized code reference: {link}"


def _repo_is_public(slug: str) -> bool:
    """gh-confirm the repo is public. Fails CLOSED on any error (no gh, no auth,
    private, 404) -> treated as not-public."""
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{slug}", "--jq", ".visibility"],
            capture_output=True, text=True, timeout=20,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0 and r.stdout.strip() == "public"


def gate(prompt_text: str, links: list[str], allow_gist: bool = False):
    """The egress gate. Returns (True, resolved_list) or (False, reason)."""
    hit = scan_secrets(prompt_text)
    if hit:
        return False, f"refusing: prompt contains secret-like content ({hit})"
    resolved = []
    for l in links:
        ok, info = resolve_link(l, allow_gist)
        if not ok:
            return False, info
        resolved.append(info)
    if not resolved:
        return False, "refusing: no public code link provided (send >=1 public GitHub link)"
    for info in resolved:
        if info["slug"] is None:
            continue  # gist explicitly allowed above
        if not _repo_is_public(info["slug"]):
            return False, f"refusing: repo not gh-confirmed public: {info['slug']}"
    return True, resolved


# --------------------------------------------------------------------------- #
# sentinel parse (canonical Python copy; a JS mirror runs in the page)
# --------------------------------------------------------------------------- #
def sentinel_parse(text: str, rid: str) -> str | None:
    """Extract the answer between bare-line BEGIN_RESPONSE:<rid> / END_RESPONSE:<rid>.
    Fence-aware: sentinels inside a ``` code fence do not trigger. Returns the answer
    body, or None if a complete wrapped answer is not present."""
    begin, end = f"BEGIN_RESPONSE:{rid}", f"END_RESPONSE:{rid}"
    in_fence = started = done = False
    buf: list[str] = []
    for line in text.split("\n"):
        t = line.strip()
        if t.startswith("```"):
            in_fence = not in_fence
            if started:
                buf.append(line)
            continue
        if not started:
            if not in_fence and t == begin:
                started = True
            continue
        if not in_fence and t == end:
            done = True
            break
        buf.append(line)
    if started and done:
        return "\n".join(buf).strip()
    return None


def render_prompt(rid: str, title: str, role: str, task: str, resolved: list[dict]) -> str:
    refs = "\n".join(f"- {i['url']}" for i in resolved)
    return f"""{role}

TASK: {title}

{task}

CODE — open and read these public GitHub links before answering:
{refs}

--- OUTPUT CONTRACT (read carefully) ---
Take as long as you need to reason. When your FINAL answer is ready, print it wrapped
EXACTLY like this — each sentinel alone on its own line, nothing else on that line,
and NOT inside a code fence:

BEGIN_RESPONSE:{rid}
<your complete final answer here>
END_RESPONSE:{rid}

Emit the BEGIN line exactly once, at the start of the final answer. End the load-bearing
claims a local agent should re-check with a short `verify locally:` note."""


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

    def __init__(self, ws_url: str):
        try:
            import websocket  # type: ignore
        except ImportError:
            raise SystemExit("gptc: missing dep — run: pip install websocket-client")
        self.ws = websocket.create_connection(ws_url, origin=ORIGIN, timeout=30)
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
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True,
        })
        if "exceptionDetails" in r:
            raise RuntimeError(r["exceptionDetails"].get("text", "js error"))
        return r.get("result", {}).get("value")

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass


def open_tab(url: str) -> Page:
    """Create a fresh tab at `url` over the browser endpoint, then attach to it."""
    ver = _http_json("/json/version")
    browser_ws = ver["webSocketDebuggerUrl"]
    import websocket  # type: ignore
    bws = websocket.create_connection(browser_ws, origin=ORIGIN, timeout=30)
    try:
        bws.send(json.dumps({"id": 1, "method": "Target.createTarget", "params": {"url": url}}))
        target_id = None
        while target_id is None:
            m = json.loads(bws.recv())
            if m.get("id") == 1:
                target_id = m["result"]["targetId"]
    finally:
        bws.close()
    # find the page ws for this target
    for _ in range(40):
        for t in _http_json("/json"):
            if t.get("id") == target_id and t.get("webSocketDebuggerUrl"):
                return Page(t["webSocketDebuggerUrl"])
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
    # returns a JSON string: {state, text?, len}
    return """(function(rid){
      var nodes=document.querySelectorAll('[data-message-author-role="assistant"]');
      var body=(document.body.innerText||'');
      if(/you've reached|rate limit|too many requests/i.test(body))
        return JSON.stringify({state:'blocker',reason:'rate-limit'});
      if(!nodes.length) return JSON.stringify({state:'waiting',len:0});
      var el=nodes[nodes.length-1]; var text=el.textContent||'';
      var begin='BEGIN_RESPONSE:'+rid, end='END_RESPONSE:'+rid;
      var lines=text.split('\\n'); var inF=false,started=false,done=false,buf=[];
      for(var i=0;i<lines.length;i++){var ln=lines[i],t=ln.trim();
        if(t.indexOf('```')===0){inF=!inF; if(started)buf.push(ln); continue;}
        if(!started){ if(!inF&&t===begin)started=true; continue; }
        if(!inF&&t===end){done=true;break;}
        buf.push(ln);}
      if(started&&done) return JSON.stringify({state:'done',text:buf.join('\\n').trim()});
      return JSON.stringify({state:started?'generating':'thinking',len:text.length});
    })(""" + json.dumps(rid) + ")"


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
    # python dep
    try:
        import websocket  # noqa: F401
        print("ok   python dep: websocket-client")
    except ImportError:
        ok = False
        print("FAIL python dep: websocket-client  (pip install websocket-client)")
    # gh
    g = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True)
    if g.returncode == 0:
        print("ok   gh CLI authenticated (egress gate can verify public repos)")
    else:
        ok = False
        print("FAIL gh not authenticated  (run: gh auth login) — the gate fails closed without it")
    # chrome + port
    if _chrome_up():
        print(f"ok   debug Chrome reachable on 127.0.0.1:{PORT}")
        try:
            p = open_tab("about:blank")
            p.close()
            print("ok   CDP loopback attach works")
        except Exception as e:
            ok = False
            print(f"FAIL CDP attach: {e}")
    else:
        ok = False
        print(f"FAIL debug Chrome not running on {PORT}  (run: gptc launch)")
    print("note verify login by looking at the Chrome window (doctor can't read your session)")
    return 0 if ok else 2


def cmd_gate(a) -> int:
    prompt = a.task + "\n" + "\n".join(a.link)
    ok, res = gate(prompt, a.link, allow_gist=a.allow_gist)
    if not ok:
        _err(res)
        return 2
    print("gate PASS — would send. Public refs:")
    for i in res:
        print(f"  - {i['url']}  [{i['kind']}]")
    return 0


def cmd_consult(a) -> int:
    rid = a.rid or secrets.token_hex(4)
    resolved_prompt_links = a.link
    role = a.role or "You are a rigorous senior engineer and reviewer."
    # gate on the FULL rendered prompt (task + role + links), not just the task
    prompt_preview = f"{role}\n{a.title}\n{a.task}\n" + "\n".join(a.link)
    ok, res = gate(prompt_preview, a.link, allow_gist=a.allow_gist)
    if not ok:
        _err(res)
        return 2
    prompt = render_prompt(rid, a.title, role, a.task, res)

    print(f"gate PASS — sending consult rid={rid} to ChatGPT ({PROJECT_URL}):")
    for i in res:
        print(f"  - {i['url']}")
    print("  task:", a.title)

    if not _chrome_up():
        _err(f"debug Chrome not running on {PORT}. Run: gptc launch  (then log into ChatGPT)")
        return 2

    page = open_tab(PROJECT_URL)
    try:
        # wait for composer / detect login wall
        for _ in range(120):
            if page.eval(_COMPOSER_JS):
                break
            if page.eval(_LOGIN_MARKER_JS):
                _err("login wall — log into ChatGPT in the debug Chrome window, then retry")
                return 3
            time.sleep(0.5)
        else:
            _err("composer never appeared (login? UI drift?)")
            return 3

        if page.eval(_type_js(prompt)) != "typed":
            _err("could not type into the composer (selector drift?)")
            return 2
        time.sleep(0.4)
        send = page.eval(_SEND_JS)
        if send != "sent":
            _err(f"could not click send ({send}) — ChatGPT UI may have changed")
            return 2

        deadline = time.time() + a.timeout
        answer = None
        while time.time() < deadline:
            time.sleep(a.poll)
            raw = page.eval(_extract_js(rid))
            st = json.loads(raw) if raw else {"state": "thinking"}
            if st["state"] == "done":
                answer = st["text"]
                break
            if st["state"] == "blocker":
                _err(f"blocker: {st.get('reason')}")
                return 3
        if answer is None:
            _err(f"no wrapped answer within {a.timeout}s")
            return 4

        out = Path(a.out or os.path.join(ANSWER_DIR, f"answer_{rid}.txt"))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(answer)
        print(f"\n=== answer (rid {rid}) -> {out} ===\n")
        print(answer)
        return 0
    finally:
        if a.close_tab:
            page.close()


def main() -> int:
    p = argparse.ArgumentParser(prog="gptc", description="Claude commands GPT (public-links-only, explicit egress).")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("launch", help="open the dedicated debug Chrome").set_defaults(fn=cmd_launch)
    sub.add_parser("doctor", help="check deps, gh, Chrome, port").set_defaults(fn=cmd_doctor)

    g = sub.add_parser("gate", help="dry-run the egress gate (no send)")
    g.add_argument("--task", required=True)
    g.add_argument("--link", action="append", default=[], required=True)
    g.add_argument("--allow-gist", action="store_true")
    g.set_defaults(fn=cmd_gate)

    c = sub.add_parser("consult", help="gate -> open chat -> type -> send -> wait -> write")
    c.add_argument("--task", required=True, help="the question / instruction")
    c.add_argument("--title", default="consult", help="short headline")
    c.add_argument("--role", default="", help="persona for ChatGPT")
    c.add_argument("--link", action="append", default=[], required=True,
                   help="public GitHub ref: owner/repo, owner/repo#PR, or a github.com URL (repeatable)")
    c.add_argument("--out", default="", help="answer file (default gptc_answers/answer_<rid>.txt)")
    c.add_argument("--rid", default="", help="fixed request id (default random)")
    c.add_argument("--timeout", type=int, default=900)
    c.add_argument("--poll", type=float, default=4.0)
    c.add_argument("--allow-gist", action="store_true")
    c.add_argument("--close-tab", action="store_true", help="close the ChatGPT tab when done")
    c.set_defaults(fn=cmd_consult)

    a = p.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
