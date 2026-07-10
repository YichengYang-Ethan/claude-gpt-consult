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
  * PUBLIC-CODE-ONLY egress. Every consult carries >=1 public GitHub link,
    gh-confirmed public. The whole rendered prompt is scanned for secret shapes and
    fails closed. A link-free follow-up requires an explicit --allow-nolink flag
    (user-controlled), not a spoofable in-prompt substring.
  * EXPLICIT, VISIBLE egress. The send happens only inside a command you run. This
    project does NOT ship a daemon whose purpose is to move the send off the agent
    so a host's data-exfiltration classifier can't see it.
  * Ordinary automation of your OWN logged-in session. The tool never handles your
    password; you log into a dedicated Chrome profile once, by hand.

Note: automating the ChatGPT *web* app is against OpenAI's Terms of Use (which allow
programmatic extraction only via the API). Use your own account, at human cadence,
and accept the account-level risk. This tool does not bypass login/CAPTCHA/limits.
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

_GH_URL = re.compile(r"github\.com/([^/\s]+)/([^/\s#?]+)")
_RAW_URL = re.compile(r"raw\.githubusercontent\.com/([^/\s]+)/([^/\s]+)")


def scan_secrets(text: str) -> str | None:
    for name, rx in SECRET_RES:
        if rx.search(text):
            return name
    return None


def resolve_link(link: str, allow_gist: bool = False):
    link = link.strip()
    if "gist.github.com" in link:
        if not allow_gist:
            return False, f"gist links are refused (visibility not cheaply provable): {link}"
        return True, {"slug": None, "url": link, "kind": "gist"}
    m = re.fullmatch(r"([\w.\-]+/[\w.\-]+)#(\d+)", link)
    if m:
        slug, pr = m.group(1), m.group(2)
        return True, {"slug": slug, "url": f"https://github.com/{slug}/pull/{pr}", "kind": "pr"}
    if re.fullmatch(r"[\w.\-]+/[\w.\-]+", link):
        return True, {"slug": link, "url": f"https://github.com/{link}", "kind": "repo"}
    if link.startswith("http"):
        m = _GH_URL.search(link) or _RAW_URL.search(link)
        if m:
            slug = f"{m.group(1)}/{m.group(2)}".removesuffix(".git")
            return True, {"slug": slug, "url": link, "kind": "url"}
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
            continue
        if not _repo_is_public(info["slug"]):
            return False, f"refusing: repo not gh-confirmed public: {info['slug']}"
    return True, resolved


# --------------------------------------------------------------------------- #
# sentinel parse (canonical Python copy; a JS mirror runs in the page)
# --------------------------------------------------------------------------- #
def sentinel_parse(text: str, rid: str) -> str | None:
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
# page orchestration helpers
# --------------------------------------------------------------------------- #
_CONV_RE = re.compile(r"/c/([0-9a-fA-F][0-9a-fA-F\-]{15,})")


def conv_id_from_url(url: str | None) -> str | None:
    m = _CONV_RE.search(url or "")
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


def open_new_chat() -> Page:
    _die_if_no_chrome()
    page = open_tab(PROJECT_URL)
    st = _wait_composer(page)
    if st == "login":
        _err("login wall — log into ChatGPT in the debug Chrome window, then retry")
        raise SystemExit(3)
    if not st:
        _err("composer never appeared (login? UI drift?)")
        raise SystemExit(3)
    return page


def find_conversation_page(conv_id: str) -> Page:
    _die_if_no_chrome()
    for t in _http_json("/json"):
        if (t.get("type") == "page" and conv_id in (t.get("url") or "")
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
    return page


def newest_chat_page() -> Page | None:
    _die_if_no_chrome()
    pages = [t for t in _http_json("/json")
             if t.get("type") == "page" and "/c/" in (t.get("url") or "")
             and t.get("webSocketDebuggerUrl")]
    if not pages:
        return None
    return Page(pages[0]["webSocketDebuggerUrl"], target_id=pages[0].get("id"))


def type_and_send(page: Page, prompt: str) -> None:
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


def poll_answer(page: Page, rid: str, timeout: int, poll: float):
    """Returns (state, answer_or_reason). state in {done, blocker, timeout}."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(poll)
        raw = page.eval(_extract_js(rid))
        st = json.loads(raw) if raw else {"state": "thinking"}
        if st["state"] == "done":
            return "done", st["text"]
        if st["state"] == "blocker":
            return "blocker", st.get("reason")
    return "timeout", None


def write_answer(rid: str, answer: str, out: str | None) -> Path:
    p = Path(out or os.path.join(ANSWER_DIR, f"answer_{rid}.txt"))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(answer)
    return p


def _wait_cmd(rid: str, conv: str | None, out: str, timeout: int) -> str:
    return (f"timeout {timeout + 40} python3 {SELF} wait "
            f"--rid {rid} --conversation {conv or 'unknown'} --out {out} --timeout {timeout}")


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


def _prep_consult(a):
    """Shared gate+render for submit/consult. Returns (rid, prompt, resolved) or raises."""
    rid = a.rid or secrets.token_hex(4)
    role = a.role or "You are a rigorous senior engineer and reviewer."
    preview = f"{role}\n{a.title}\n{a.task}\n" + "\n".join(a.link)
    ok, res = gate(preview, a.link, allow_gist=a.allow_gist)
    if not ok:
        _err(res)
        raise SystemExit(2)
    return rid, render_prompt(rid, a.title, role, a.task, res), res


def cmd_consult(a) -> int:
    """Blocking: submit + wait in one go (interactive convenience)."""
    rid, prompt, res = _prep_consult(a)
    print(f"gate PASS — sending consult rid={rid} to ChatGPT ({PROJECT_URL}):")
    for i in res:
        print(f"  - {i['url']}")
    print("  task:", a.title)
    page = open_new_chat()
    try:
        type_and_send(page, prompt)
        state, answer = poll_answer(page, rid, a.timeout, a.poll)
        if state == "blocker":
            _err(f"blocker: {answer}")
            return 3
        if state == "timeout":
            _err(f"no wrapped answer within {a.timeout}s")
            return 4
        out = write_answer(rid, answer, a.out)
        print(f"\n=== answer (rid {rid}) -> {out} ===\n")
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
    page = open_new_chat()
    type_and_send(page, prompt)
    cid = capture_conversation_id(page)
    page.close()  # detach our client; the tab stays open for `wait`
    out = a.out or os.path.join(ANSWER_DIR, f"answer_{rid}.txt")
    print(json.dumps({"rid": rid, "conversation_id": cid, "out": out,
                      "wait_cmd": _wait_cmd(rid, cid, out, a.timeout)}))
    return 0


def cmd_wait(a) -> int:
    """Detached poller: re-attach to the conversation, poll to the wrapped answer,
    write it, exit. Exit codes: 0 done / 3 blocker / 4 no-answer / 2 setup."""
    if a.conversation and a.conversation != "unknown":
        page = find_conversation_page(a.conversation)
    else:
        page = newest_chat_page()
        if page is None:
            _err("no ChatGPT conversation tab found to wait on")
            return 2
    try:
        state, answer = poll_answer(page, a.rid, a.timeout, a.poll)
        if state == "blocker":
            _err(f"blocker: {answer}")
            return 3
        if state == "timeout":
            _err(f"no wrapped answer within {a.timeout}s")
            return 4
        out = write_answer(a.rid, answer, a.out)
        print(f"answer written -> {out}")
        return 0
    finally:
        if a.close_tab:
            page.close_target()
        page.close()


def cmd_followup(a) -> int:
    """Send another round into an existing conversation. Always secret-scanned;
    requires a public --link unless --allow-nolink is passed explicitly."""
    rid = a.rid or secrets.token_hex(4)
    hit = scan_secrets(a.task + "\n" + "\n".join(a.link))
    if hit:
        _err(f"refusing: follow-up contains secret-like content ({hit})")
        return 2
    resolved: list[dict] = []
    if a.link:
        ok, res = gate(a.task + "\n" + "\n".join(a.link), a.link, allow_gist=a.allow_gist)
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
    type_and_send(page, prompt)
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
    p.add_argument("--timeout", type=int, default=900)
    p.add_argument("--poll", type=float, default=4.0)
    p.add_argument("--allow-gist", action="store_true")
    p.add_argument("--close-tab", action="store_true")


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
    w.add_argument("--timeout", type=int, default=900)
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
    f.add_argument("--timeout", type=int, default=900)
    f.add_argument("--allow-gist", action="store_true")
    f.set_defaults(fn=cmd_followup)

    st = sub.add_parser("status", help="one-shot state of a conversation")
    st.add_argument("--rid", required=True)
    st.add_argument("--conversation", default="unknown")
    st.set_defaults(fn=cmd_status)

    a = p.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
