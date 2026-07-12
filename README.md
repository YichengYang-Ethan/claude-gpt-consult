# gptc — Claude commands GPT

> A **Claude Code skill + CLI** that turns a logged-in **ChatGPT** tab into a background
> coprocessor for your local agent. Claude fires off a self-contained job — a plan, a hard
> reasoning problem, a code review — keeps working locally, and a **detached waiter wakes it**
> when the full answer lands, ready to verify. It drives the **web app you're already logged
> into** — not the API — so there's **no key and no per-token bill**.

Claude drives locally; a dedicated Chrome tab logged into ChatGPT does the background
reasoning. A consult is a **thread, not a one-shot**: feed local results back and follow up
in the same conversation until the answer is clean. A small, honest reimplementation of
[`open-claude-gpt`](https://github.com/fitz-s/open-claude-gpt), then hardened over a
multi-round GPT-vs-itself security review (see the commit history).

## What it does (capabilities)

- **Background reasoning on the subscription you already pay for** — no API key, no token
  bill. ChatGPT **advises**; your local agent **verifies and executes**.
- **Full workflow, both attended and unattended:**
  - *Interactive:* `consult` (blocking) or `submit → detached wait → wake → followup`.
  - *Auto mode:* `enqueue → watch (daemon) → await`. The agent only touches local files;
    a user-started daemon does the send, so it works under Claude Code's auto-mode
    data-exfiltration classifier.
- **Public-GitHub-only egress by default, enforced by construction.** Every consult carries
  ≥1 GitHub link, `gh`-confirmed public **and confirmed to exist** (fake `/commit/<sha>` or
  `/pull/<n>` covert channels are refused). The whole prompt is secret-scanned and **fails
  closed** — catching shapes the field forgets (`sk-ant-`, `sk_live_`, `user:pass@host`).
  `--private` is a per-job opt-in that drops *only* the public assertion (see boundaries).
- **The daemon is the confidentiality boundary.** It takes only **raw inputs** (never an
  agent-supplied rendered prompt), enforces a strict job schema + token grammars, and
  **re-derives + re-validates** every job at the point of send (secret re-scan, gh public +
  object-existence re-check), fail closed. Single-writer (`flock`); never resends a job
  interrupted after a possible send.
- **Reliable multi-round threads.** Completion is **request-correlated** (reads the answer
  node carrying *this* request's `BEGIN_RESPONSE:<rid>`, not the global last node), accepted
  only once generation has stopped and the text is stable (no post-`END` truncation), with
  a delimiter-aware fence parser. Conversation identity is host/path-exact and re-verified
  immediately before every send (no cross-thread sends).
- **Tier selection, verified.** `--mode chat` pins Sol *Pro* (fast); `--mode work` pins Sol
  *Ultra*, the strongest effort tier (deep) — reached via the Advanced → Effort submenu, since
  the simple power slider caps a rung below Ultra. The tool actuates the Chat/Work toggle +
  model picker, **reads back what actually took, and fails closed** if it can't reach the
  requested tier — it never silently answers on a weaker one. Which tier a task needs is the
  caller's call, not a hardcoded heuristic.
- **Model transparency.** Reads which model actually answered (`data-message-model-slug`);
  set `GPTC_EXPECT_MODEL=<substr>` to get warned on a silent Plus-tier downgrade.
- **Private repos are an explicit opt-in.** By default egress is public-GitHub-only. Pass
  `--private` (per job) to consult on code you OWN via ChatGPT's own GitHub connector — the
  prompt is still secret-scanned and the repo still gh-existence-checked, but the connector's
  fetched CONTENT is outside the gate. See the boundary note below before using it.

## Where the line is (boundaries — read before trusting it)

- **Against OpenAI's Terms of Use.** Automating the ChatGPT *web app* is prohibited (the API
  is the only sanctioned programmatic path). It does **not** bypass login/CAPTCHA/limits, but
  the automated extraction itself is the restricted part. Risk is *low-probability,
  high-consequence*: a flagged account can be lost. **Use a secondary account, at human
  cadence — not your primary.** You accept that by using this.
- **A trusted-user convenience tool, not a prompt-injection-proof boundary.** The `--task`
  text is inherently outbound, and regex can't catch obfuscated data (base64/hex/source) a
  *prompt-injected* agent might place there. In auto mode there's no human to approve the
  send, so this residual is **accepted by design**. Point it only at work you'd be comfortable
  disclosing; don't treat the gate as a safe against a hijacked agent.
- **`--private` is a deliberate posture change — understand it.** With `--private`, egress is
  no longer public-only: ChatGPT's GitHub connector can read repos your account can see,
  through a channel the prompt-text gate never inspects (the secret scan and gh-existence
  check still run; the fetched file *content* does not pass through gptc at all). This is an
  explicit per-job opt-in, off by default, and it is honored on **both** paths — including the
  unattended daemon. That means in auto mode a prompt-injected agent could enqueue a private
  job with no human at the send; the owner accepts this by passing `--private`. Use it only
  for code that is yours to disclose to OpenAI.
- **Same-OS-user limit.** Pure-stdlib spool state can't be made tamper-proof against another
  process running as *you*. Strong isolation would need the daemon under a separate account.
- **The live CDP path can break when OpenAI ships UI changes** (selectors have no stability
  contract) — it fails **closed/loud**, not silently. Not unit-testable in-repo; the gate,
  parser, plumbing, and model logic are (`pytest`).
- **Not yet done (non-blocking):** durable `send_intent` state machine (current recovery is
  conservative — never resends), unwrapped-answer salvage on timeout. Tier *selection* is now
  done (`--mode`, verified + fail-closed); the picker actuation is the most UI-fragile part
  and, like the rest of the CDP path, breaks loud on a ChatGPT redesign.

## How it works

```
 Claude Code ──gate────▶ public GitHub links + whole-prompt secret scan (fail closed)
     │        ──submit──▶ open a fresh chat, type a sentinel-wrapped prompt, send
     │                    ▶ returns { rid, conversation_id, wait_cmd }
     │        ──wait─────▶ DETACHED poller re-attaches to that conversation, polls to
     │                     the wrapped answer, writes a file — its exit WAKES the agent
     ▼        ──followup▶ another round into the same conversation (feed results back)
 verify locally ──▶ act on the load-bearing claims after re-checking them
```

Completion is detected by **bare-line sentinels** (`BEGIN_RESPONSE:<rid>` /
`END_RESPONSE:<rid>`) read off `textContent` (not `innerText`, which collapses on a
backgrounded tab), **fence-aware** so a model quoting the sentinel inside a code fence
can't false-trigger, and matched against the request id so answers can't cross.

### Auto mode — the daemon path

For a **fully unattended** Claude Code session (auto permission mode), a
data-exfiltration classifier blocks any agent send to chatgpt.com. So the agent only does
**local file I/O** and a user-started daemon does the send:

```
 agent ──enqueue──▶ local job file (secret scan + link syntax; NO network)
 daemon ──validate▶ re-scan secrets + gh public re-check (fail closed)
        ──send─────▶ open chat, type, poll to the wrapped answer, write it + status
 agent ──await─────▶ poll the local status file (NO network); exit wakes the agent
```

The daemon (`gptc watch`) is the **only** component that talks to chatgpt.com. The user
starts it once, like the login. **Trade-off, stated plainly:** this moves egress off the
agent, so Claude Code's exfiltration net no longer sees it — the daemon's re-validating
gate is what protects you instead. That gate is public-repo-only + whole-prompt secret
scan, fail closed; it is deliberately narrow, and you should keep it that way.

**Honest scope of the daemon's trust.** It never trusts agent-supplied *content* (it
re-derives the prompt and re-scans/re-checks every job), and it contains the answer `out`
path to the answer dir so it can't be used as a write-anywhere gadget. It **does** honor two
owner-authorized agent-supplied *flags* — `--private` (non-public repos) and `--allow-nolink`
(waive the link anchor on a follow-up) — by your deliberate choice to give the agent that
latitude. If you don't want the agent to self-authorize those, don't pass them / patch the
daemon to require an out-of-band allowlist.

## Requirements

- **Python 3.8+** and `websocket-client` (`pip install websocket-client`)
- **`gh` CLI**, authenticated (`gh auth status`) — the gate uses it to prove repos public
- **Google Chrome** (or Chromium/Edge) installed
- A **ChatGPT account** you log into by hand (Pro recommended — that's the point)

## Install

```bash
git clone https://github.com/YichengYang-Ethan/claude-gpt-consult gptc && cd gptc
pip install -r requirements.txt
./install.sh                 # install the Claude Code skill + CLI into ~/.claude/skills
./bin/gptc launch            # start the debug Chrome, log into ChatGPT ONCE, leave it open
./bin/gptc doctor            # deps + gh + Chrome/login
```

In Claude Code the **`gptc-consult` skill auto-activates** when a task fits — Claude reads
its `SKILL.md` and orchestrates the arc for you. You can also drive the CLI by hand.

**New here? See [`USAGE.md`](USAGE.md)** — a one-page cheat sheet (boot steps, the daily
commands, flags, exit codes, gotchas).

## CLI

```bash
# dry-run the gate — see what would be sent, without sending
./bin/gptc gate    --task "review for concurrency bugs" --link owner/repo#123

# blocking: submit + wait in one go (small jobs, foreground)
./bin/gptc consult --title "Concurrency review" \
  --role "You are a senior systems engineer." \
  --task "Review the locking in this PR for races; verdict + confidence." \
  --link owner/repo#123

# pick the tier: chat=Sol Pro (fast) / work=Sol Ultra (deep). Verified + fail-closed.
./bin/gptc consult --mode work --title "Deep review" --task "..." --link owner/repo#123

# consult your OWN private repo via ChatGPT's GitHub connector (explicit opt-in)
./bin/gptc consult --mode work --private --task "..." --link me/private-repo

# background: submit returns rid + conversation_id + the exact wait_cmd
./bin/gptc submit  --title "..." --task "..." --link owner/repo#123
# then run the printed wait_cmd detached; its exit wakes the caller
./bin/gptc wait    --rid <rid> --conversation <cid> --out answer.txt --timeout 900

# continue the SAME thread (feed local results back)
./bin/gptc followup --conversation <cid> --task "Local tests show X — reconsider Z." --link owner/repo#124

# one-shot state of a conversation
./bin/gptc status  --rid <rid> --conversation <cid>
```

### Auto mode (unattended) — daemon path

```bash
./bin/gptc watch --detach                          # start the daemon in the background (agent- or user-started)
./bin/gptc enqueue --task "..." --link owner/repo  # agent: local write, no network
./bin/gptc await   --rid <rid> --out answer.txt    # agent: local poll, no network; exit wakes caller
./bin/gptc queue                                   # daemon liveness + spool counts
```

Answers are written to `gptc_answers/answer_<rid>.txt`. Set the model tier and project
once in the ChatGPT window (this version does not automate the model picker — that is the
most UI-fragile part of the original and is intentionally left out).

### Link formats

`owner/repo` · `owner/repo#123` (PR) · any `https://github.com/...` URL · `raw.githubusercontent.com/...`.
Non-GitHub links and gists are refused (gists: `--allow-gist` to override).

### `wait` / `await` exit codes
`0` answer written · `3` blocker (login/captcha/rate-limit) · `4` no answer before timeout
(the model may still be reasoning — raise `--timeout`) · `5` salvaged **partial** answer to
`<out>.partial` (unwrapped / clipped — treat as unverified) · `2` setup error (e.g. Chrome
not running).

**Timeouts are ceilings, not fixed waits** — a consult returns the instant the answer lands.
Pro/Ultra reasoning legitimately runs **30–50 min** (48m+ observed), so the default is
mode-aware and generous (`--mode work`≈3000s, else 1800s, capped at 3600) and `await` outlives
the job window. Don't read a long wait as a hang.

## Configuration (env; nothing here is a secret)

| Var | Default | Purpose |
| --- | --- | --- |
| `GPTC_PROJECT_URL` | `https://chatgpt.com/` | URL a fresh consult opens (set to your project to group them) |
| `GPTC_PORT` | `9333` | remote-debugging port for the dedicated Chrome |
| `GPTC_PROFILE` | `~/.gptc-chrome` | dedicated Chrome profile dir |
| `GPTC_CHROME` | auto-detect | explicit browser binary |
| `GPTC_ANSWER_DIR` | `./gptc_answers` | where answers are written |
| `GPTC_EXPECT_MODEL` | unset | substring of the model you pinned (e.g. `thinking`); if the answer came from a different model, a downgrade warning is surfaced (read-only, never selects) |

## What this version does NOT do (yet)

- Tier *selection* IS automated (`--mode chat|work`, actuated + read back + fail-closed), but
  it pins **effort/tier**, not the model family — the account's default model (e.g. GPT-5.6
  Sol) is assumed; pin a different family once in the ChatGPT window. The tool also **detects**
  which model actually answered (`data-message-model-slug`) and, if `GPTC_EXPECT_MODEL` is
  set, warns on a silent downgrade.
- Answer completion is request-correlated (it reads the assistant node carrying *this*
  request's sentinel, not the global last node) and only accepts a wrapped answer once
  generation has stopped and the text is stable — so concurrent rounds don't cross and
  post-`END` streaming isn't truncated.
- The live CDP path (drive chatgpt.com) is not unit-tested — it can't be without a
  logged-in session. The gate, sentinel parser, workflow plumbing, spool/daemon validation,
  tier/model logic, and heartbeat plumbing are tested (`pytest`, 74 passing).

## Security notes

- The tool never handles your password; you log into the dedicated profile by hand.
- Remote debugging is **loopback-bound** (`127.0.0.1`) with an origin allow-list. On a
  shared/compromised host, any local process can still reach an unauthenticated debug
  port — use this profile only for consults.
- **Never put secrets, private code, `.env`, or customer data in a prompt.** The gate
  catches common shapes but the real control is *public links only + you review it*.

## License

MIT
