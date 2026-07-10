# gptc — Claude commands GPT

> A **Claude Code skill + CLI** that turns a logged-in **ChatGPT Pro** tab into a
> background coprocessor for your local agent. Claude fires off a self-contained job —
> a plan, a hard reasoning problem, a code review — keeps working locally, and a
> **detached waiter wakes it** when the full answer lands, ready to verify.
> It drives the **web app you're already logged into** — not the API — so there's
> **no key and no per-token bill**.

Claude drives locally; a dedicated Chrome tab logged into ChatGPT does the background
reasoning. A consult is a **thread, not a one-shot**: feed local verification results
back and follow up in the same conversation until the answer is clean.

This is a small, honest reimplementation of the idea behind
[`open-claude-gpt`](https://github.com/fitz-s/open-claude-gpt), rebuilt around two
principles the original bends:

1. **Public-code-only egress, enforced by construction.** Every consult carries ≥1
   public GitHub link, `gh`-confirmed public. The whole prompt is scanned for secret
   shapes and **fails closed** — catching the shapes the field forgets (`sk-ant-`,
   `sk_live_`, any `user:pass@host` connection string). A link-free follow-up requires
   an explicit `--allow-nolink` **flag** (user-controlled), not a spoofable in-prompt
   substring.
2. **Explicit, visible egress — no safety-classifier evasion.** The network send happens
   only inside a command *you* run. This project deliberately does **not** ship a daemon
   whose purpose is to move the send off the agent so a host's data-exfiltration
   classifier can't see it.

## ⚠️ Read this first

Automating the ChatGPT **web app** is **against OpenAI's Terms of Use** (which permit
programmatic extraction only through the API). This tool does not bypass login, CAPTCHA,
or rate limits — but the automated extraction itself is the part OpenAI restricts.
Realistic risk is *low-probability, high-consequence*: if the account is flagged, the
penalty is your whole ChatGPT account. **Run it on a secondary/throwaway account, at
human cadence, not your primary one.** You accept that risk by using this.

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

## CLI

```bash
# dry-run the gate — see what would be sent, without sending
./bin/gptc gate    --task "review for concurrency bugs" --link owner/repo#123

# blocking: submit + wait in one go (small jobs, foreground)
./bin/gptc consult --title "Concurrency review" \
  --role "You are a senior systems engineer." \
  --task "Review the locking in this PR for races; verdict + confidence." \
  --link owner/repo#123

# background: submit returns rid + conversation_id + the exact wait_cmd
./bin/gptc submit  --title "..." --task "..." --link owner/repo#123
# then run the printed wait_cmd detached; its exit wakes the caller
./bin/gptc wait    --rid <rid> --conversation <cid> --out answer.txt --timeout 900

# continue the SAME thread (feed local results back)
./bin/gptc followup --conversation <cid> --task "Local tests show X — reconsider Z." --link owner/repo#124

# one-shot state of a conversation
./bin/gptc status  --rid <rid> --conversation <cid>
```

Answers are written to `gptc_answers/answer_<rid>.txt`. Set the model tier and project
once in the ChatGPT window (this version does not automate the model picker — that is the
most UI-fragile part of the original and is intentionally left out).

### Link formats

`owner/repo` · `owner/repo#123` (PR) · any `https://github.com/...` URL · `raw.githubusercontent.com/...`.
Non-GitHub links and gists are refused (gists: `--allow-gist` to override).

### `wait` exit codes
`0` answer written · `3` blocker (login/captcha/rate-limit) · `4` no wrapped answer before
timeout · `2` setup error (e.g. Chrome not running).

## Configuration (env; nothing here is a secret)

| Var | Default | Purpose |
| --- | --- | --- |
| `GPTC_PROJECT_URL` | `https://chatgpt.com/` | URL a fresh consult opens (set to your project to group them) |
| `GPTC_PORT` | `9333` | remote-debugging port for the dedicated Chrome |
| `GPTC_PROFILE` | `~/.gptc-chrome` | dedicated Chrome profile dir |
| `GPTC_CHROME` | auto-detect | explicit browser binary |
| `GPTC_ANSWER_DIR` | `./gptc_answers` | where answers are written |

## What this version does NOT do (yet)

- No automated model-picker selection (set it once in the tab).
- No auto-mode egress daemon — by design (see principle 2). Under a locked-down agent
  mode that blocks the send, run `gptc consult`/`submit` yourself or approve it.
- The live CDP path (drive chatgpt.com) is not unit-tested — it can't be without a
  logged-in session. The gate, sentinel parser, and workflow plumbing are tested
  (`pytest`, 18 passing).

## Security notes

- The tool never handles your password; you log into the dedicated profile by hand.
- Remote debugging is **loopback-bound** (`127.0.0.1`) with an origin allow-list. On a
  shared/compromised host, any local process can still reach an unauthenticated debug
  port — use this profile only for consults.
- **Never put secrets, private code, `.env`, or customer data in a prompt.** The gate
  catches common shapes but the real control is *public links only + you review it*.

## License

MIT
