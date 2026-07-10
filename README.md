# gptc — Claude commands GPT

> Hand a self-contained job (review, plan, hard reasoning) from a local agent
> (Claude Code) to a **logged-in ChatGPT tab**, get the wrapped answer back, and
> act on it — using the two **subscriptions** you already pay for. No API key,
> no per-token bill.

Claude drives locally; a dedicated Chrome tab logged into ChatGPT does the
background reasoning. Claude fires a consult, keeps working, and reads the answer
when it lands — then **verifies the load-bearing parts locally** before acting.

This is a small, honest, single-file reimplementation of the idea behind
[`open-claude-gpt`](https://github.com/fitz-s/open-claude-gpt), rebuilt around two
principles the original bends:

1. **Public-code-only egress, enforced by construction.** Every consult must carry
   ≥1 public GitHub link, `gh`-confirmed public. The whole prompt is scanned for
   secret shapes and **fails closed**. There is no spoofable "follow-up" exemption,
   and the secret scanner catches the shapes the field forgets — `sk-ant-` keys,
   `sk_live_` keys, and any `user:pass@host` connection string.
2. **Explicit, visible egress — no safety-classifier evasion.** The network send
   happens only inside a command *you* run (`gptc consult`), which prints exactly
   what it is about to send. This project deliberately does **not** ship a daemon
   whose purpose is to move the send off the agent so a host's data-exfiltration
   classifier can't see it.

## ⚠️ Read this first

Automating the ChatGPT **web app** is **against OpenAI's Terms of Use** (which
permit programmatic extraction only through the API). This tool does not bypass
login, CAPTCHA, or rate limits — but the automated extraction itself is the part
OpenAI restricts. Realistic risk is *low-probability, high-consequence*: if the
account is flagged, the penalty is your whole ChatGPT account.

**Recommendation: run it on a secondary/throwaway ChatGPT account, at human
cadence, not your primary one.** You accept that risk by using this.

## How it works

```
 local agent ──gate──▶ public GitHub links + secret scan (fail closed)
     │        ──render▶ prompt wrapped in BEGIN_RESPONSE:<rid> / END_RESPONSE:<rid>
     │        ──CDP────▶ dedicated Chrome (loopback debug port) ─▶ your logged-in ChatGPT tab
     │        ◀──poll───  read the answer between the sentinels
     ▼
 verify locally ──▶ act on it
```

Completion is detected by **bare-line sentinels** read off `textContent` (not
`innerText`, which collapses on a backgrounded tab), fence-aware so a model quoting
the sentinel inside a code fence can't false-trigger, and matched against the
request id so answers can't cross.

## Requirements

- **Python 3.8+** and `websocket-client` (`pip install websocket-client`)
- **`gh` CLI**, authenticated (`gh auth status`) — the gate uses it to prove repos public
- **Google Chrome** (or Chromium/Edge) installed
- A **ChatGPT account** you log into by hand (Pro recommended — that's the point)

## Install

```bash
git clone <your-fork-url> gptc && cd gptc
pip install -r requirements.txt
./bin/gptc doctor          # deps + gh + (chrome not up yet is expected)
```

## Use

```bash
# 1. Start the dedicated debug Chrome, log into ChatGPT ONCE, leave it open.
./bin/gptc launch

# 2. (optional) dry-run the gate — see what would be sent, without sending.
./bin/gptc gate --task "review for concurrency bugs" --link owner/repo#123

# 3. Consult: gate -> open a fresh chat -> type -> send -> wait -> write the answer.
./bin/gptc consult \
  --title "Concurrency review" \
  --role  "You are a senior systems engineer." \
  --task  "Review the locking in the PR for races and deadlocks; give a verdict + confidence." \
  --link  owner/repo#123
```

The answer is written to `gptc_answers/answer_<rid>.txt` and printed. Set the model
tier and project once in the ChatGPT window (MVP does not automate the model picker —
that is the most UI-fragile part of the original and is intentionally left out for now).

### Link formats

`owner/repo` · `owner/repo#123` (PR) · any `https://github.com/...` URL (repo / tree /
blob / pull) · `raw.githubusercontent.com/...`. Non-GitHub links and gists are refused
(gists: `--allow-gist` to override — the gate can't cheaply prove a gist is public).

## Configuration (env; nothing here is a secret)

| Var | Default | Purpose |
| --- | --- | --- |
| `GPTC_PROJECT_URL` | `https://chatgpt.com/` | URL a fresh consult opens (set to your project to group them) |
| `GPTC_PORT` | `9333` | remote-debugging port for the dedicated Chrome |
| `GPTC_PROFILE` | `~/.gptc-chrome` | dedicated Chrome profile dir |
| `GPTC_CHROME` | auto-detect | explicit browser binary |
| `GPTC_ANSWER_DIR` | `./gptc_answers` | where answers are written |

## What this MVP does NOT do yet

- No automated model-picker selection (set it once in the tab).
- No multi-round follow-up threads.
- No detached/background waiter or Claude Code skill packaging.
- The live CDP path (drive chatgpt.com) is not unit-tested — it can't be without a
  logged-in session. The gate and sentinel parser are fully tested (`pytest`).

## Security notes

- The tool never handles your password; you log into the dedicated profile by hand.
- Remote debugging is **loopback-bound** (`127.0.0.1`) with an origin allow-list.
  On a shared/compromised host, any local process can still reach an unauthenticated
  debug port — use this profile only for consults.
- **Never put secrets, private code, `.env`, or customer data in a prompt.** The gate
  catches common shapes but the real control is *public links only + you review it*.

## License

MIT
