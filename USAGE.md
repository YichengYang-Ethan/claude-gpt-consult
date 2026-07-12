# gptc — one-page cheat sheet

Hand a self-contained job to your logged-in **ChatGPT** tab in the background, keep working,
get woken with the answer to **verify**. ChatGPT *advises*; your local agent *executes + checks*.

## 0. Once per machine boot (YOU do this — it's login)
```bash
gptc launch      # opens the dedicated debug Chrome — log into ChatGPT in it ONCE, leave open
gptc watch       # starts the daemon (the only thing that talks to chatgpt.com). Leave running.
gptc doctor      # green-checks deps / gh / Chrome / daemon
```
`launch` + `watch` must be up for anything to run. After a reboot, re-run both.

## 1. From another terminal's Claude Code (the normal way)
Just ask in plain language — the `gptc-consult` skill auto-activates and drives the daemon path
(`enqueue → await`, safe under auto-mode). Examples:
> "Use gptc to have ChatGPT deep-review this PR for concurrency bugs: `owner/repo#123`, work mode."
> "Consult GPT to derive the pricing model in `owner/repo` and give a proof; I'll verify."

You keep working locally; a detached waiter wakes Claude when the answer lands (tens of minutes
for Pro/Ultra — that's normal, not stuck). Claude then **re-checks the load-bearing claims**.

## 2. Manual CLI (when you want to drive it yourself)
```bash
# dry-run the gate — see exactly what would be sent, no send
gptc gate    --task "..." --link owner/repo#123

# blocking one-shot (foreground; returns when the answer lands)
gptc consult --mode work --title "Deep review" \
  --role "You are a senior systems engineer." \
  --task "Review the locking for races; verdict + confidence." \
  --link owner/repo#123

# background: submit -> run the printed wait_cmd detached -> its exit wakes you
gptc submit  --mode work --task "..." --link owner/repo#123
gptc wait    --rid <rid> --conversation <cid> --out answer.txt

# auto-mode (agent-side, no network): enqueue -> await (daemon does the send)
gptc enqueue --mode work --task "..." --link owner/repo#123
gptc await   --rid <rid> --out answer.txt

# continue the SAME thread (feed local results back)
gptc followup --conversation <cid> --task "Local tests show X — reconsider Z." --link owner/repo#124
```

## 3. Flags that matter
| flag | meaning |
| --- | --- |
| `--mode chat` | Sol **Pro** — fast, cheap. Quick lookups, small snippets, low-stakes second opinion. |
| `--mode work` | Sol **Ultra** — deep. Architecture reviews, large PRs, hard proofs, agentic planning. |
| `--private` | Allow **your own** non-public repos (via ChatGPT's GitHub connector). Off by default. |
| `--link` | `owner/repo` · `owner/repo#123` (PR) · a `github.com/...` repo/pull/commit URL. |
| `--timeout` | Ceiling seconds (returns as soon as the answer lands). Default is mode-aware. |

## 4. Exit codes (`wait` / `await`)
`0` clean answer written · `3` blocker (login/captcha/rate-limit — clear it in the tab, re-run) ·
`4` no answer in time (raise `--timeout`) · `5` **partial** answer salvaged to `<out>.partial`
(unwrapped/clipped — treat as unverified) · `2` setup error (Chrome/daemon not running).

## 5. Gotchas
- **Pro/Ultra think for 30–50 min.** Timeouts are ceilings, not fixed waits. A long wait is the
  model reasoning, not a hang. Don't set tight timeouts.
- **Public GitHub links only** unless you pass `--private` (which is for *your own* code — the
  connector's fetched content is outside the gate; only point it at what you'd disclose).
- Answers land in `gptc_answers/answer_<rid>.txt` (set `GPTC_ANSWER_DIR` to change).
- **Never** put secrets / `.env` / tokens / customer data in a task — the gate catches common
  shapes and fails closed, but the real control is *public links + you review it*.
- Automating the ChatGPT web app is against OpenAI's ToS — use a **secondary** account at human
  cadence, not your primary.
