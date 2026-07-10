#!/usr/bin/env bash
# gptc installer — install the Claude Code skill + CLI.
#
#   ./install.sh            # copy the skill into ~/.claude/skills/gptc-consult
#   ./install.sh --link     # symlink the script instead (edits in the repo go live)
#   ./install.sh --dir DIR  # install into a different skills root
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
SKILLS_DIR="${CLAUDE_SKILLS_DIR:-$HOME/.claude/skills}"
NAME="gptc-consult"
MODE="copy"

while [ $# -gt 0 ]; do
  case "$1" in
    --link) MODE="link"; shift ;;
    --dir)  SKILLS_DIR="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

DEST="$SKILLS_DIR/$NAME"
echo "gptc → $DEST  (mode: $MODE)"

# --- dependency preflight -----------------------------------------------------
command -v python3 >/dev/null || { echo "ERROR: python3 not found" >&2; exit 1; }
if ! python3 -c "import websocket; assert hasattr(websocket,'create_connection')" 2>/dev/null; then
  echo "• installing Python dep: websocket-client"
  python3 -m pip install --user websocket-client >/dev/null 2>&1 \
    || echo "  ! could not auto-install; run: pip install websocket-client" >&2
fi
command -v gh >/dev/null || echo "  ! gh CLI not found — install from https://cli.github.com (the gate needs it)"

# --- install skill payload (SKILL.md + scripts/gptc.py) -----------------------
mkdir -p "$DEST/scripts"
if [ -e "$DEST/SKILL.md" ] && [ ! -L "$DEST/scripts/gptc.py" ]; then
  echo "• existing install found — overwriting"
fi
cp "$REPO/skill/SKILL.md" "$DEST/SKILL.md"
if [ "$MODE" = "link" ]; then
  ln -sf "$REPO/gptc.py" "$DEST/scripts/gptc.py"
else
  cp "$REPO/gptc.py" "$DEST/scripts/gptc.py"
fi
chmod +x "$DEST/scripts/gptc.py" 2>/dev/null || true

echo "• installed. running doctor…"
echo
python3 "$DEST/scripts/gptc.py" doctor || true

cat <<EOF

Next steps
  1. Start the dedicated debug Chrome and log into ChatGPT once (USER does this):
       python3 "$DEST/scripts/gptc.py" launch
  2. In Claude Code the skill 'gptc-consult' auto-activates when a task fits.
     Manual test:
       python3 "$DEST/scripts/gptc.py" consult --title demo \\
         --task "Summarize the top risk in this repo" --link owner/repo

Config lives in the environment — see README.md.
EOF
