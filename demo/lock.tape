# Records the lock GIF: a pull request that looks harmless, and what `ghostrules lock --check`
# says about what the agents will read after it.
#   vhs demo/lock.tape      (needs https://github.com/charmbracelet/vhs, ffmpeg and ttyd)
# Run it from the repository root with `pip install -e .` done. The hidden setup writes the
# scenario to /tmp/acme (base/ is locked, pr/ is base plus the pull request).
# Keep the total under 20 seconds: tests/test_demo.py checks it.

Output demo/lock.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 760
Set Padding 16
Set Theme "Dracula"
Set TypingSpeed 30ms

Env FORCE_COLOR "1"
Env COLUMNS "118"

Hide
Type "export PS1='$ ' LC_ALL=C && python scripts/make_demo.py --lock-scenario /tmp/acme > /dev/null"
Enter
Type "ghostrules lock --root /tmp/acme/base > /dev/null && cp /tmp/acme/base/.ghostrules.lock /tmp/acme/pr/ && cd /tmp/acme && clear"
Enter
Sleep 3s
Show

# 1. The pull request, as a reviewer's diff shows it: invisible characters are not visible.
Type "diff base/shared/team-rules.md pr/shared/team-rules.md | sed 's/[^ -~]//g'"
Enter
Sleep 2400ms

# 2. What the agents will read after it, with the invisible characters revealed.
Ctrl+L
Type "ghostrules lock --check --root pr"
Enter
Sleep 5000ms
