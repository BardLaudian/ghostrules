# Records the README demo: a file that looks innocent, what ghostrules finds, what is hidden.
#   vhs demo/demo.tape      (needs https://github.com/charmbracelet/vhs, ffmpeg and ttyd)
# Run it from the repository root with `pip install -e .` done and the demo repos generated
# (`python scripts/make_demo.py`). Keep the total under 15 seconds: tests/test_demo.py checks it.

Output demo/demo.gif

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
Type "export PS1='$ ' && clear"
Enter
Show

# 1. The file looks perfectly normal.
Type "cat examples/poisoned-repo/AGENTS.md"
Enter
Sleep 1800ms

# 2. ghostrules shows what it really contains.
Ctrl+L
Type "ghostrules scan examples/poisoned-repo | head -24"
Enter
Sleep 3600ms

# 3. Every invisible character, made visible.
Ctrl+L
Type "ghostrules reveal examples/poisoned-repo/AGENTS.md"
Enter
Sleep 3200ms
