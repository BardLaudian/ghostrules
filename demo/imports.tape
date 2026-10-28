# Records the import-chain GIF: CLAUDE.md looks clean, but it imports a file that imports a file
# with a hidden instruction. A scanner that only reads agent files sees nothing.
#   vhs demo/imports.tape   (needs https://github.com/charmbracelet/vhs, ffmpeg and ttyd)
# Run it from the repository root with `pip install -e .` done and the demo repos generated
# (`python scripts/make_demo.py`). Keep the total under 20 seconds: tests/test_demo.py checks it.

Output demo/imports.gif

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
Type "cat examples/import-chain-repo/CLAUDE.md"
Enter
Sleep 1600ms

# 2. A scanner that only reads agent files finds nothing.
Ctrl+L
Type "ghostrules scan --no-follow-imports examples/import-chain-repo"
Enter
Sleep 1800ms

# 3. Following the imports finds the payload, with the chain that leads to it.
Ctrl+L
Type "ghostrules scan examples/import-chain-repo | head -12"
Enter
Sleep 3200ms

# 4. And this is everything Claude Code reads when it works on src/api/users.ts.
Ctrl+L
Type "ghostrules context src/api/users.ts --root examples/import-chain-repo --agent claude-code"
Enter
Sleep 4000ms
