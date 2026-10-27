# ghostrules

*Find the instructions your AI agent sees but you don't.*

`ghostrules` scans a repository (and optionally your machine) for hidden instructions and risky
configuration in the files AI coding agents read and obey: `AGENTS.md`, `CLAUDE.md`,
`.cursorrules`, Copilot instructions, skills, MCP configs and more.

It is a defensive tool: it only reads files and reports findings. It never executes anything it
finds and never makes network requests.

> Work in progress (pre-0.1.0). The full README lands in the final phase.
