# v0.3 — Web playground: "See what your AI agent sees"

## Goal
Let anyone try ghostrules in 5 seconds without installing anything: a static page on GitHub Pages
that runs the real ghostrules code **in the browser** with Pyodide. Files never leave the browser.

URL: `https://bardlaudian.github.io/ghostrules/` — linked as the first thing in the README and in the
repo "About → Website".

## Feasibility check (Phase 0 of the plan)
- The core must import without `typer`/`rich` (the CLI and the table reporter are the only users).
  Add a test that imports `ghostrules.scanner`, the rules registry, `context` engine, JSON reporter
  and `reveal` helpers with `typer`/`rich` blocked (`sys.modules[...] = None`).
- Build the pure-Python wheel in CI and load it in Pyodide with `micropip.install(<wheel URL>,
  deps=False)`. Pin an exact Pyodide version from its CDN (jsdelivr), no `latest`.
- If something in the core uses APIs Pyodide lacks (subprocess, real symlinks, `os.scandir` edge
  cases), add a thin in-memory filesystem adapter rather than forking logic.

## Features (in priority order)
1. **Paste a file** (default tab): a text area preloaded with a harmless-looking demo `AGENTS.md`
   that hides a defanged tag-character instruction. Button "Scan". Result:
   - findings list (severity badge, rule, message, fix);
   - "What you see / What the agent reads" two-column view: left = rendered/visible text, right =
     raw text with every invisible character shown as a highlighted token and decoded hidden text
     underneath (reuse `reveal` logic). This view is the screenshot people will share.
2. **Drop a folder** (`<input webkitdirectory>` + drag & drop): load only agent-relevant files
   (target list + anything they import, max total 5 MB) into Pyodide's in-memory FS, then show the
   `context` tree per agent and the findings with import chains.
3. **Scan a public GitHub repo** (`owner/repo` or URL): fetch the tree via the GitHub REST API
   (unauthenticated, 60 req/h — show the limit and errors clearly), download only agent files and
   their imports from `raw.githubusercontent.com`, then same view as (2). Make it explicit in the UI
   that this is the only feature that touches the network, and that it talks to GitHub only.
4. Copy a **permalink** for pasted content? No — never put user content in URLs. Instead offer
   "Download report (JSON / Markdown / SARIF)".

## Design
- Single static site in `web/` (vanilla JS or a tiny framework, no build step preferred). Dark and
  light themes, mobile friendly, accessible (keyboard, contrast, ARIA for results).
- Loading state while Pyodide boots (it takes a few seconds): show a progress line, and let the user
  paste meanwhile.
- No analytics, no cookies, no external fonts beyond what's necessary; say so in the footer
  ("Runs entirely in your browser. No data is sent anywhere." — plus the GitHub exception for (3)).
- Footer: install command, link to repo, star button (GitHub's official button or a plain link).

## Deployment
`.github/workflows/pages.yml`: on release tags (and manual dispatch) build the wheel, copy it into
`web/`, deploy to GitHub Pages with the official `actions/upload-pages-artifact` +
`actions/deploy-pages` (pin by SHA). The page loads the wheel from its own origin.

## Tests
- Playwright smoke test in CI (Chromium is enough): page loads, demo scan shows the GR001 finding and
  the decoded text, folder upload with the import-chain demo shows the chain. Run on the built site
  served locally.
