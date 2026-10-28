# Recording the README GIF

`demo.tape` is a [vhs](https://github.com/charmbracelet/vhs) script. It needs `vhs`, `ffmpeg` and
`ttyd` on the PATH (see the vhs README for your platform).

```bash
pip install -e .                 # so `ghostrules` is on the PATH
python scripts/make_demo.py      # regenerate examples/ (the invisible characters are generated)
vhs demo/demo.tape               # writes demo/demo.gif from the repository root
```

Keep the recording under 15 seconds: `tests/test_demo.py` estimates its length from the tape. The
README embeds the file from the `main` branch, so committing `demo/demo.gif` is all it takes.

Two more tapes tell the 0.2 story. Same requirements, also run from the repository root:

```bash
vhs demo/imports.tape            # CLAUDE.md looks clean; the payload is two imports away
vhs demo/lock.tape               # a harmless-looking pull request, and `ghostrules lock --check`
```

`imports.tape` writes `demo/imports.gif` and `lock.tape` writes `demo/lock.gif`; both must stay under
20 seconds (tested). `lock.tape` builds its scenario in `/tmp/acme` with
`python scripts/make_demo.py --lock-scenario /tmp/acme`.
