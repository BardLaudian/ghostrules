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
