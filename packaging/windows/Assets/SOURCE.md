# LICENSE.rtf

Generated from `LICENSE` at the repo root. The WiX license dialog reads RTF,
not plain text, so the GPL text is wrapped rather than rewritten. Nothing here
is edited by hand: regenerate it when `LICENSE` changes.

```bash
python3 - <<'PY'
src = open("LICENSE", encoding="ascii").read()

def esc(ch):
    if ch in "\\{}":
        return "\\" + ch
    return ch if ord(ch) <= 127 else "\\'%02x" % ord(ch)

body = "".join("".join(esc(c) for c in line) + "\\par\n" for line in src.split("\n"))
rtf = ("{\\rtf1\\ansi\\ansicpg1252\\deff0\n"
       "{\\fonttbl{\\f0\\fmodern Courier New;}}\n"
       "\\viewkind4\\uc1\\pard\\f0\\fs16\n" + body + "}\n")
open("packaging/windows/Assets/LICENSE.rtf", "w", encoding="ascii", newline="\r\n").write(rtf)
PY
```

Run it from the repo root. Confirm the result still carries the whole license:

```bash
shasum -a 256 packaging/windows/Assets/LICENSE.rtf
```
