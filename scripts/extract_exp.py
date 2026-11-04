"""Extract the EDB 52704 exploit source from the saved HTML view into a runnable file.

Reads ext/edb52704_view.txt, strips the HTML code wrapper, applies the RUN AA
instrumentation patches (attach-window marker + generous A1 timeout), and
writes exp_aa.py next to it.
"""
import re

SRC = "ext/edb52704_view.txt"
DST = "exp_aa.py"

raw = open(SRC, encoding="utf-8", errors="replace").read()

# The view file is: <code class="language-py" style="white-space: pre-wrap;">SCRIPT</code>
start = raw.index('pre-wrap;') + len('pre-wrap;') + 2  # skip the closing ">
script = raw[start:]
script = script.rsplit("</code>", 1)[0]
script = script.lstrip("\r\n")

# RUN AA patches
script, n1 = re.subn(
    r"^(\s*)time\.sleep\(0\.25\)\s*$",
    r"\1print('SLEEPING-60-FOR-ATTACH', flush=True); time.sleep(60.0)",
    script,
    count=1,
    flags=re.M,
)
script, n2 = re.subn(
    r"a1_response, 180\.0\)",
    "a1_response, 900.0)",
    script,
    count=1,
)

open(DST, "w", encoding="utf-8", newline="\n").write(script)
print(f"wrote {DST}: sleep-patch={n1} timeout-patch={n2} lines={script.count(chr(10))}")
