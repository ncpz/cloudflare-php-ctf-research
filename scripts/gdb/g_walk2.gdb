set pagination off
set confirm off
set height 0
set width 0
set $h = *(unsigned long*)&'alloc_globals'
set $pg = (unsigned long)&'ps_globals'
python
import gdb
inf = gdb.selected_inferior()
def rq(a, n=8):
    return int.from_bytes(bytes(inf.read_memory(a, n)), "little")
out = []
W = out.append
h = int(gdb.parse_and_eval("$h"))
main = rq(h + 0x140)
W("heap=%#x main=%#x" % (h, main))
pg = int(gdb.parse_and_eval("$pg"))
sid = rq(pg + 0x10)
W("PS(id)=%#x  main_delta=%#x page=%d" % (sid, sid - main, (sid - main) >> 12))
try:
    hdr = bytes(inf.read_memory(sid, 0x40))
    W("sid hdr: " + " ".join("%016x" % int.from_bytes(hdr[i:i+8], "little") for i in range(0, 0x40, 8)))
    W("sid val[:32]=%r" % hdr[0x18:0x18+32])
except Exception as e:
    W("sid read fail: %r" % e)
try:
    pf = main + 0x56230
    raw = bytes(inf.read_memory(pf, 0x40))
    W("ps_files raw: " + " ".join("%016x" % int.from_bytes(raw[i:i+8], "little") for i in range(0, 0x40, 8)))
    pathptr = rq(pf + 8)
    W("path ptr=%#x main_delta=%#x page=%d" % (pathptr, pathptr - main, (pathptr - main) >> 12))
    ph = bytes(inf.read_memory(pathptr, 0x30))
    W("path hdr: " + " ".join("%016x" % int.from_bytes(ph[i:i+8], "little") for i in range(0, 0x30, 8)))
    W("path val=%r" % ph[0x18:0x18+16])
except Exception as e:
    W("ps_files read fail: %r" % e)
head = rq(h + 0x148); count = rq(h + 0x158)
W("cache count=%d head=%#x" % (count, head))
try:
    c = head; i = 0
    while c and i < count + 2:
        fp = rq(c + 0x18)
        W("  cache[%d]=%#x free_pages=%d" % (i, c, fp))
        c = rq(c + 8); i += 1
except Exception as e:
    W("cache walk fail at %d: %r" % (i, e))
txt = "\n".join(out)
with open("/tmp/walk2.txt", "w") as f:
    f.write(txt)
print(txt)
print("WALK2_WRITTEN")
end
detach
quit
