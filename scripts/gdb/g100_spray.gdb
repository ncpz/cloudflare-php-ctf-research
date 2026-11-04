set pagination off
set confirm off
set height 0
set width 0
set $h = *(unsigned long*)&'alloc_globals'
python
import gdb
inf = gdb.selected_inferior()
def rq(a, n=8):
    return int.from_bytes(bytes(inf.read_memory(a, n)), "little")
out = []
W = out.append
h = int(gdb.parse_and_eval("$h"))
main = rq(h + 0x140)
W("main=%#x" % main)
pg = int(gdb.parse_and_eval("(unsigned long)&'ps_globals'"))
sid = rq(pg + 0x10)
W("PS(id)=%#x main_delta=%#x page=%d" % (sid, sid - main, (sid - main) >> 12))
if main <= sid < main + 0x200000:
    hdr = bytes(inf.read_memory(sid, 0x30))
    W("sid hdr: " + " ".join("%016x" % int.from_bytes(hdr[i:i+8], "little") for i in range(0, 0x30, 8)))
    W("sid val[:24]=%r" % hdr[0x18:0x18+24])
# free_map bit for page 107 (chunk+528 = free_map; bit SET = allocated)
fm = bytes(inf.read_memory(main + 528 + 13, 1))
W("free_map byte13=%#x bit107(alloc)=%d" % (fm[0], (fm[0] >> 3) & 1))
# spray signature search in main: {refcount=2,type=6,len=0x4000} every 0x40
pat = (2).to_bytes(4, "little") + (6).to_bytes(4, "little") + (0x4000).to_bytes(8, "little")
region = bytes(inf.read_memory(main, 0x200000))
hits = []
i = region.find(pat)
while i != -1 and len(hits) < 6:
    hits.append(i)
    i = region.find(pat, i + 1)
W("spray hits in main: %d %s" % (len(hits), [hex(x) for x in hits]))
if hits:
    first = hits[0]
    W("first hit delta from main: %#x (mod 0x40 = %#x)" % (first, first % 0x40))
    # check periodicity
    if len(hits) >= 2:
        W("hit spacing: %s" % [hex(hits[k+1]-hits[k]) for k in range(len(hits)-1)])
# also search ONE chunk above/below in case the run went to a neighbor
head = rq(h + 0x148); count = rq(h + 0x158)
W("cache count=%d" % count)
txt = "\n".join(out)
with open("/tmp/walk3.txt", "w") as f:
    f.write(txt)
print(txt)
print("WALK3_WRITTEN")
end
detach
quit
