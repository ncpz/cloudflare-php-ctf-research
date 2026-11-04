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
h = int(gdb.parse_and_eval("$h"))
main = rq(h + 0x140)
out = []
W = out.append
W("main=%#x" % main)
pg = int(gdb.parse_and_eval("$pg"))
sid = rq(pg + 0x10)
page = (sid - main) >> 12
W("sid=%#x page=%d" % (sid, page))
# chunk header counters: free_pages @0x18, free_tail @0x1c (uint32)
fp = int.from_bytes(bytes(inf.read_memory(main + 0x18, 4)), "little")
ft = int.from_bytes(bytes(inf.read_memory(main + 0x1c, 4)), "little")
W("free_pages=%d free_tail=%d" % (fp, ft))
fm = bytes(inf.read_memory(main + 528, 64))
W("free_map byte0=%02x (page0 bit=%d)" % (fm[0], fm[0] & 1))
alloc_pages = [i for i in range(512) if (fm[i//8] >> (i%8)) & 1]
W("free_map set-bits(=allocated?) count=%d pages[:40]=%s" % (len(alloc_pages), alloc_pages[:40]))
# map[] entries (uint32 each) at main+592
def m(n):
    return int.from_bytes(bytes(inf.read_memory(main + 592 + 4*n, 4)), "little")
W("map[0]=%#x map[86]=%#x map[107]=%#x map[108]=%#x" % (m(0), m(86), m(107), m(108)))
free_by_map = sum(1 for n in range(512) if m(n) == 0)
W("map[] FRUN(=0) count=%d" % free_by_map)
txt = "\n".join(out)
with open("/tmp/map_out.txt", "w") as f:
    f.write(txt)
print(txt)
print("MAP_WRITTEN")
end
detach
quit
