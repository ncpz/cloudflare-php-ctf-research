set pagination off
set confirm off
set height 0
set width 0
break zend_mm_safe_error
break zend_mm_heap_corrupted
continue
bt 40
python
import gdb
with open("/tmp/abort_bt.txt", "w") as f:
    f.write(str(gdb.execute("bt 40", to_string=True)))
print("ABORT_BT_WRITTEN")
end
kill
quit
