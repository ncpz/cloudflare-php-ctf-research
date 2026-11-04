set pagination off
set print thread-events off
dprintf *0x5469d0,"INIT-HIT php_session_initialize\n"
dprintf php_session_reset_id,"RESETID-HIT\n"
dprintf *0x5f23f0,"URLENC-HIT php_url_encode_to_smart_str\n"
dprintf zend_mm_safe_error,"OOM-HIT zend_mm_safe_error\n"
continue
