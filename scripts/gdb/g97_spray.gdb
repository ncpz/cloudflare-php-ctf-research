set pagination off
set confirm off
handle SIGABRT stop print nopass
handle SIGSEGV stop print nopass
echo \n=== attached; waiting for the spray abort ===\n
continue
echo \n=== signal captured ===\n
bt
echo \n=== full threads ===\n
thread apply all bt
echo \n=== done ===\n
