 >lsmod

> insmod lkmprotect.ko

> lsmod

> lkmprotect 2192 0 - Live 0xbf000000 (P)

> insmod debug_evt.ko

> insmod: init_module 'debug_evt.ko' failed (Operation not permitted)

> kill -31 1337

> rmmod lkmprotect

> lsmod

> insmod lkmprotect.ko

> lsmod

> lkmprotect 2192 0 - Live 0xbf006000 (P)

> rmmod lkmprotect

> rmmod: delete_module 'lkmprotect' failed (errno 1)