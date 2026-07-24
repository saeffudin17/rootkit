obj-m += gsock_protect.o

KDIR  := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
	rm -f modules.order Module.symvers

install:
	@echo "[*] Loading kernel module..."
	insmod gsock_protect.ko protected_pids=$(PIDS)
	@echo "[+] Done"
