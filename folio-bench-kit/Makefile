# SPDX-License-Identifier: GPL-2.0
#
# Builds:
#   - folio_copy_ab_bench.ko   (out-of-tree kernel module)
#   - move_pages_bench         (userspace)

obj-m := folio_copy_ab_bench.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all: module move_pages_bench

module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

move_pages_bench: move_pages_bench.c
	$(CC) -O2 -Wall -o $@ $<

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f move_pages_bench

.PHONY: all module clean
