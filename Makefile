#
## Makefile for the linux hfsplus filesystem routines.
#

obj-$(CONFIG_HFSPLUS_FS) += hfsplus.o

hfsplus-objs := super.o options.o inode.o ioctl.o extents.o catalog.o dir.o btree.o \
		bnode.o brec.o bfind.o tables.o unicode.o wrapper.o bitmap.o part_tbl.o journal.o


all:
	make -C /lib/modules/`uname -r`/build M=`pwd`
	
clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean



