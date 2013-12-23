#
## Makefile for the linux hfsplus filesystem routines.
#
KERNELRELEASE ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KERNELRELEASE)/build
#KDIR  ?= /lib/modules/3.2.0-34-generic/build

obj-$(CONFIG_HFSPLUS_FS) += hfsplus.o

hfsplus-objs := super.o options.o inode.o ioctl.o extents.o catalog.o dir.o btree.o \
		bnode.o brec.o bfind.o tables.o unicode.o wrapper.o bitmap.o part_tbl.o journal.o \
		attributes.o xattr.o xattr_user.o xattr_security.o xattr_trusted.o

hfsplus-$(CONFIG_HFSPLUS_FS_POSIX_ACL)	+= posix_acl.o

default: modules

modules:
	$(MAKE) -C  $(KDIR) M=`pwd` $@

modules_prepare:
	$(MAKE) O=$(KDIR) M=$(PWD) $@

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) $@



