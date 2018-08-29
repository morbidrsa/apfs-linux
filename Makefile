obj-m := apfs.o

apfs-y := super.o

ifneq ($(wildcard ~/src/linux/*),)
	KDIR="~/src/linux"
else
	KDIR="/lib/modules/$(shell uname -r)/build"
endif

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
