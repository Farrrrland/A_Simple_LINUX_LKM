obj-m += GetRouting.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

Routing:
	make
	-sudo rmmod GetRouting
	sudo dmesg -C
	sudo insmod GetRouting.ko
	dmesg
	gcc user.c -o user
	# IP address to listen. 
	./user 192.168.17.131
	dmesg