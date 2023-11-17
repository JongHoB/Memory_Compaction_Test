#!/bin/bash

KERNEL=./linux-6.6
IMAGE=./
sudo qemu-system-x86_64 \
        -kernel $KERNEL/arch/x86/boot/bzImage -enable-kvm \
        -nographic \
	-append "console=ttyS0,115200 root=/dev/sda earlyprintk=serial net.ifnames=0 nokaslr norandmaps" \
        -m 16G \
	-drive file=./bionic.img,format=raw \
	-smp 8 \
	-net user,host=10.0.2.10,hostfwd=tcp:127.0.0.1:10021-:22\
	-net nic,model=e1000 \
        -pidfile vm.pid -gdb tcp::4321 \
        2>&1 | tee vm.log

	#-smp cpus=8,cores=4,maxcpus=8,dies=1,sockets=2,threads=1 \
	#-object memory-backend-ram,id=mem0,size=8G\
	#-object memory-backend-ram,id=mem1,size=8G\
        #-numa node,memdev=mem0,nodeid=0,cpus=0-3 \
        #-numa node,memdev=mem1,nodeid=1,cpus=4-7 \
#-object memory-backend-ram,id=mem0,size=16G\
#	-numa node,memdev=mem0,nodeid=0,cpus=0-1\

