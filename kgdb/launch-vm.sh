#!/bin/bash

KERNEL=./linux-6.6
IMAGE=./
INITRAMFS_IGZ=./initramfs.cpio.gz
sudo qemu-system-x86_64 \
        -kernel $KERNEL/arch/x86/boot/bzImage -enable-kvm -cpu host \
        -nographic \
	-append "rw console=ttyS0,115200" \
        -device e1000,netdev=net0 -m 16G \
        -smp cpus=8,cores=4,maxcpus=8,dies=1,sockets=2,threads=1 \
	-object memory-backend-ram,id=mem0,size=8G\
	-object memory-backend-ram,id=mem1,size=8G\
        -numa node,memdev=mem0,nodeid=0,cpus=0-3 \
        -numa node,memdev=mem1,nodeid=1,cpus=4-7 \
	-initrd $INITRAMFS_IGZ \
	-netdev user,id=net0,hostfwd=tcp::2222-:22 \
        -pidfile vm.pid -gdb tcp::4321 \
        2>&1 | tee vm.log
