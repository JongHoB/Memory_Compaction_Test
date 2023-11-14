#!/bin/bash

KERNEL_VER=6
KERNEL_PATCHLEVEL=6

ROOT=$PWD
SRC=$ROOT


BUSYBOX_VER=1.36.1
INITRAMFS_IGZ=$SRC/initramfs.cpio.gz

KERNEL_FOLDER=$SRC/linux-${KERNEL_VER}.${KERNEL_PATCHLEVEL}
initrd=$SRC/initramfs
DIR=$initrd

set -e

if [ -e ${initrd} ]; then
	echo -n "Removing existing initrd, press ENTER to proceed... "
	read input
	rm -rf ${initrd}
fi

if [ -e ${INITRAMFS_IGZ} ]; then
	echo -n "Removing existing initrd, press ENTER to proceed... "
	read input
	rm -rf ${INITRAMFS_IGZ}
fi

build_busybox() {

	if [ ! -d $SRC/busybox-${BUSYBOX_VER} ]; then
		curl https://busybox.net/downloads/busybox-${BUSYBOX_VER}.tar.bz2 | tar jxf -
	fi

	cd $SRC/busybox-${BUSYBOX_VER}	

	make defconfig

	cp $ROOT/busybox.config $PWD/.config

	make -j $(nproc)

	if [ $? != 0 ]; then
		echo "Failed to compile busybox"
		exit 1
	fi

	make install

	mkdir -pv $SRC/initramfs/
	cd $SRC/initramfs
	mkdir -pv {bin,dev,sbin,etc,proc,sys/kernel/debug,usr/{bin,sbin},lib,lib64,mnt/root,root}
	cp -av $SRC/busybox-${BUSYBOX_VER}/_install/* $SRC/initramfs
	sudo cp -av /dev/{null,console,tty*,sda1} $SRC/initramfs/dev/
	sudo cp -av /bin/sh $SRC/initramfs/bin/

	# Set some defaults and enable promtless ssh to the machine for root.
	mkdir -pv $DIR/etc/netplan
	touch $DIR/etc/passwd

	sudo sed -i '/^root/ { s/:x:/::/ }' $DIR/etc/passwd
	echo 'T0:23:respawn:/sbin/getty -L ttyS0 115200 vt100' | sudo tee -a $DIR/etc/inittab
	cat << EOL | sudo tee $DIR/etc/netplan/01-network-manager-all.yaml > /dev/null
network:
 version: 2
 renderer: networkd
 ethernets:
  eth0:
   dhcp4: true
EOL
#sudo chroot $DIR /bin/bash -c "netplan apply"
echo '/dev/root / ext4 defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'debugfs /sys/kernel/debug debugfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'securityfs /sys/kernel/security securityfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo 'configfs /sys/kernel/config/ configfs defaults 0 0' | sudo tee -a $DIR/etc/fstab
echo "kernel.printk = 7 4 1 3" | sudo tee -a $DIR/etc/sysctl.conf
echo 'debug.exception-trace = 0' | sudo tee -a $DIR/etc/sysctl.conf
echo "net.core.bpf_jit_enable = 1" | sudo tee -a $DIR/etc/sysctl.conf
echo "net.core.bpf_jit_kallsyms = 1" | sudo tee -a $DIR/etc/sysctl.conf
echo "net.core.bpf_jit_harden = 0" | sudo tee -a $DIR/etc/sysctl.conf
echo "kernel.softlockup_all_cpu_backtrace = 1" | sudo tee -a $DIR/etc/sysctl.conf
echo "kernel.kptr_restrict = 0" | sudo tee -a $DIR/etc/sysctl.conf
echo "kernel.watchdog_thresh = 60" | sudo tee -a $DIR/etc/sysctl.conf
echo "net.ipv4.ping_group_range = 0 65535" | sudo tee -a $DIR/etc/sysctl.conf
echo -en "127.0.0.1\tlocalhost\n" | sudo tee $DIR/etc/hosts
echo "nameserver 8.8.8.8" | sudo tee -a $DIR/etc/resolve.conf
echo "cslvm" | sudo tee $DIR/etc/hostname
cd $ROOT
ssh-keygen -f qemu.id_rsa -t rsa -N ''
sudo mkdir -p $DIR/root/.ssh/
cat qemu.id_rsa.pub | sudo tee $DIR/root/.ssh/authorized_keys

	# This is a quite tricky way to run 'tee' with EOF in a bash function.
	# The file content 'OUT/initramfs/busybox/init' cannot have the
	# indentation for the utility command 'tee file << EOF'
	tee $SRC/initramfs/init << EOF
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t debugfs none /sys/kernel/debug
exec /bin/sh
EOF

chmod +x $SRC/initramfs/init

cd $SRC/initramfs/
find . | cpio -H newc -o > ../initramfs.cpio
cd ..
cat initramfs.cpio | gzip > $INITRAMFS_IGZ
}

if [ ! -f $INITRAMFS_IGZ ]; then
	build_busybox
fi



echo "Done"
