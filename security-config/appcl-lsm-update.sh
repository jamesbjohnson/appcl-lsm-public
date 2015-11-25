#!/bin/bash
# update AppCL LSM in security directory of linux kernel

cd /home/jamesjohnson/appcl-lsm/ &&
git pull &&
cp -avr /home/jamesjohnson/appcl-lsm /home/jamesjohnson/linux-4.3/security/ &&
rm /home/jamesjohnson/linux-4.3/security/Makefile &&
rm /home/jamesjohnson/linux-4.3/security/Kconfig &&
cp /home/jamesjohnson/appcl-lsm/security-config/Makefile /home/jamesjohnson/linux-4.3/security &&
cp /home/jamesjohnson/appcl-lsm/security-config/Kconfig /home/jamesjohnson/linux-4.3/security &&
cd /home/jamesjohnson/linux-4.3/ &&
make clean &&
make menuconfig &&
make && make modules_install && make install
