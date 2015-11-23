#!/bin/bash
# update AppCL LSM in security directory of linux kernel

cd /home/jamesjohnson/appcl-lsm/ &&
git pull &&
cp -avr /home/jamesjohnson/appcl-lsm /home/jamesjohnson/linux-4.1.6/security/ &&
rm /home/jamesjohnson/linux-4.1.6/security/Makefile &&
rm /home/jamesjohnson/linux-4.1.6/security/Kconfig &&
cp /home/jamesjohnson/appcl-lsm/security-config/Makefile /home/jamesjohnson/linux-4.1.6/security &&
cp /home/jamesjohnson/appcl-lsm/security-config/Kconfig /home/jamesjohnson/linux-4.1.6/security &&
cd /home/jamesjohnson/linux-4.1.6/ &&
make clean &&
make menuconfig &&
cd /home/jamesjohnson/linux-4.1.6/ &&
make &&
make modules_install &&
make install
