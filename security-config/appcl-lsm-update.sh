#!/bin/bash
# update AppCL LSM in security directory of linux kernel

HOME="/home/jamesjohnson"
#HOME="/root"
LINUX_SRC="linux-4.3"
#LINUX_SRC="linux-4.5"

cd $HOME/appcl-lsm/ &&
git pull &&
cp -avr $HOME/appcl-lsm $HOME/$LINUX_SRC/security/ &&
rm $HOME/$LINUX_SRC/security/Makefile &&
rm $HOME/$LINUX_SRC/security/Kconfig &&
cp $HOME/appcl-lsm/security-config/Makefile $HOME/$LINUX_SRC/security &&
cp $HOME/appcl-lsm/security-config/Kconfig $HOME/$LINUX_SRC/security &&
cd $HOME/$LINUX_SRC/ &&
make clean &&
make menuconfig &&
make && make modules_install && make install
