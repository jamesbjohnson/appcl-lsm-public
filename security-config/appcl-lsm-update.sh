#!/bin/bash
# update AppCL LSM in security directory of linux kernel

HOME="/home/jamesjohnson"

cd $HOME/appcl-lsm/ &&
git pull &&
cp -avr $HOME/appcl-lsm $HOME/linux-4.3/security/ &&
rm $HOME/linux-4.3/security/Makefile &&
rm $HOME/linux-4.3/security/Kconfig &&
cp $HOME/appcl-lsm/security-config/Makefile $HOME/linux-4.3/security &&
cp $HOME/appcl-lsm/security-config/Kconfig $HOME/linux-4.3/security &&
cd $HOME/linux-4.3/ &&
make clean &&
make menuconfig &&
make && make modules_install && make install
