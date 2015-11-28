# AppCL - LSM README.md

Linux kernel security module to implement program based access control mechanisms

    Author - James Johnson
    License - GNU General Public License v3.0
    Copyright (C) 2015  James Johnson
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    For a full copy of the GNU General Public License, see <http://www.gnu.org/licenses/>.

Final year project at Leeds Beckett University, BSc (Hons) Computer Forensics and Security

AppCL-LSM is currently in the early stages of development.
  - appcl-lsm.org contains a development blog for updates to the public repository

# appcl_lsm.c   
contains the security hooks through the LSM framework.
contains security module 'init', to register the security module with the kernel.

# appcl_lsm.h
defines security label structure

 path.c - not compiled
 contains apparmor functions related to identifying the path of an application.
 TODO : move path identification to appcl_lsm.c within security hook.

 path.h - not compiled
 contains flags required for apparmor functions (path.c)

# security-config
contains the Makefile and Kconfig configuration for the kernel 'security' directory

# security-config/appcl-lsm-update.sh
  - contains a bash script to automate pulling the latest repo from git, configuring the kernel build and installing the new kernel on my test system (Debian VM)

