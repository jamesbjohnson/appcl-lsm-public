# appcl-lsm README.md
#
# linux security module to implement program based access control mechanisms
# Author - James Johnson
# License - GNU General Public License v3.0
#
# Final year project at Leeds Beckett University, BSc (Hons) Computer Forensics and Security
#
# AppCL-LSM is currently in the early stages of development.
#   - Currently the module initialises various security hooks through the LSM framework and
#     registers the security module with the kernel.
#
# appcl_lsm.c   
# contains the security hooks through the LSM framework.
# contains security module 'init', to register the security module with the kernel.
#
# appcl_lsm.h
# contains permission flags and masks as seen in 'richacl'.
# TODO : create appcl-lsm object
# TODO : define appcl-lsm properties and values
#
# path.c
# contains apparmor functions related to identifying the path of an application.
# TODO : move path identification to appcl_lsm.c within security hook.
#
# path.h
# contains flags required for apparmor functions (path.c)
#
# security-config
# contains the Makefile and Kconfig configuration for the kernel 'security' directory
#
# security-config/appcl-lsm-update.sh
#   - contains a bash script to automate pulling the latest repo from git, configuring the
#     kernel build and installing the new kernel on my test system (Debian VM)
#
