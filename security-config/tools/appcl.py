# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
# AppCL - LSM
# Python tool to manage the security labelling of files/directories
# for the AppCL LSM access control module.
# Help:
#      python appcl.py -h/--help
#
#    DESCRIPTION
#    The appcl.py script handles the extended attributes associated with the
#    AppCL LSM security module.
#    The setfattr and getfattr system utilities can also be used to manage
#    extended attributes. If using these utilities the appcl security namespace
#    must be specified [-n security.appcl] for AppCL LSM to process and
#    enforce the attribute.
#    The attr package is still required for appcl.py functionality.
#
#    EXAMPLE USAGE
#    Set Attributes:
#        Directory - python appcl.py --dir <input-directory> --set <xattr-value>
#        File - python appcl.py --file <input-file> --set <xattr-value>
#    Get Attributes:
#        Directory - python appcl.py --dir <input-directory> --get
#        File - python appcl.py --file <input-file> --get
#    Remove Attributes:
#        Directory - python appcl.py --dir <input-directory> --remove
#        File - python appcl.py --file <input-file> --remove
#    Build mode:
#        Directory - python appcl.py --dir <input-directory> --build
#        File - python appcl.py --file <input-file> --build
#
#    OPTIONS
#    -f file, --file=file
#        Specifies a file input.
#    -d directory, --dir=directory
#        Specifies a directory input.
#    -r, --walk
#    Recursively walk through directory. Only valid on directory input (-d, --dir).
#    -v, --set
#        Sets the new AppCL LSM value of the entended attribute,
#        and associated permissions.
#    -g, --get
#        View the AppCL LSM stored extended attribute for
#        file/directory contents.
#    -x, --remove
#        Remove the AppCL LSM extended attribute and associated
#        permission entries.
#    -b, --build
#        Build the AppCL attributes. Knowledge of the AppCL attribute
#        format is not required when using build mode. The path for a
#        program is also not required as it locates the path of the
#        binary applications from the program name.
#    -h, --help
#        Help page
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
# Linux kernel security module to implement program based access control mechanisms
#    Author - James Johnson
#    License - GNU General Public License v3.0
#    Copyright (C) 2016  James Johnson
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#    For a full copy of the GNU General Public License, see <http://www.gnu.org/licenses/>.
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *

import sys, getopt
import subprocess
import os
from sys import version_info

def main(argv):
        NL = '\n'
        # Default command options
        SET = 'setfattr'
        GET = 'getfattr'
        APPCL_NS = 'security.appcl'
        GET_BIN = 'whereis -b '

        # 'dir' flag indicates -d arg and directory input
        # 'file' flag indicates -f arg and file input
        fileflag = ''

        # 'set' flag by default sets xattr
        # 'get' flag indicates -g arg and retrives attributes
        # 'rm' flag indicates -x arg and attributes to be removed
        opflag = ''
        recflag = 0

        inputdir = ''
        inputvalue = ''

        # build VARS
        g_prog_input = ''
        g_perm_input = ''
        g_valid_perm = 0
        g_deny_flag = 0
        g_deny_set = 0
        g_end_build = 0

        py3 = version_info[0] > 2;
        invalid_chars = [';', '/', ':', '*', '?', '"', '<', '>', '|', '&', ' ']

        try:
            opts, args = getopt.getopt(argv, "hd:f:v:gxbr", ["help", "dir=", "file=", "set=", "get", "remove", "build", "walk"])
        except getopt.GetoptError:
            print '\nError: please read the help page for usage'
            print '\t python appcl.py --help\n'
            sys.exit(2)
        for opt, arg in opts:
            # '-h' arg specifies help page
            if opt in ('-h', "--help"):
                print '\nNAME'
                print '\tappcl.py - manage AppCL LSM security policies'
                print '\nSYNOPSIS'
                print '\tappcl.py [FILE] ... [OPTION] ...'
                print '\tappcl.py [DIRECTORY] ... [OPTION] ...'
                print '\nDESCRIPTION'
                print '\tThe appcl.py script handles the extended attributes \n\tassociated with the AppCL LSM security module.'
                print '\tThe setfattr and getfattr system utilities can also \n\tbe used to manage extended attributes.'
                print '\tIf using these utilities the appcl security namespace \n\tmust be specified [-n security.appcl]'
                print '\tfor AppCL LSM to process and enforce the attribute.'
                print '\tThe attr package is still required for appcl.py. \n'
                print 'EXAMPLE USAGE'
                print '\tSet Attributes:'
                print '\tDirectory -\n\tpython appcl.py --dir <input-directory> --set <xattr-value>'
                print '\tFile - \n\tpython appcl.py --file <input-file> --set <xattr-value> \n'
                print '\tGet Attributes:'
                print '\tDirectory - \n\tpython appcl.py --dir <input-directory> --get'
                print '\tFile - \n\tpython appcl.py --file <input-file> --get \n'
                print '\tRemove Attributes:'
                print '\tDirectory - \n\tpython appcl.py --dir <input-directory> --remove'
                print '\tFile - \n\tpython appcl.py --file <input-file> --remove \n'
                print '\tBuild Mode:'
                print '\tDirectory - \n\tpython appcl.py --dir <input-directory> --build'
                print '\tFile - \n\tpython appcl.py --file <input-file> --build \n'
                print 'OPTIONS'
                print '\t-f file, --file=file'
                print '\tSpecifies a file input. \n'
                print '\t-d directory, --dir=directory'
                print '\tSpecifies a directory input. \n'
                print '\t-r, --walk'
                print '\tRecursively walk through directory. \n\tOnly valid on directory input (-d, --dir). \n'
                print '\t-v, --set'
                print '\tSets the new AppCL LSM value of the entended attribute, \n\tand associated permissions. \n'
                print '\t-g, --get'
                print '\tView the AppCL LSM stored extended attribute for \n\tfile/directory contents. \n'
                print '\t-x, --remove'
                print '\tRemove the AppCL LSM extended attribute and associated \n\tpermission entries. \n'
                print '\t-b, --build'
                print '\tBuild the AppCL attributes. Knowledge of the AppCL attribute'
                print '\tformat is not required when using build mode. The path for a'
                print '\tprogram is also not required as it locates the path of the'
                print '\tbinary applications from the program name.\n'
                print '\t-h, --help'
                print '\tHelp page \n'
                print '\nAUTHOR'
                print '\tWritten by James Johnson.'
                print '\tFor more information visit: <http://appcl-lsm.org/>'
                print '\nREPORTING BUGS'
                print '\tReport AppCL LSM/appcl.py bugs: <http://appcl-lsm.org/contact/>'
                print '\nCOPYRIGHT'
                print '\tCopyright (C) 2016: License GNU General Public License v3.0.'
                print '\tThis program is free software: you can redistribute it and/or'
                print '\tmodify it under the terms of the GNU General Public License as'
                print '\tpublished by the Free Software Foundation, either version 3 of'
                print '\tthe License, or (at your option) any later version.'
                print '\tThis program is distributed in the hope that it will be useful,'
                print '\tbut WITHOUT ANY WARRANTY; without even the implied warranty of'
                print '\tMERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the'
                print '\tGNU General Public License for more details.'
                print '\tFor a full copy of the GNU General Public License, see \n\t<http://www.gnu.org/licenses/>.'
                sys.exit()
            # '-b' arg specifies build mode
            elif opt in ('-b', '--build'):
                print '\n*** BUILD MODE ***'
                while True:
                    if py3:
                        g_prog_input = input("\nPlease enter the program name: ")
                    else:
                        g_prog_input = raw_input("\nPlease enter the program name: ")

                    for c in g_prog_input:
                        if c.isalnum():
                            continue
                        else:
                            for i in invalid_chars:
                                if (i == c):
                                    print 'Please enter a valid application/program name.'
                                    sys.exit(2)

                    command = GET_BIN+g_prog_input
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
                    output = process.communicate()

                    print output[0]
                    path_array = output[0].split(" ")

                    g_valid_perm = 0
                    while (g_valid_perm == 0):
                        if py3:
                            g_perm_input = input("Please enter the permissions to grant the program: \n" + path_array[0] + "\n\n[r]ead, [w]rite, e[x]ecute: ")
                        else:
                            g_perm_input = raw_input("Please enter the permissions to grant the program: \n" + path_array[0] + "\n\n[r]ead, [w]rite, e[x]ecute: ")

                        for char in g_perm_input:
                            if (len(g_perm_input) > 4):
                                g_valid_perm = 0
                                print '\nPlease enter valid permissions.'
                                break;
                            if (char == "r"):
                                g_valid_perm = 1
                            elif (char == "w"):
                                g_valid_perm = 1
                            elif (char == "x"):
                                g_valid_perm = 1
                            else:
                                g_valid_perm = 0
                                print '\nPlease enter valid permissions.'
                                break;

                    path_array.pop(0)

                    for path in path_array:
                        path = path.strip()
                        inputvalue = inputvalue+path+":"+g_perm_input+";"
                        inputvalue = inputvalue.strip()

                    print NL+inputvalue

                    g_valid_perm = 0
                    while (g_valid_perm == 0):
                        if py3:
                            deny_input = input("\nWould you like to add another program to the attribute? [Y]es / [N]o: ")
                        else:
                            deny_input = raw_input("\nWould you like to add another program to the attribute? [Y]es / [N]o: ")
                        if (deny_input == "Y" or deny_input == "y"):
                            g_valid_perm = 1
                        elif (deny_input == "N" or deny_input == "n"):
                            g_valid_perm = 1
                            g_end_build = 1

                    if (g_end_build == 1):
                        break

                g_valid_perm = 0
                if (g_deny_flag == 0):
                    while (g_valid_perm == 0):
                        if py3:
                            deny_input = input("\nWould you like to DENY all other programs by default? [Y]es / [N]o: ")
                        else:
                            deny_input = raw_input("\nWould you like to DENY all other programs by default? [Y]es / [N]o: ")
                        if (deny_input == "Y" or deny_input == "y"):
                            g_valid_perm = 1
                            g_deny_flag = 1
                        elif (deny_input == "N" or deny_input == "n"):
                            g_valid_perm = 1

                if (g_deny_set == 0):
                    if (g_deny_flag == 1):
                        inputvalue = inputvalue+"deny:-;"
                        inputvalue = inputvalue.strip()
                        g_deny_set = 1

                print NL+inputvalue+NL
                opflag = 'set'

            # '-d' arg specifies directory
            elif opt in ("-d", "--dir"):
                inputdir = arg
                fileflag = 'dir'
            # '-f' arg specifies file
            elif opt in ("-f", "--file"):
                inputdir = arg
                fileflag = 'file'
            # '-r' arg specifies recursive through directory
            elif opt in ('-r', "--walk"):
                recflag = 1
            # '-v' arg specifies xattr value to set
            elif opt in ("-v", "--set"):
                inputvalue = arg
                opflag = 'set'
            # '-g' arg specifies retrieve xattr value
            elif opt in ("-g", "--get"):
                opflag = 'get'
            # '-g' arg specifies remove xattr value
            elif opt in ("-x", "--remove"):
                opflag = 'rm'
            else:
                print '\nError: please read the help page for usage'
                print '\t python appcl.py --help\n'
                sys.exit(2)

        print 'Input directory: ', inputdir
        if opflag == 'set':
            print 'Extended attribute value: ', inputvalue

        if fileflag == 'dir':
            if (recflag == 0):
                if opflag == 'rm':
                    for filename in os.listdir(inputdir):
                        subprocess.call([SET, "-x", APPCL_NS, inputdir+filename])
                        print 'File attribute removed: ', filename
                elif opflag == 'get':
                    for filename in os.listdir(inputdir):
                        subprocess.call([GET, "-n", APPCL_NS, inputdir+filename])
                        print 'File attribute: ', filename
                elif opflag == 'set':
                    for filename in os.listdir(inputdir):
                        subprocess.call([SET, "-n", APPCL_NS, "-v", inputvalue, inputdir+filename])
                        print 'File attribute set: ', filename
            else:
                if opflag == 'rm':
                    for root, subdirs, files in os.walk(inputdir):
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            subprocess.call([SET, "-x", APPCL_NS, filepath])
                            print 'File attribute removed: ', filepath
                elif opflag == 'get':
                    for root, subdirs, files in os.walk(inputdir):
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            subprocess.call([GET, "-n", APPCL_NS, filepath])
                            print 'File attribute: ', filepath
                elif opflag == 'set':
                    for root, subdirs, files in os.walk(inputdir):
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            subprocess.call([SET, "-n", APPCL_NS, "-v", inputvalue, filepath])
                            print 'File attribute set: ', filepath
        elif fileflag == 'file':
            if opflag == 'rm':
                subprocess.call([SET, "-x", APPCL_NS, inputdir])
                print 'File attribute removed: ', inputdir
            elif opflag == 'get':
                subprocess.call([GET, "-n", APPCL_NS, inputdir])
            elif opflag == 'set':
                subprocess.call([SET, "-n", APPCL_NS, "-v", inputvalue, inputdir])
                print 'File attribute set: ', inputdir

if __name__ == "__main__":
        main(sys.argv[1:])
