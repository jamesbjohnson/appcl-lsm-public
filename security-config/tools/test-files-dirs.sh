#!/bin/bash
# add test files and directories

HOME="/home/jamesjohnson"

cd $HOME
echo "root-testfile-content" > $HOME/testfile1 &&
echo "root-testfile-content" > $HOME/testfile2 &&
mkdir testdir && cd testdir &&
echo "testdir-testdirfile-content" > testdirfile1 &&
echo "testdir-testdirfile-content" > testdirfile2 &&
echo "testdir-testdirfile-content" > testdirfile3 &&
echo "testdir-testdirfile-content" > testdirfile4 &&
mkdir testsubdir && cd testsubdir &&
echo "testsubdir-testsubdirfile-content" > testsubdirfile1 &&
echo "testsubdir-testsubdirfile-content" > testsubdirfile2 &&
echo "testsubdir-testsubdirfile-content" > testsubdirfile3 &&
echo "testsubdir-testsubdirfile-content" > testsubdirfile4 &&
mkdir testsub-subdir && cd testsub-subdir &&
echo "testsub-subdir-testsub-subdirfile-content" > testsub-subdirfile1 &&
echo "testsub-subdir-testsub-subdirfile-content" > testsub-subdirfile1
