#!/bin/bash

sudo apt install -y libtool

cd filebench/
libtoolize
aclocal
autoheader
automake --add-missing
autoconf

./configure
make
sudo make install

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
