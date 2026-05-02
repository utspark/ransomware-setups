#!/bin/bash

sudo apt install -y libtool flex bison

cd filebench/
libtoolize
aclocal
autoheader
automake --add-missing
autoconf

./configure
make
sudo make install

# Apply patch to fix filebench hanging issue
git apply ../benchmark_settings.patch
cd -

echo 0 | sudo tee /proc/sys/kernel/randomize_va_space