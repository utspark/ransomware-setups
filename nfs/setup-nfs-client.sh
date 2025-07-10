#!/bin/bash

sudo apt install -y nfs-common

hostname_ext=(${HOSTNAME#*.})
sudo mount node-1.$hostname_ext:$HOME/shared /mnt
