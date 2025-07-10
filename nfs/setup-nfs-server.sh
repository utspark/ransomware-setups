#!/bin/bash

sudo apt install -y nfs-kernel-server debootstrap

# Export shared directory
SHARED_DIR=$HOME/shared
sudo mkdir -p $SHARED_DIR
sudo chown nobody:nogroup $SHARED_DIR

# Add to /etc/exports
hostname_ext=(${HOSTNAME#*.})
echo "$SHARED_DIR node-0.$hostname_ext(rw,sync,no_subtree_check)" | sudo tee -a /etc/exports

# Populate NFS directory
sudo debootstrap jammy $SHARED_DIR http://archive.ubuntu.com/ubuntu/
sudo chown -R (id -u):(id -g) $SHARED_DIR

DATA_PATH=../000.zip
unzip $DATA_PATH -d $SHARED_DIR/home/ # zip file is not included; point to your test data archive
