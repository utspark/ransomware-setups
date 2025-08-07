#!/bin/bash

sudo apt install -y nfs-common

hostname_ext=(${HOSTNAME#*.})
sudo mount node-1.$hostname_ext:$HOME/shared /mnt

# Setup exfil mechanism
sudo apt install -y rclone

mkdir -p $HOME/.config/rclone
cp rclone_conf $HOME/.config/rclone/rclone.conf # Edit rclone_config AWS/local server appropriately
sed -i "/^host = [a-z0-9\.-]/c\host = node-2.$hostname_ext" $HOME/.config/rclone/rclone.conf

# Setup node to run ransomware
sudo apt install -y python3 python3-pip trace-cmd
pip3 install pycryptodome rclone-python
#pip3 install -r requirements.txt

