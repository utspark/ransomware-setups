#!/bin/bash
sudo apt update
sudo apt install vainfo snapd nmap rclone -y
sudo apt install python3 python3-pip -y
sudo snap install ngrok
pip3 install -r requirements.txt

echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
