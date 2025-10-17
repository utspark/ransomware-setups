#!/bin/bash

# Setup exfil mechanism
sudo apt install rclone

rclone serve sftp ~/backup --user alice --pass secret --addr :2022 &
