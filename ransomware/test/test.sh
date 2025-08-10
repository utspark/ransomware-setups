#!/bin/bash
nohup bash -c 'rclone serve sftp ~/backup --user alice --pass secret --addr :2022' &> rclone.out &

mkdir -p ~/.config/rclone
cat << EOF > ~/.config/rclone/rclone.conf
[backup]
type = sftp
host = localhost
user = alice
port = 2022
pass = YxUTq1gKGsIzhD51zbw6QWu0YirGdQ
md5sum_command = md5sum
sha1sum_command = sha1sum
EOF

./test_units.py

sudo kill -9 $(ps aux | grep rclone | awk '{print $2}' | head -n 1)
rm rclone.out
