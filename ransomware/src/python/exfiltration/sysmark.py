#!/usr/bin/python3

import os
import time
import ctypes
import sys

# Syscall numbers for x86_64 (Linux 5.15)
__NR_pidfd_open = 434
__NR_pidfd_getfd = 438

# Load the libc syscall function
libc = ctypes.CDLL("libc.so.6", use_errno=True)
syscall = libc.syscall
syscall.restype = ctypes.c_long

def sys_pidfd_open(pid, flags=0):
    res = syscall(__NR_pidfd_open, pid, flags)
    if res < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"pidfd_open failed: {os.strerror(errno)}")
    return res

def sys_pidfd_getfd(pidfd, targetfd, flags=0):
    res = syscall(__NR_pidfd_getfd, pidfd, targetfd, flags)
    if res < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"pidfd_getfd failed: {os.strerror(errno)}")
    return res

def create_child():
    """Forks a child process that keeps stdout open."""
    pid = os.fork()
    if pid == 0:
        print(f"[Child] PID={os.getpid()} alive, stdout open.")
        while True:
            time.sleep(1)
    return pid

def invoke_syscall(target_pid, target_fd):
    #child_pid = create_child()
    #print(f"[Parent] Spawned child with PID={child_pid}")
    #time.sleep(1)

    if not os.path.exists(f"/proc/{target_pid}"):
        print(f"Error: PID {target_pid} does not exist!")
        sys.exit(1)

    #print(f"[Parent] Attaching to PID={target_pid}, target_fd={target_fd}")
	# Step 1: Open pidfd for the target
    pidfd = sys_pidfd_open(target_pid)
    #print(f"[Parent] pidfd={pidfd}")

    # Step 2: Duplicate child's stdout (fd=1)
    dup_fd = sys_pidfd_getfd(pidfd, target_fd)
    #print(f"[Parent] Duplicated child's stdout -> local fd={dup_fd}")

    # Step 3: Write to child's stdout from parent
    os.write(dup_fd, b"[Parent] Hello via pidfd_getfd!\n")

    # Cleanup
    os.close(dup_fd)
    os.close(pidfd)
    #print("[Parent] Done.")

    #while True:
    #    time.sleep(1)

if __name__ == "__main__":
    invoke_syscall(int(sys.argv[1]), int(sys.argv[2]))


