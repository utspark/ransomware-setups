#!/usr/bin/python3

import os
import time
import ctypes
import sys
import socket
import subprocess

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

def invoke_netcall(port=54321, message="PHASE_MARKER"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(message.encode(), ("127.0.0.1", port))
    finally:
        sock.close()

def invoke_syscall(target_pid, target_fd=1):

    if not os.path.exists(f"/proc/{target_pid}"):
        print(f"Error: PID {target_pid} does not exist!")
        sys.exit(1)

	# Step 1: Open pidfd for the target
    pidfd = sys_pidfd_open(target_pid)

    # Step 2: Duplicate child's stdout (fd=1)
    dup_fd = sys_pidfd_getfd(pidfd, target_fd)

    # Step 3: Write to child's stdout from parent
    os.write(dup_fd, b"[Parent] Hello via pidfd_getfd!\n")

    # Cleanup
    os.close(dup_fd)
    os.close(pidfd)

def get_process_uptime(pid: int) -> float:
    with open("/proc/uptime", "r") as f:
        uptime_seconds = float(f.readline().split()[0])

    with open(f"/proc/{pid}/stat", "r") as f:
        fields = f.readline().split()
        start_time_jiffies = int(fields[22 - 1])  # stat fields are 1-based

    clock_ticks = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
    start_time_seconds = start_time_jiffies / clock_ticks
    return uptime_seconds - start_time_seconds

def get_perf_pid():
	pid = subprocess.check_output("ps aux | grep 'sudo perf' | grep -v grep | awk '{print $2}' | head -n 1", shell=True,text=True).strip()
	return pid

def invoke_perfmark(file):
    print("Perf marker")
    pid = get_perf_pid()
    elapsed_time = get_process_uptime(pid)
    with open(f"../../outputs/perf_results/{file}", 'a') as f:
        f.write(f"{str(elapsed_time)}\n")

def invoke_marker(mark):
    if isinstance(mark, int):
        invoke_syscall(mark)
        invoke_netcall()
    elif isinstance(mark, str):
        invoke_perfmark(mark)

if __name__ == "__main__":
    try:
        invoke_syscall(int(sys.argv[1]))
        invoke_netcall()
    except ValueError:
        invoke_perfmark(sys.argv[1])


