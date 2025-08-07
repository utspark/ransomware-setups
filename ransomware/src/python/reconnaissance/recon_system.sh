#!/bin/bash

# Function to safely execute commands and handle errors
safe_exec() {
    if command -v "$1" >/dev/null 2>&1; then
        "$@" 2>/dev/null || echo "Warning: Command '$*' failed or produced no output"
    else
        echo "Command '$1' not found"
    fi
}

echo "=== Operating System ==="
if [ -f /etc/os-release ]; then
    cat /etc/os-release
else
    safe_exec uname -a
fi

echo
echo "=== Kernel Information ==="
uname -a
echo "Kernel version: $(uname -r)"
echo "Architecture: $(uname -m)"

echo
echo "=== CPU Information ==="
if [ -f /proc/cpuinfo ]; then
    echo "CPU Model: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^ *//')"
    echo "CPU Cores: $(grep -c ^processor /proc/cpuinfo)"
    echo "CPU Architecture: $(uname -m)"
    echo
    echo "CPU Flags (first processor):"
    grep 'flags' /proc/cpuinfo | head -1 | cut -d: -f2 | tr ' ' '\n' | sort | column
fi

echo
echo "=== Memory Information ==="
free -h
echo
cat /proc/meminfo | head -10

echo
echo "=== Hardware Acceleration ==="
safe_exec lspci | grep -i vga

echo
echo "--- Hardware Video Acceleration ---"
safe_exec vainfo

echo
echo "=== Package Information ==="
echo "Package managers and installed packages:"

# Debian/Ubuntu
if command -v dpkg >/dev/null 2>&1; then
    echo "APT packages: $(dpkg --get-selections | wc -l)"
    echo "Recently installed packages:"
    grep "install " /var/log/dpkg.log 2>/dev/null | tail -5 || echo "No recent install log found"
fi

# Red Hat/CentOS/Fedora
if command -v rpm >/dev/null 2>&1; then
    echo "RPM packages: $(rpm -qa | wc -l)"
fi

echo 
echo "=== Running Services ==="
systemctl --no-pager list-units --type=service --all
systemctl --no-pager list-units --type=service --state=active
systemctl --no-pager list-units --type=service --state=running
ps aux | grep -E "(sshd|nginx|apache|mysql|postgres|docker|systemd)" | grep -v grep

echo
echo "=== Services to run on login ==="
ls /etc/init.d/
