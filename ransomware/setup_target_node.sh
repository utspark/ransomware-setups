#!/bin/bash
set -e  # Exit on error

# Detect OS family
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_FAMILY=$ID_LIKE
else
    echo "Cannot detect OS type. /etc/os-release not found."
    exit 1
fi
echo "Detected OS: $OS (Family: $OS_FAMILY)"

if [[ "$OS_FAMILY" =~ "debian" || "$OS" =~ "debian" || "$OS" =~ "ubuntu" ]]; then
    echo "Running Debian/Ubuntu install..."
    sudo apt update
    sudo apt-get install -y ca-certificates apt-transport-https gnupg2 curl inotify-tools
    sudo apt install -y vainfo snapd nmap rclone
    sudo apt install -y python3 python3-pip
    sudo snap install ngrok

elif [[ "$OS_FAMILY" =~ "rhel" || "$OS" =~ "rhel" || "$OS" =~ "fedora" || "$OS" =~ "centos" ]]; then
    echo "Running RHEL/Fedora/CentOS install..."
    sudo dnf update -y
    sudo dnf install -y ca-certificates gnupg2 curl inotify-tools libva-utils snapd nmap epel-release
    sudo dnf install -y rclone python3 python3-pip
    sudo systemctl enable --now snapd.socket
    sudo ln -s /var/lib/snapd/snap /snap
    sudo snap install ngrok

else
    echo "Unsupported OS: $OS"
    exit 1
fi

pip3 install -r requirements.txt
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
