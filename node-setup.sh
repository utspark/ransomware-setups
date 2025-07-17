#!/bin/bash
ARCH=$(dpkg --print-architecture)
OS=$(lsb_release -cs)

# Install Docker
sudo apt-get update
sudo apt-get install -y ca-certificates apt-transport-https gnupg2 curl lsb-release htop fish inotify-tools cpufrequtils python3

# Add PPA repos
sudo mkdir -m 0755 -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch="$ARCH" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
 $OS stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin
sudo apt-get install -y docker.io docker-compose-plugin # rerunning this line installs docker correctly?

# Allow docker commands without sudo
sudo usermod -aG docker $USER
sudo rm /etc/containerd/config.toml
sudo systemctl restart containerd

#Install perf tools
sudo apt install -y linux-tools-common linux-tools-generic linux-tools-$(uname -r) cpulimit
echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid
echo 0 | sudo tee /proc/sys/kernel/nmi_watchdog

# Disable DVFS
sudo modprobe acpi-cpufreq
echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
echo "1" | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
echo "GOVERNOR=\"performance\"" | sudo tee /etc/default/cpufrequtils
echo "1" | sudo tee /sys/devices/system/cpu/cpu*/cpuidle/state*/disable
sudo systemctl disable ondemand
sudo systemctl daemon-reload
sudo systemctl enable cpufrequtils

sudo chsh -s /usr/bin/fish psahu

echo "Close shell and reopen to use docker commands without sudo"
