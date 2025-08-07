#!/bin/bash

# Function to safely execute commands and handle errors
safe_exec() {
    if command -v "$1" >/dev/null 2>&1; then
        "$@" 2>/dev/null || echo "Warning: Command '$*' failed or produced no output"
    else
        echo "Command '$1' not found"
    fi
}

echo "=== Network Interfaces ==="
ip addr show

echo
echo "=== Routing Table ==="
ip route show

echo
echo "=== DNS Configuration ==="
cat /etc/resolv.conf

echo
echo "=== Network Scan ==="
echo "Scanning local network for active IPs..."

# Get the local network range
LOCAL_NETWORK=$(ip route | grep -E "128\.105\.|144\.|166\." | grep -v default | head -1 | awk '{print $1}')

if [ -n "$LOCAL_NETWORK" ]; then
    echo "Scanning network: $LOCAL_NETWORK"
#    safe_exec nmap -sn "$LOCAL_NETWORK" 2>/dev/null | grep -E "Nmap scan report|MAC Address" || echo "nmap not available or scan failed"
    CONNECTED_HOSTS=$(nmap -sn $LOCAL_NETWORK/20 | grep -E "^Nmap" | awk '{print $5}' | head -n -1)
    CONNECTED_HOSTS=(128.105.146.94 128.105.145.244)
    count=0
    max_scan=3
    for ip in $CONNECTED_HOSTS; do
        echo "Scanning IP: $ip"
        ((count++))
        if [ "$count" -ge "$max_scan" ]; then
            break
        fi
        sudo nmap -O -p- $ip
    done
else
    echo "Could not determine local network range"
fi

echo
echo "=== Open Ports (Local) ==="
echo "--- TCP Ports ---"
safe_exec netstat -tlnp
echo
echo "--- UDP Ports ---"
safe_exec netstat -ulnp

echo
echo "=== NSLookup Tests ==="
echo "Testing DNS resolution:"
for host in google.com cloudflare.com github.com; do
    echo -n "$host: "
    nslookup "$host" 2>/dev/null | grep "Address:" | tail -1 | awk '{print $2}' || echo "DNS lookup failed"
done

echo
echo "=== Ngrok Status ==="
if command -v ngrok >/dev/null 2>&1; then
    echo "Ngrok is installed"
    ngrok version
    echo "Active tunnels:"
    curl -s http://localhost:4040/api/tunnels 2>/dev/null | grep -o '"public_url":"[^"]*"' | cut -d'"' -f4 || echo "No active tunnels or ngrok not running"
else
    echo "Ngrok not installed"
fi

echo
echo "=== Additional Network Information ==="
echo "--- Active Connections ---"
safe_exec netstat -i

echo
echo "--- ARP Table ---"
safe_exec arp -a

echo
echo "--- Firewall Status ---"
sudo ufw status 2>/dev/null || safe_exec iptables -L -n 2>/dev/null | head -20 || echo "Could not check firewall status"
