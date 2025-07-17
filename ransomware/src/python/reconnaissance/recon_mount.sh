#!/bin/bash

set -e

# Function to safely execute commands and handle errors
safe_exec() {
    if command -v "$1" >/dev/null 2>&1; then
        "$@" 2>/dev/null || echo "Warning: Command '$*' failed or produced no output"
    else
        echo "Command '$1' not found"
    fi
}

echo "=== All Mounted Filesystems ==="
mount | column -t

# Also check /media and /mnt for common mount points
ls -la /media/ 2>/dev/null | grep -v "^total" || true
ls -la /mnt/ 2>/dev/null | grep -v "^total" || true

echo
echo "--- Partition Types ---"
echo "Filesystem breakdown:"
mount | awk '{print $5}' | sort | uniq -c | sort -nr

echo
echo "=== Block Devices ==="
safe_exec lsblk -f

echo "Analyzing each mount point..."
echo

# Get all mount points excluding special filesystems
MOUNT_POINTS=$(mount | grep -E "^/dev/|cloudlab" | awk '{print $3}' | sort)

for mp in $MOUNT_POINTS; do
    if [ -d "$mp" ]; then
        echo "--- Mount Point: $mp ---"
        df -h "$mp" | tail -1
        
        # Count files (with timeout to avoid hanging on large filesystems)
        echo -n "File Count: "
        timeout 30s find "$mp" -type f 2>/dev/null | wc -l || echo "Timeout (large filesystem)"
        
        # Count directories
        echo -n "Directory Count: "
        timeout 30s find "$mp" -type d 2>/dev/null | wc -l || echo "Timeout (large filesystem)"

        # List large and recent user files not owned by root
        sudo find "$mp" -mtime -7 ! -path "*/bin/*" ! -path "*/cache/*" ! -path "*/sbin/*" ! -path "*/lib/*" ! -path "*/var/*" -type f \( -name "*.txt" -o -name "*.pdf" ! -uid 0 \) 
        
        echo
    fi
done
