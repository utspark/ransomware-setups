#!/bin/bash
TSHARK_CMD="sudo tshark -l -i any -t e -T fields -E separator=, \
	    -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e udp.srcport -e udp.dstport \
	    -e frame.len -e _ws.col.Protocol -e _ws.col.Info"
FTRACE_CMD="sudo stdbuf -oL trace-cmd stream -e syscalls -a"
HWPERF_CMD="sudo perf stat -C 1 -I 100 -a -e mem-loads,mem-stores,cache-references,LLC-load-misses -x, --log-fd 1"

MAWK_SCRIPT='
function get_timestamp() {
    getline < "/proc/uptime"
    t = $1
    close("/proc/uptime")
    return t
}

BEGIN { 
print "gawk started, mode=" mode ", base=" base ", fname=" fname > "/dev/stdout" 
metrics = 0
size = 0
}
{
    if (mode == "sys") {
        if (match($2, /\][0-9]+/)) {
            timestamp_ns = substr($2, RSTART + 1, RLENGTH - 1)
            window = int(timestamp_ns / 100000000)
            full_time = $2
        } else { next }
    } else if (mode == "net" || mode == "perf") {
        if (match($1, /[0-9]+\.[0-9]/)) {
            window = substr($1, RSTART, RLENGTH)
            full_time = $1
        } else { next }
    }
    if (window != prev) {
        now = get_timestamp()
        if (prev != "") {
            duration = (now - start_time) * 1000
            close(fn)
            system("mv " fn " " base "/" fname "_" prev ".txt" " &")
            printf("[Metrics] Window %s(%s): %.3f ms. Counted %d lines, Size: %d bytes\n", prev, full_time, duration, metrics, size) > (base "/metrics.log")
            fflush(base "/metrics.log")
            metrics = 0
            size = 0
        }
        start_time = now
        fn = base "active_" window ".tmp"
        prev = window
    }
    metrics++
    size += length($0) + 1
    print $0 >> fn
    fflush(fn)
}
END {
    if (fn != "") {
        close(fn)
        system("mv " fn " " base "/" fname "_" prev ".txt" " &")
        printf("[Metrics] Window %s(%s): %.3f ms. Counted %d lines, Size: %d bytes\n", prev, full_time, duration, metrics, size) > (base "/metrics.log")
        fflush(base "/metrics.log")
    }
}'

## Run workload
CURR_DIR=$(pwd)
OUTDIR=$CURR_DIR/output_streaming
mkdir -p $OUTDIR

options=("compute")
# options=("download" "streaming" "compute" "generic")

MOUNT_POINT="/mnt/ramdisk"
DISK_SIZE="1G"

setup_ramdisk() {
    # 1. Check if already mounted
    if grep -qs "$MOUNT_POINT" /proc/mounts; then
        echo "Ramdisk found at $MOUNT_POINT. Cleaning files..."
        # Clean the contents without removing the directory itself
        sudo rm -rf "${MOUNT_POINT:?}"/*
        echo "Cleanup complete."
    else
        echo "Ramdisk not detected. Creating fresh at $MOUNT_POINT..."
        sudo mkdir -p "$MOUNT_POINT"
        sudo mount -t tmpfs -o size="$DISK_SIZE" tmpfs "$MOUNT_POINT"
        echo "Created $DISK_SIZE ramdisk."
    fi
}

cleanup_ramdisk() {
    if grep -qs "$MOUNT_POINT" /proc/mounts; then
        echo "Unmounting ramdisk at $MOUNT_POINT..."
        sudo umount "$MOUNT_POINT"
        # Optional: Remove the mount point directory
        sudo rmdir "$MOUNT_POINT"
        echo "Unmount complete."
    else
        echo "No ramdisk found at $MOUNT_POINT to unmount."
    fi
}

browser_run(){
    if [[ ! -z $CMD ]]; then
        echo "Start tracer"
        eval "$CMD" &
        STREAM_PID=$!
        sleep 1
    fi
    
    
    start=$EPOCHREALTIME
    ./playwrite_chrome.py -wl $o >> logs 2>&1
    end=$EPOCHREALTIME
    duration_ms=$(echo "($end - $start) * 1000" | bc)
    echo "Duration: ${duration_ms} ms" >> $OUTDIR/latency_overhead.log
    
    if [[ ! -z $CMD ]]; then
        sleep 2
        sudo pkill -INT $TRACER_PROCESS
        while ls /mnt/ramdisk/*.tmp >/dev/null 2>&1; do
            # Optional: Print how many lines are left in the current tmp file to show progress
            # wc -l /mnt/ramdisk/*.tmp
            sleep 0.5
        done
        sudo kill -INT -"$STREAM_PID"
        echo "Complete"
    fi
}

setup_ramdisk
TRIES=1
METRICS=("SYSTEM" "NETWORK" "HWPERF" "NONE")
for METRIC in "${METRICS[@]}"; do
    echo "Running workload with $TRIES iterations for each option: ${options[*]} for metric $METRIC"
    for i in $(seq 1 $TRIES); do
        for o in "${options[@]}"; do
            if [[ $METRIC == "SYSTEM" ]]; then
                echo "Syscall Trace $o" >> $OUTDIR/latency_overhead.log
                OUTFNAME=browser_syscall_${o}_$i
                TRACE_CMD="$FTRACE_CMD"
                TRACER_PROCESS="trace-cmd"
                MODE="sys"
            elif [[ $METRIC == "NETWORK" ]]; then
                echo "Network Trace $o" >> $OUTDIR/latency_overhead.log
                OUTFNAME=browser_netcall_${o}_$i
                TRACE_CMD="$TSHARK_CMD"
                TRACER_PROCESS="tshark"
                MODE="net"
            elif [[ $METRIC == "HWPERF" ]]; then
                echo "Hardware Performance Trace $o" >> $OUTDIR/latency_overhead.log
                OUTFNAME=browser_hwperf_${o}_$i
                TRACE_CMD="$HWPERF_CMD"
                TRACER_PROCESS="perf"
                MODE="perf"
            elif [[ $METRIC == "NONE" ]]; then
                echo "No Trace $o" >> $OUTDIR/latency_overhead.log
                TRACE_CMD=""
            fi
            if [[ ! -z $TRACE_CMD ]]; then
                CMD="($TRACE_CMD | mawk -W interactive -v fname=$OUTFNAME -v base=$MOUNT_POINT -v mode=$MODE '$MAWK_SCRIPT') 2>>$OUTDIR/gawk.err"
            fi
            browser_run
            if [[ ! -z $TRACE_CMD ]]; then
                mkdir -p $OUTDIR/${METRIC}_${o}_$i
                mv $MOUNT_POINT/* $OUTDIR/${METRIC}_${o}_$i/
            fi
        done
    done
done
