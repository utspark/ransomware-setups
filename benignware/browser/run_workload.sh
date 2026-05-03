#!/bin/bash

TSHARK_CMD="sudo tshark -i any -T fields -E header=y -E separator=, \
	    -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e udp.srcport -e udp.dstport \
	    -e frame.len -e _ws.col.Protocol -e _ws.col.Info -a duration:120"
FTRACE_CMD="sudo trace-cmd record -e syscalls -a"
HWPERF_CMD="sudo perf stat -C 1 -I 100 -a -e"

declare -A stat
# Best overall performing counters
stat[1]=instructions,br_inst_retired.all_branches,avx_insts.all,cache-references

# All tested counters: Uncomment below to run multiple perf stat runs for different counter sets
# stat[1]=instructions,br_inst_retired.all_branches,avx_insts.all,block:block_rq_issue
# stat[2]=mem-loads,mem-stores,cache-references,LLC-load-misses
# stat[3]=uops_executed_port.port_2,uops_executed_port.port_3,uops_executed_port.port_4,uops_executed_port.port_7
# stat[4]=uops_executed_port.port_0,uops_executed_port.port_1,uops_executed_port.port_5,uops_executed_port.port_6

## Run workload
CURR_DIR=$(pwd)
OUTDIR=$CURR_DIR/output
mkdir -p $OUTDIR

options=("download" "streaming" "compute" "generic" "mix")

browser_run(){
    echo "Start tracer"
    eval "$CMD &"
    tracer=$!
    sleep 5
    
    ./playwrite_chrome.py $args
    
    sudo kill -INT $tracer
    date +%M:%S
    while kill -0 $tracer 2>/dev/null; do sleep 1; done
    echo "Complete"
}

TRIES=1
METRICS=("SYSTEM" "NETWORK" "HWPERF")
for METRIC in "${METRICS[@]}"; do
    echo "Running workload with $TRIES iterations for each option: ${options[*]} for metric $METRIC"
    for i in $(seq 1 $TRIES); do
        for o in "${options[@]}"; do
            if [[ $o == "mix" ]]; then
                args="-u 3 -t 2"
            else
                args="-wl $o"
            fi
            if [[ $1 == "SYSTEM" ]]; then
                echo "Syscall Trace"
                TRACEDIR=$OUTDIR/syscall_output
                mkdir -p $TRACEDIR
                OUTFNAME=browser_syscall_${o}_$i
                CMD="$FTRACE_CMD -o trace_${o}_$i.dat > strace.out 2>&1"
                browser_run
                sleep 3
                sudo trace-cmd report -i trace_${o}_$i.dat > $TRACEDIR/$OUTFNAME
            elif [[ $1 == "NETWORK" ]]; then
                echo "Network Trace"
                TRACEDIR=$OUTDIR/netcall_output
                mkdir -p $TRACEDIR
                OUTFNAME=browser_netcall_${o}_$i
                CMD="$TSHARK_CMD > $TRACEDIR/$OUTFNAME 2> ntrace.out"
                browser_run
            elif [[ $1 == "HWPERF" ]]; then
                echo "Hardware Trace"
                TRACEDIR=$OUTDIR/hardware_output
                mkdir -p $TRACEDIR
                for s in "${stat[@]}"; do
                    OUTFNAME=browser_hardware_${s}_${o}_${i}
                    CMD="$HWPERF_CMD $s -o $TRACEDIR/$OUTFNAME > perf.out 2>&1"
                    browser_run
                done
            fi
        done
    done
done
