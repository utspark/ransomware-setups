#!/bin/bash

TSHARK_CMD="sudo tshark -i any -T fields -E header=y -E separator=, \
	    -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e udp.srcport -e udp.dstport \
	    -e frame.len -e _ws.col.Protocol -e _ws.col.Info -a duration:120"
FTRACE_CMD="sudo trace-cmd record -e syscalls -a"
HWPERF_CMD="sudo perf stat -C 1 -I 100 -a -e"

declare -A stat
# stat[1]=instructions,br_inst_retired.all_branches,avx_insts.all,block:block_rq_issue
stat[1]=mem-loads,mem-stores,cache-references,LLC-load-misses
#stat[2]=mem-loads,mem-stores,cache-references,mem_load_retired.l3_miss
# stat[3]=uops_executed_port.port_2,uops_executed_port.port_3,uops_executed_port.port_4,uops_executed_port.port_7
# stat[4]=uops_executed_port.port_0,uops_executed_port.port_1,uops_executed_port.port_5,uops_executed_port.port_6

## Run workload
hostname_ext=(${HOSTNAME#*.})
HOST="node-0.$hostname_ext"
CURR_DIR=$(pwd)
OUTDIR=$CURR_DIR/output_timed
mkdir -p $OUTDIR

# options=("mix")
options=("download" "streaming" "compute" "generic")

browser_run(){
    if [[ ! -z $CMD ]]; then
        echo "Start tracer"
        eval "$CMD &"
        #sudo trace-cmd record -e syscalls -a -o trace_${o}_${i}.dat > strace.out 2>&1 &
        tracer=$!
        sleep 5
    fi
    
    start=$EPOCHREALTIME
    ./playwrite_chrome.py $args >> logs 2>&1
    end=$EPOCHREALTIME
    duration_ms=$(echo "($end - $start) * 1000" | bc)
    echo "Duration: ${duration_ms} ms $METRIC $o" >> $OUTDIR/latency_overhead.log
    
    if [[ ! -z $CMD ]]; then
        echo "Stopping tracer"
        sudo kill -INT $tracer
        date +%M:%S
        while kill -0 $tracer 2>/dev/null; do sleep 1; done
        echo "Complete"
    fi
}

TRIES=1
METRIC=$1
# for METRIC in "SYSTEM" "NETWORK" "HARDWARE" "NONE"; do
echo "Running workload with $TRIES iterations for each option: ${options[*]} for metric $METRIC"
for i in $(seq 1 $TRIES); do
    for o in "${options[@]}"; do
        if [[ $o == "mix" ]]; then
            args="-u 1 -t 1"
        else
            args="-wl $o"
        fi
        if [[ $METRIC == "SYSTEM" ]]; then
            echo "Syscall Trace"
            OUTFNAME=browser_syscallx_${o}_$i
            CMD="$FTRACE_CMD -o trace_${o}_$i.dat > strace.out 2>&1"
            browser_run
            sleep 3
            sudo trace-cmd report -i trace_${o}_$i.dat > $OUTDIR/$OUTFNAME
        elif [[ $METRIC == "NETWORK" ]]; then
            echo "Network Trace"
            OUTFNAME=browser_netcall_${o}_$i
            CMD="$TSHARK_CMD > $OUTDIR/$OUTFNAME 2> ntrace.out"
            browser_run
        elif [[ $METRIC == "HWPERF" ]]; then
            echo "Hardware Trace"
            for s in "${stat[@]}"; do
                OUTFNAME=browser_hardware_${s}_${o}_${i}
                CMD="$HWPERF_CMD $s -o $OUTDIR/$OUTFNAME > perf.out 2>&1"
                browser_run
            done
        elif [[ $METRIC == "NONE" ]]; then
            echo "No Trace"
            CMD=""
            browser_run
        fi
    done
done
# done
