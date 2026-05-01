#!/bin/bash

TSHARK_CMD="sudo tshark -i any -T fields -E header=y -E separator=, \
	    -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e udp.srcport -e udp.dstport \
	    -e frame.len -e _ws.col.Protocol -e _ws.col.Info -a duration:120"
FTRACE_CMD="sudo trace-cmd record -e syscalls -a"
HWPERF_CMD="sudo perf stat -C 1 -I 100 -a -e"

declare -A stat
stat[1]=instructions,br_inst_retired.all_branches,avx_insts.all,block:block_rq_issue
stat[2]=mem-loads,mem-stores,cache-references,LLC-load-misses
#stat[2]=mem-loads,mem-stores,cache-references,mem_load_retired.l3_miss
stat[3]=uops_executed_port.port_2,uops_executed_port.port_3,uops_executed_port.port_4,uops_executed_port.port_7
stat[4]=uops_executed_port.port_0,uops_executed_port.port_1,uops_executed_port.port_5,uops_executed_port.port_6

## Run workload
hostname_ext=(${HOSTNAME#*.})
HOST="node-0.$hostname_ext"
CURR_DIR=$(pwd)
OUTDIR=$CURR_DIR/output2
mkdir -p $OUTDIR

options=("gcc_r" "deepsjeng_r" "leela_r")
#options=("gcc_r")
source shrc

perf_run() {
        echo "Start tracer"
        eval "$CMD &"
        tracer=$!
        sleep 5
        runcpu --config=my_gcc.cfg --size=ref --action=run $o
        #sleep 200
        sudo kill -INT $tracer
        while kill -0 $tracer 2>/dev/null; do sleep 1; done
        echo "Complete"
}

TRIES=3
for o in "${options[@]}"; do
    #runcpu --config=my_gcc.cfg --size=ref --action=run $o &
    #spec_pid=$!
    #sleep 5
    for i in $(seq 1 $TRIES); do
        if [[ $1 == "SYSTEM" ]]; then
            echo "Syscall Trace"
            OUTFNAME=perf_syscall_${o}_$i
            CMD="$FTRACE_CMD -o trace_${o}_$i.dat > strace.out 2>&1"
            perf_run
            sleep 3
            sudo trace-cmd report -i trace_${o}_$i.dat > $OUTDIR/$OUTFNAME
        elif [[ $1 == "NETWORK" ]]; then
            echo "Network Trace"
            OUTFNAME=perf_netcall_${o}_$i
            CMD="$TSHARK_CMD > $OUTDIR/$OUTFNAME 2> ntrace.out"
            perf_run
        elif [[ $1 == "HARDWARE" ]]; then
            echo "Hardware Trace"
            for s in "${stat[@]}"; do
                OUTFNAME=perf_hardware_${s}_${o}_${i}
                CMD="$HWPERF_CMD $s -o $OUTDIR/$OUTFNAME > perf.out 2>&1"
                perf_run
            done
        fi
    done
    #mapfile -t ps_lines < <(ps aux | grep runcpu | grep -v grep | awk '{print $2}')
    #for pid in "${ps_lines[@]}"; do
    #    echo "Killing $o: $pid"
    #    sudo kill -SIGTERM $pid
    #    while kill -0 $pid 2>/dev/null; do sleep 1; done
    #done

done
