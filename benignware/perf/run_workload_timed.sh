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
OUTDIR=$CURR_DIR/output_timed
mkdir -p "$OUTDIR"
cd cpu2017

options=("gcc_r" "deepsjeng_r" "leela_r")
source shrc

perf_run(){
    if [[ -n "$CMD" ]]; then
        echo "Start tracer"
        eval "$CMD &"
        tracer=$!
        sleep 5
    fi

    start=$EPOCHREALTIME
    runcpu --config=my_gcc.cfg --size=train --action=run "$o" >> ../logs 2>&1
    end=$EPOCHREALTIME
    duration_ms=$(echo "($end - $start) * 1000" | bc)
    echo "Duration: ${duration_ms} ms $METRIC $o" >> "$OUTDIR/latency_overhead.log"

    if [[ -n "$CMD" ]]; then
        echo "Stopping tracer"
        sudo kill -INT "$tracer"
        while kill -0 "$tracer" 2>/dev/null; do sleep 1; done
        echo "Complete"
    fi
}

TRIES=1
METRICS=("SYSTEM" "NETWORK" "HWPERF" "NONE")
for METRIC in "${METRICS[@]}"; do
    echo "Running workload with $TRIES iterations for each option: ${options[*]} for metric $METRIC"
    for i in $(seq 1 $TRIES); do
        for o in "${options[@]}"; do
            if [[ $METRIC == "SYSTEM" ]]; then
                echo "Syscall Trace"
                OUTFNAME=perf_syscall_${o}_$i
                CMD="$FTRACE_CMD -o trace_${o}_$i.dat > strace.out 2>&1"
                perf_run
                sleep 3
                sudo trace-cmd report -i trace_${o}_$i.dat > "$OUTDIR/$OUTFNAME"
            elif [[ $METRIC == "NETWORK" ]]; then
                echo "Network Trace"
                OUTFNAME=perf_netcall_${o}_$i
                CMD="$TSHARK_CMD > $OUTDIR/$OUTFNAME 2> ntrace.out"
                perf_run
            elif [[ $METRIC == "HWPERF" ]]; then
                echo "Hardware Trace"
                for s in "${stat[@]}"; do
                    OUTFNAME=perf_hardware_${s}_${o}_$i
                    CMD="$HWPERF_CMD $s -o $OUTDIR/$OUTFNAME > perf.out 2>&1"
                    perf_run
                done
            elif [[ $METRIC == "NONE" ]]; then
                echo "No Trace"
                CMD=""
                perf_run
            fi
        done
    done
done
cd ..