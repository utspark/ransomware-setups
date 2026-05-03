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

declare -A cmds
declare -A exts
options=("7zip" "Gzip" "Bzip2" "zStd" "Zip")
cmds=(["7zip"]="7z a" ["Gzip"]="tar -czf" ["Bzip2"]="tar -cjf" ["zStd"]="tar --zstd -cf" ["Zip"]="zip -q -r")
exts=(["7zip"]="7z" ["Gzip"]="tr.gz" ["Bzip2"]="tar.bz2" ["zStd"]="tar.zst" ["Zip"]="zip")

compressor_run(){
    echo "Start tracer"
    eval "$CMD &"
    tracer=$!
    sleep 5
    
    $1 data.$2 /mnt/home/000/ >> logs 2>&1
    
    sudo kill -INT $tracer
    date +%M:%S
    while kill -0 $tracer 2>/dev/null; do sleep 1; done
    echo "Complete"
    rm data.$2
}

TRIES=1
METRICS=("SYSTEM" "NETWORK" "HWPERF")
for METRIC in "${METRICS[@]}"; do
    echo "Running workload with $TRIES iterations for each option: ${options[*]} for metric $METRIC"
    for i in $(seq 1 $TRIES); do
        for o in "${options[@]}"; do
            if [[ $METRIC == "SYSTEM" ]]; then
                echo "Syscall Trace"
                TRACEDIR=$OUTDIR/syscall_output
                mkdir -p $TRACEDIR
                OUTFNAME=compression_syscall_${o}_$i
                CMD="$FTRACE_CMD -o trace_${o}_$i.dat > strace.out 2>&1"
                compressor_run "${cmds[$o]}" "${exts[$o]}"
                sleep 3
                sudo trace-cmd report -i trace_${o}_$i.dat > $TRACEDIR/$OUTFNAME
            elif [[ $METRIC == "NETWORK" ]]; then
                echo "Network Trace"
                TRACEDIR=$OUTDIR/netcall_output
                mkdir -p $TRACEDIR
                OUTFNAME=compression_netcall_${o}_$i
                CMD="$TSHARK_CMD > $TRACEDIR/$OUTFNAME 2> ntrace.out"
                compressor_run "${cmds[$o]}" "${exts[$o]}"
            elif [[ $METRIC == "HWPERF" ]]; then
                echo "Hardware Trace"
                TRACEDIR=$OUTDIR/hardware_output
                mkdir -p $TRACEDIR
                for s in "${stat[@]}"; do
                    OUTFNAME=compression_hardware_${s}_${o}_$i
                    CMD="$HWPERF_CMD $s -o $TRACEDIR/$OUTFNAME > perf.out 2>&1"
                    compressor_run "${cmds[$o]}" "${exts[$o]}"
                done
            fi
        done
    done
done
