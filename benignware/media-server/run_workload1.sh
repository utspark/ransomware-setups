#!/bin/bash

if ! command -v wrk &> /dev/null; then
    echo "wrk not found, installing..."
        sudo apt install -y wrk
fi

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
OUTDIR=$CURR_DIR/outputx2

mkdir -p $OUTDIR
st=$(ssh psahu@$HOST "ps aux | grep fd_target | grep -v grep > /dev/null && echo 1 || echo 0")
if [[ $st == "1" ]]
then
    ssh psahu@$HOST "ps aux | grep fd_target | grep -v grep | awk '{print \$2}' > fd_target.pid"
else
    ssh psahu@$HOST "bash -c 'nohup $CURR_DIR/fd_target.py > tmp.out 2>&1 & echo \$! > fd_target.pid'"
fi

photoprism_run() {
    echo "Host:$HOST\nCmd:$CMD\nDir:$CURR_DIR"
    ssh psahu@$HOST "bash -c 'nohup taskset -c 1 photoprism start > prism.out 2>&1 & echo \$! > prism.pid'"
    sleep 11

    echo "Start tracer"
    date +%M:%S
    ssh psahu@$HOST "bash -c 'nohup $CMD & echo \$! > tracer.pid'"
    sleep 5
    ssh psahu@$HOST "bash -c 'sudo $CURR_DIR/marker.py \$(cat fd_target.pid)'"
    #ssh psahu@$HOST "bash -c 'ps -p \$(cat tracer.pid) -o etime= >> \$(cat fd_target.pid)'"

    echo "Start API calls"
    
    export TOKEN=$(./get_api.py -s $HOST -l)
    echo $TOKEN
    ## Sync/Index files
    ./get_api.py -s $HOST -t $TOKEN -i
    ./get_api.py -s $HOST -t $TOKEN -api
    ssh psahu@$HOST "bash -c '$CURR_DIR/marker.py \$(cat fd_target.pid)'"
    #ssh psahu@$HOST "bash -c 'ps -p \$(cat tracer.pid) -o etime= >> \$(cat fd_target.pid)'"
    
    wrk -t5 -c5 -d15s -s benchmark.lua http://$HOST:2342
    #ssh psahu@$HOST "bash -c 'ps -p \$(cat tracer.pid) -o etime= >> \$(cat fd_target.pid)'"
    ssh psahu@$HOST "bash -c 'sudo $CURR_DIR/marker.py \$(cat fd_target.pid)'"
    
    sleep 1
    ssh psahu@$HOST "bash -c 'sudo kill -INT \$(cat tracer.pid)'"
    date +%M:%S
    ssh psahu@$HOST "bash -c 'while kill -0 \$(cat tracer.pid) 2>/dev/null; do sleep 1; done'"
    echo "Complete"
    ssh psahu@$HOST "bash -c 'sudo kill -INT \$(cat prism.pid)'"
    ssh psahu@$HOST "bash -c 'photoprism reset -y >> prism.out 2>&1'"
}

TRIES=5
for i in $(seq 2 $TRIES); do
    if [[ $1 == "SYSTEM" ]]; then
        echo "Syscall Trace"
        OUTFNAME=media_syscall_$i
        CMD="$FTRACE_CMD -o trace_$i.dat > strace.out 2>&1"
        photoprism_run
        sleep 3
        ssh psahu@$HOST "bash -c 'sudo trace-cmd report -i trace_$i.dat > $OUTDIR/$OUTFNAME'"
    elif [[ $1 == "NETWORK" ]]; then
        echo "Network Trace"
        OUTFNAME=media_netcall_$i
        CMD="$TSHARK_CMD > $OUTDIR/$OUTFNAME 2> ntrace.out"
        photoprism_run
    elif [[ $1 == "HARDWARE" ]]; then
        echo "Hardware Trace"
        for s in "${stat[@]}"; do
            OUTFNAME=media_hardware_${s}_${i}
            CMD="$HWPERF_CMD $s -o $OUTDIR/$OUTFNAME > perf.out 2>&1"
            ssh psahu@$HOST "echo $OUTDIR/${OUTFNAME}_phase > fd_target.pid"
            photoprism_run
        done
    fi
#    ssh psahu@$HOST "bash -c 'nohup taskset -c 1 photoprism start > prism.out 2>&1 & echo \$! > prism.pid'"
#    sleep 11
#
#    echo "Start tracer"
#    date +%M:%S
#    ssh psahu@$HOST "bash -c 'nohup $CMD & echo \$! > tracer.pid'"
#    sleep 5
#    ssh psahu@$HOST "bash -c '$CURR_DIR/marker.py \$(cat fd_target.pid)'"
#    
#    export TOKEN=$(./get_api.py -s $HOST -l)
#    ## Sync/Index files
#    ./get_api.py -s $HOST -t $TOKEN -i
#    ./get_api.py -s $HOST -t $TOKEN -api
#    ssh psahu@$HOST "bash -c '$CURR_DIR/marker.py \$(cat fd_target.pid)'"
#    
#    wrk -t5 -c5 -d15s -s benchmark.lua http://$HOST:2342
#    ssh psahu@$HOST "bash -c '$CURR_DIR/marker.py \$(cat fd_target.pid)'"
#    
#    sleep 1
#    ssh psahu@$HOST "bash -c 'sudo kill -INT \$(cat tracer.pid)'"
#    date +%M:%S
#    ssh psahu@$HOST "bash -c 'while kill -0 \$(cat tracer.pid) 2>/dev/null; do sleep 1; done'"
#    echo "Complete"
#    if [[ $1 == "SYSTEM" ]]; then
#        sleep 3
#        ssh psahu@$HOST "bash -c 'sudo trace-cmd report -i trace_$i.dat > $OUTDIR/$OUTFNAME'"
#    fi
#    ssh psahu@$HOST "bash -c 'sudo kill -INT \$(cat prism.pid)'"
#    ssh psahu@$HOST "bash -c 'photoprism reset -y >> prism.out 2>&1'"
done
