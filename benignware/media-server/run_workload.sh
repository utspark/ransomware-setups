#!/bin/bash

# if ! command -v wrk &> /dev/null; then
#     echo "wrk not found, installing..."
#         sudo apt install -y wrk
# fi

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
hostname_ext=(${HOSTNAME#*.})
WRKHOST="node-1.$hostname_ext"
SRVHOST="node-0.$hostname_ext"
CURR_DIR=$(pwd)
OUTDIR=$CURR_DIR/output

mkdir -p $OUTDIR
st=$(ps aux | grep fd_target | grep -v grep > /dev/null && echo 1 || echo 0)
if [[ $st == "1" ]]
then
    ps aux | grep fd_target | grep -v grep | awk '{print $2}' > ~/fd_target.pid
else
    ./fd_target.py > tmp.out 2>&1 & echo "$!" > ~/fd_target.pid
fi

photoprism_run() {
    echo "Host:$HOST\nCmd:$CMD\nDir:$CURR_DIR"
    taskset -c 1 photoprism start > ~/prism.out 2>&1 & echo $! > ~/prism.pid
    sleep 11

    echo "Start tracer"
    #date +%M:%S
    eval "$CMD &"
    echo $! > ~/tracer.pid
    sleep 5
    ./marker.py $(cat ~/fd_target.pid)
    #ssh $USER@$HOST "bash -c 'ps -p \$(cat tracer.pid) -o etime= >> \$(cat fd_target.pid)'"

    echo "Start API calls"

    ssh $USER@$WRKHOST "cd $CURR_DIR; ./get_api.py -s $SRVHOST -l > token"
    ## Sync/Index files
    ssh $USER@$WRKHOST "bash -c 'cd $CURR_DIR; ./get_api.py -s $SRVHOST -t \$(cat token) -i'"
    ssh $USER@$WRKHOST "bash -c 'cd $CURR_DIR; ./get_api.py -s $SRVHOST -t \$(cat token) -api'"
    #./get_api.py -s $HOST -t $TOKEN -i
    #./get_api.py -s $HOST -t $TOKEN -api
    ./marker.py $(cat ~/fd_target.pid)
    #ssh $USER@$HOST "bash -c 'ps -p \$(cat tracer.pid) -o etime= >> \$(cat fd_target.pid)'"

    #wrk -t5 -c5 -d15s -s benchmark.lua http://$HOST:2342
    ssh $USER@$WRKHOST "bash -c 'cd $CURR_DIR; wrk -t5 -c5 -d15s -s benchmark.lua http://$SRVHOST:2342'"
    ./marker.py $(cat ~/fd_target.pid)
    #ssh $USER@$HOST "bash -c 'ps -p \$(cat tracer.pid) -o etime= >> \$(cat fd_target.pid)'"
    
    sleep 1
    sudo kill -INT $(cat ~/tracer.pid)
    while kill -0 $(cat ~/tracer.pid) 2>/dev/null; do sleep 1; done
    echo "Complete"
    kill -INT $(cat ~/prism.pid)
    photoprism reset -y >> ~/prism.out 2>&1
}

TRIES=1
METRICS=("SYSTEM" "NETWORK" "HWPERF")
for METRIC in "${METRICS[@]}"; do
    echo "Running workload with $TRIES iterations for each option: ${options[*]} for metric $METRIC"
    for i in $(seq 1 $TRIES); do
        if [[ $METRIC == "SYSTEM" ]]; then
            echo "Syscall Trace"
            TRACEDIR=$OUTDIR/syscall_output
            mkdir -p $TRACEDIR
            OUTFNAME=media_syscall_$i
            CMD="$FTRACE_CMD -o trace_$i.dat > strace.out 2>&1"
            photoprism_run
            sleep 3
            sudo trace-cmd report -i trace_$i.dat > $TRACEDIR/$OUTFNAME
        elif [[ $METRIC == "NETWORK" ]]; then
            echo "Network Trace"
            TRACEDIR=$OUTDIR/netcall_output
            mkdir -p $TRACEDIR
            OUTFNAME=media_netcall_$i
            CMD="$TSHARK_CMD > $TRACEDIR/$OUTFNAME 2> ntrace.out"
            photoprism_run
        elif [[ $METRIC == "HWPERF" ]]; then
            echo "Hardware Trace"
            TRACEDIR=$OUTDIR/hardware_output
            mkdir -p $TRACEDIR
            for s in "${stat[@]}"; do
                OUTFNAME=media_hardware_${s}_${i}
                CMD="$HWPERF_CMD $s -o $TRACEDIR/$OUTFNAME > perf.out 2>&1"
                # ssh $USER@$WRKHOST "echo $TRACEDIR/${OUTFNAME}_phase > fd_target.pid"
                echo $TRACEDIR/${OUTFNAME}_phase > ~/fd_target.pid
                photoprism_run
            done
        fi
    #    ssh $USER@$HOST "bash -c 'nohup taskset -c 1 photoprism start > prism.out 2>&1 & echo \$! > prism.pid'"
    #    sleep 11
    #
    #    echo "Start tracer"
    #    date +%M:%S
    #    ssh $USER@$HOST "bash -c 'nohup $CMD & echo \$! > tracer.pid'"
    #    sleep 5
    #    ssh $USER@$HOST "bash -c '$CURR_DIR/marker.py \$(cat fd_target.pid)'"
    #    
    #    export TOKEN=$(./get_api.py -s $HOST -l)
    #    ## Sync/Index files
    #    ./get_api.py -s $HOST -t $TOKEN -i
    #    ./get_api.py -s $HOST -t $TOKEN -api
    #    ssh $USER@$HOST "bash -c '$CURR_DIR/marker.py \$(cat fd_target.pid)'"
    #    
    #    wrk -t5 -c5 -d15s -s benchmark.lua http://$HOST:2342
    #    ssh $USER@$HOST "bash -c '$CURR_DIR/marker.py \$(cat fd_target.pid)'"
    #    
    #    sleep 1
    #    ssh $USER@$HOST "bash -c 'sudo kill -INT \$(cat tracer.pid)'"
    #    date +%M:%S
    #    ssh $USER@$HOST "bash -c 'while kill -0 \$(cat tracer.pid) 2>/dev/null; do sleep 1; done'"
    #    echo "Complete"
    #    if [[ $1 == "SYSTEM" ]]; then
    #        sleep 3
    #        ssh $USER@$HOST "bash -c 'sudo trace-cmd report -i trace_$i.dat > $OUTDIR/$OUTFNAME'"
    #    fi
    #    ssh $USER@$HOST "bash -c 'sudo kill -INT \$(cat prism.pid)'"
    #    ssh $USER@$HOST "bash -c 'photoprism reset -y >> prism.out 2>&1'"
    done
done
