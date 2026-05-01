#!/bin/bash

workloads=("fbench" "compression" "browser" "perf/cpu2017")
METRICS=("SYSTEM" "NETWORK" "HWPERF" "NONE")
for w in "${workloads[@]}"; do
    echo "Running workload $w with streaming collection"
    cd ${w}
    for m in "${METRICS[@]}"; do
        echo "Collecting metric $m"
        bash run_workload_streaming.sh $m
        sleep 1
    done
    cd -
done