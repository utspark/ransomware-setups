#!/bin/bash

# workloads=("fbench" "compression" "browser" "perf/cpu2017")
METRICS=("SYSTEM" "NETWORK" "HWPERF" "NONE")
workloads=("fbench")
# METRICS=("HWPERF")
for w in "${workloads[@]}"; do
    echo "Running workload $w with timed collection"
    cd ${w}
    for m in "${METRICS[@]}"; do
        echo "Collecting metric $m"
        bash run_workload_timed.sh $m
        sleep 1
    done
    cd -
done
