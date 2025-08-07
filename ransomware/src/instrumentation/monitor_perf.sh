#!/bin/bash

declare -A stat
stat[1]=instructions
stat[2]=mem_inst_retired.all_loads
stat[3]=mem-stores #mem_inst_retired.all_stores
stat[4]=cache-references
stat[5]=mem_load_retired.l3_miss
stat[6]=br_inst_retired.all_branches
stat[7]=uops_dispatched_port.port_0
stat[8]=cycles
#stat[9]=syscalls:sys_enter_*
#stat[10]=block:block_rq_issue

algos=(AES Salsa20 ChaCha20)
modes=(CTR ECB CBC OFB CFB)

target_dir='/mnt/nfs_shared/home/Downloads'

mkdir -p outputs

for algo in "${algos[@]}"; do
	if [ $algo == AES ]; then
		for mode in "${modes[@]}"; do
			for s in "${stat[@]}"; do
				perf stat -C 1 -I 100 -e $s -o outputs/${s}_AES-${mode}_out taskset -c 1 ./main.py -p $target_dir -a $algo -m $mode
				./main.py -p $target_dir -a $algo -m $mode -d
				cat ${target_dir}/000/000387.txt
				echo
			done
		done
	else
		for s in "${stat[@]}"; do
			perf stat -C 1 -I 100 -e $s -o outputs/${s}_${algo}_out taskset -c 1 ./main.py -p $target_dir -a $algo
			./main.py -p $target_dir -a $algo -d
			cat ${target_dir}/000/000387.txt
			echo
		done
	fi

done
