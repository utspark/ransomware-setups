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

for s in "${stat[@]}"; do
	perf stat -C 1 -I 100 -e $s -o outputs/${s}_gzip_out taskset -c 1 gzip -r $target_dir
	gunzip -r $target_dir
done

for s in "${stat[@]}"; do
	perf stat -C 1 -I 100 -e $s -o outputs/${s}_lzma_out taskset -c 1 ./xz_compress -r $target_dir
	./xz_decompress -r $target_dir
done
