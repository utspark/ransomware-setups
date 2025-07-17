#!/bin/bash

target_dir='/mnt/home/000'
output_dir='../outputs'

mkdir -p $output_dir

run_ransomware() {
	sudo trace-cmd record -e syscalls -a &
	trace_pid=$!
	echo $trace_pid
	sleep 5.5
	./sysmark.py 24184 1
	gzip -r $target_dir
	./sysmark.py 24184 1
	sudo kill -INT $trace_pid
	sleep 4
	sudo trace-cmd report > ${output_dir}/gzip_system_marker
	gunzip -r $target_dir
	cat ${target_dir}/000387.txt
	echo
}

run_ransomware_timed() {
	gzip -r $target_dir
    prog_pid=$!
	
	sudo trace-cmd record -e syscalls -o trace.dat sleep 15
	sleep 5
	sudo trace-cmd report trace.dat > ${output_dir}/gzip_system_timed
	
	wait $prog_pid
	
    gunzip -r $target_dir
	cat ${target_dir}/000387.txt
	echo
}

ransomware=run_ransomware

$ransomware
