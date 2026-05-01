#!/bin/bash

algos=(AES)
modes=(O)
exfil=(aws)
order=()

target_dir='/mnt/home/Data'
output_dir='../outputs'

mkdir -p $output_dir

idle=$1

run_ransomware() {
	sudo trace-cmd record -e syscalls -a &
	trace_pid=$!
	echo $trace_pid
	sleep 5.5
	./sysmark.py 24184 1
	if [ $1 == "idle" ]; then
		sleep $2
	else
		./main.py -p $target_dir -a $1 -w $2 -e $3 -v 24184
	fi
	./sysmark.py 24184 1
	sudo kill -INT $trace_pid
	sleep 4
	read -ra elements <<< "$3"
	if [[ ${#elements[@]} -ge 3 ]]; then
		run_num="${elements[0]}"
	else
		run_num=""
	fi
	sudo trace-cmd report > ${output_dir}/$1_$2_$4${run_num}_system_marker
	if [ $1 != "idle" ]; then
		./main.py -p $target_dir -a $1 -w $2 -d -v 24184
	fi
	cat ${target_dir}/000387.txt
	echo
}

run_ransomware_timed() {
	read -ra elements <<< "$3"
	if [[ ${#elements[@]} -ge 3 ]]; then
		run_num="${elements[0]}"
	else
		run_num=""
	fi
	
	if [ $1 == "idle" ]; then
		sleep $2 &
		prog_pid=$!
	else
		./main.py -p $target_dir -a $1 -w $2 -e $3 -v 24184 &
		prog_pid=$!
	fi
	
	sudo trace-cmd record -e syscalls -o trace.dat sleep 15
	sleep 5
	sudo trace-cmd report trace.dat > ${output_dir}/$1_$2_$4${run_num}_system_timed
	
	wait $prog_pid
	if [ $1 != "idle" ]; then
		./main.py -p $target_dir -a $1 -w $2 -d
	fi
	cat ${target_dir}/000387.txt
	echo
}

run_ransomware_interleave() {
	sudo trace-cmd record -e syscalls -a &
	trace_pid=$!
	echo $trace_pid
	sleep 5
	if [ $1 == "idle" ]; then
		sleep 85
	else
		./main.py -p $target_dir -a $1 -w $2 -e $3
		sleep 5
		./main.py -p $target_dir -a $1 -w $2 -d
		sleep 5
		./main.py -p $target_dir -a $1 -w $2 -e $3
		sleep 5
		./main.py -p $target_dir -a $1 -w $2 -d
		sleep 5
	fi
	sudo kill -INT $trace_pid
	sleep 5
	sudo trace-cmd report > ${output_dir}/$1_$2_$4_repeat_system_interval
	echo
}

ransomware=run_ransomware_timed

for algo in "${algos[@]}"; do
	for mode in "${modes[@]}"; do
		for o in "${order[@]}"; do
			if [ "$o" -gt "0" ]; then
				for e in "${exfil[@]}"; do
					ex_arg="$o -r $e"
					name="exfil_$e"
					$ransomware $algo $mode "$ex_arg" $name
				done
			else
				name="exfil_none"
				$ransomware $algo $mode $o $name

			fi
		done
	done
done

if [ $1 == 1 ]; then
	$ransomware idle 20 "0" trace
fi
