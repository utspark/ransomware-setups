#!/bin/bash

HWPERF_CMD="perf stat -C 1 -I 100 -a -e"

declare -A stat
# Best overall performing counters
stat[1]=instructions,br_inst_retired.all_branches,avx_insts.all,cache-references

# All tested counters: Uncomment below to run multiple perf stat runs for different counter sets
# stat[1]=instructions,br_inst_retired.all_branches,avx_insts.all,block:block_rq_issue
# stat[2]=mem-loads,mem-stores,cache-references,LLC-load-misses
# stat[3]=uops_executed_port.port_2,uops_executed_port.port_3,uops_executed_port.port_4,uops_executed_port.port_7
# stat[4]=uops_executed_port.port_0,uops_executed_port.port_1,uops_executed_port.port_5,uops_executed_port.port_6

TRIES=1
BASE_OUTDIR='../../output/hardware'
echo "Hardware Trace"

# Exploration Stage
if [[ $1 == "RECON" ]]; then
# echo -n "Proceed to Recon? [y/n] "
# read recon
# if [[ $recon == "n" ]]; then
#     #exit
#     echo "Skipping Reconnaissance"
# else
    RECON_CMD=(recon_mount recon_net recon_system)
    OUT_DIR=$BASE_OUTDIR/out_recon

    mkdir -p $OUT_DIR
    for i in $(seq 1 $TRIES); do
        for s in "${stat[@]}"; do
            for r in "${RECON_CMD[@]}"; do
                echo "Recon: $r"
                sudo $HWPERF_CMD $s -o $OUT_DIR/${r}_${s}_${i} taskset -c 1 ../python/reconnaissance/${r}.sh
                sleep 5
            done
        done
    done
fi

# Exfiltration Stage
if [[ $1 == "EXFIL" ]]; then
# echo -n "Proceed to Exfil? [y/n] "
# read exfil
# if [[ $exfil == "n" ]]; then
#     echo "Skipping Exfiltration"
#     #exit
# else
    DATA_DIR='/mnt/home/000'
    COMPRESS=(gzip zstd none)
    THREADS=(1 8)
    REMOTE=(sftp) # Options: sftp or aws
    
    OUT_DIR=$BASE_OUTDIR/out_exfil
    
    mkdir -p $OUT_DIR
    
    for i in $(seq 1 $TRIES); do
        for s in "${stat[@]}"; do
            for r in "${REMOTE[@]}"; do
                for t in "${THREADS[@]}"; do
                    for c in "${COMPRESS[@]}"; do
                        echo "Exfil: Remote $r, threads: $t with $c compression"
                        #PROGRAM="../exfiltration/exfiltrate.py -d $DATA_DIR -c $c -t $t -r $r -v $PID"
                        sudo $HWPERF_CMD $s -o $OUT_DIR/exfil_${c}_${t}_${r}_${s}_${i} taskset -c 1 ../python/exfiltration/exfiltrate.py -d $DATA_DIR -c $c -t $t -r $r -v ${s}_$i
                        sleep 5
                    done
                done
            done
        done
    done
fi

# Execution Stage
if [[ $1 == "EXEC" ]]; then
# echo -n "Proceed to Execute? [y/n] "
# read execute
# if [[ $exfil == "n" ]]; then
#     echo "Skipping Execution"
#     #exit
# else
    DATA_DIR='/mnt/home/000'
    SYM=(AES Salsa20) # Options: AES, Salsa20, Chacha20
    KEYLEN=(128 256)
    WRMODE=(O WA) # Options: O (overwrite), WA (write-after-delete), WB (write-before-delete)
    EXTEND=(none default)
    
    OUT_DIR=$BASE_OUTDIR/out_exec
    
    mkdir -p $OUT_DIR
    
    for i in $(seq 1 $TRIES); do
        for stat in "${stat[@]}"; do
            for s in "${SYM[@]}"; do
                for k in "${KEYLEN[@]}"; do
                    for w in "${WRMODE[@]}"; do
                        for e in "${EXTEND[@]}"; do
                            #PROGRAM="../execution/payload.py -d $DATA_DIR -sym $s -k $k -w $w -ext $e -v $PID"
                            echo "Sym Cipher $s KeyLen $k WriteMode $w Ext $e"
                            taskset -c 1 ../python/execution/payload.py -d $DATA_DIR -sym $s -k $k -w $w -ext $e -v ${stat}_$i &
                            workload=$!
                            sudo $HWPERF_CMD $stat -o $OUT_DIR/exec_${s}_${k}_${w}_${e}_${stat}_${i} -p $workload
                            echo "Encryption Done"
                            wait $workload
                            sleep 1
                            echo

                            # Decrypt before next run
                            ../python/execution/decryptor.py -d $DATA_DIR -sym $s -k $k -w $w -ext $e
                            echo "Decryption Done"
                            cat $DATA_DIR/000387.txt
                            echo
                        done
                    done
                done
            done
        done
    done
fi
