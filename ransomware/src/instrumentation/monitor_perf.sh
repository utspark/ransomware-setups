#!/bin/bash

declare -A stat
#stat[1]=instructions
#stat[2]=mem_inst_retired.all_loads
#stat[3]=mem-stores #mem_inst_retired.all_stores
#stat[4]=cache-references
#stat[5]=mem_load_retired.l3_miss
#stat[6]=br_inst_retired.all_branches
#stat[7]=avx_insts.all
#stat[8]=block:block_rq_issue
#stat[9]=uops_executed_port.port_0
#stat[10]=uops_executed_port.port_0
#stat[11]=uops_executed_port.port_0
#stat[12]=uops_executed_port.port_0
#stat[13]=uops_executed_port.port_0
#stat[14]=uops_executed_port.port_0
#stat[15]=uops_executed_port.port_0
#stat[16]=uops_executed_port.port_0
stat[1]=instructions,br_inst_retired.all_branches,avx_insts.all,block:block_rq_issue
stat[2]=mem-loads,mem-stores,cache-references,LLC-load-misses
#stat[2]=mem-loads,mem-stores,cache-references,mem_load_retired.l3_miss
stat[3]=uops_executed_port.port_2,uops_executed_port.port_3,uops_executed_port.port_4,uops_executed_port.port_7
stat[4]=uops_executed_port.port_0,uops_executed_port.port_1,uops_executed_port.port_5,uops_executed_port.port_6
algos=(AES Salsa20 ChaCha20)
modes=(CTR ECB CBC OFB CFB)

# Exploration Stage
echo -n "Proceed to Recon? [y/n] "
read recon

if [[ $recon == "n" ]]; then
    #exit
    echo "Skipping Reconnaissance"
else
    RECON_CMD=(recon_mount recon_net recon_system)
    BASE_OUTDIR='../../outputs/perf_results'
    OUT_DIR=$BASE_OUTDIR/out_recon

    mkdir -p $OUT_DIR
    TRIES=3
    for i in $(seq 1 $TRIES); do
        for s in "${stat[@]}"; do
            for r in "${RECON_CMD[@]}"; do
                sudo perf stat -C 1 -I 100 -a -e $s -o $OUT_DIR/${r}_${s}_${i} taskset -c 1 ../python/reconnaissance/${r}.sh
                sleep 5
            done
        done
    done
fi

# Exfiltration Stage
echo -n "Proceed to Exfil? [y/n] "
read exfil

if [[ $exfil == "n" ]]; then
    echo "Skipping Exfiltration"
    #exit
else
    DATA_DIR='/mnt/home/000'
    COMPRESS=(gzip zstd)
    THREADS=(1 8)
    REMOTE=(sftp aws)
    
    BASE_OUTDIR='../../outputs/perf_results'
    OUT_DIR=$BASE_OUTDIR/out_exfil
    
    mkdir -p $OUT_DIR
    #../fd_target.py &
    #PID=$!
    #exfil_gzip_{1}_sftp_uops_executed_port.port_0,uops_executed_port.port_1,uops_executed_port.port_5,uops_executed_port.port_6_1 -- redo
    TRIES=4
    for i in $(seq 4 $TRIES); do
        for s in "${stat[@]}"; do
            for r in "${REMOTE[@]}"; do
                for t in "${THREADS[@]}"; do
                    for c in "${COMPRESS[@]}"; do
                        #PROGRAM="../exfiltration/exfiltrate.py -d $DATA_DIR -c $c -t $t -r $r -v $PID"
                        sudo perf stat -C 1 -I 100 -a -e $s -o $OUT_DIR/exfil_${c}_{$t}_${r}_${s}_${i} taskset -c 1 ../python/exfiltration/exfiltrate.py -d $DATA_DIR -c $c -t $t -r $r -v ${s}_$i
                        sleep 5
                    done
                done
            done
        done
    done
fi

# Execution Stage
#echo -n "Proceed to Execute? [y/n] "
#read execute

if [[ $exfil == "n" ]]; then
    echo "Skipping Execution"
    #exit
else
    DATA_DIR='/mnt/home/000'
    SYM=(AES Salsa20)
    KEYLEN=(128 256)
    WRMODE=(O WA)
    EXTEND=(none default)
    
    BASE_OUTDIR='../../outputs/perf_results'
    OUT_DIR=$BASE_OUTDIR/out_exec
    
    mkdir -p $OUT_DIR
    #../fd_target.py &
    #PID=$!
    
    TRIES=4
    for i in $(seq 4 $TRIES); do
        for stat in "${stat[@]}"; do
            for s in "${SYM[@]}"; do
                for k in "${KEYLEN[@]}"; do
                    for w in "${WRMODE[@]}"; do
                        for e in "${EXTEND[@]}"; do
                            #PROGRAM="../execution/payload.py -d $DATA_DIR -sym $s -k $k -w $w -ext $e -v $PID"
                            echo "Sym Cipher $s KeyLen $k WriteMode $w Ext $e"
                            taskset -c 1 ../python/execution/payload.py -d $DATA_DIR -sym $s -k $k -w $w -ext $e -v ${stat}_$i &
                            workload=$!
                            sudo perf stat -C 1 -I 100 -a -e $stat -o $OUT_DIR/exec_${s}_${k}_${w}_${e}_${stat}_${i} -p $workload
                            echo "Encryption Done"
                            wait $workload
                            sleep 1
                            ../python/execution/decryptor.py -d $DATA_DIR -sym $s -k $k -w $w -ext $e
                            echo "Decryption Done"
                            cat $DATA_DIR/000387.txt
                            sleep 1
                        done
                    done
                done
            done
        done
    done
fi
