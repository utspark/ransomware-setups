#!/bin/bash

# Exploration Stage
RECON_CMD=(recon_mount recon_net recon_system)
OUT_DIR='../out_recon'

mkdir -p $OUT_DIR
TRIES=5
for i in $(seq 1 $TRIES); do
    for r in "${RECON_CMD[@]}"; do
        sudo trace-cmd record -e syscalls -a &
        trace_pid=$!
        sleep 5
        ../reconnaissance/${r}.sh
        sudo kill -INT $trace_pid
        sleep 5
        sudo trace-cmd report > $OUT_DIR/${r}_${i}
        echo
    done
done

# Exfiltration Stage
DATA_DIR='/mnt/home/000'
COMPRESS=(gzip zstd none)
THREADS=(1 8)
REMOTE=(sftp aws)

OUT_DIR='../out_exfil'

mkdir -p $OUT_DIR
../exfiltration/fd_target.py &
PID=$!

TRIES=5
for i in $(seq 1 $TRIES); do
    for r in "${REMOTE[@]}"; do
        for t in "${THREADS[@]}"; do
            for c in "${COMPRESS[@]}"; do
                sudo trace-cmd record -e syscalls -a &
                trace_pid=$!
                sleep 5
                ../exfiltration/exfiltrate.py -d $DATA_DIR -c $c -t $t -r $r -v $PID
                sudo kill -INT $trace_pid
                sleep 5
                sudo trace-cmd report > $OUT_DIR/exfil_${c}_${t}_${r}_${i}
                echo
            done
        done
    done
done

# Execution Stage
DATA_DIR='/mnt/home/000'
SYM=(AES Salsa20)
KEYLEN=(128 256)
WRMODE=(O WA)
EXTEND=(none default)

OUT_DIR='../out_exec'

mkdir -p $OUT_DIR
../exfiltration/fd_target.py &
PID=$!

TRIES=3
for i in $(seq 1 $TRIES); do
    for s in "${SYM[@]}"; do
        for k in "${KEYLEN[@]}"; do
            for w in "${WRMODE[@]}"; do
                for e in "${EXTEND[@]}"; do
                    sudo trace-cmd record -e syscalls -a &
                    trace_pid=$!
                    sleep 5
                    set -x
                    ../execution/payload.py -d $DATA_DIR -sym $s -k $k -w $w -ext $e -v $PID
                    set +x
                    sudo kill -INT $trace_pid
                    sleep 5
                    sudo trace-cmd report > $OUT_DIR/exec_${s}_${k}_${w}_${e}_${i}
                    echo

                    ../execution/decryptor.py -d $DATA_DIR -sym $s -k $k -w $w -ext $e
                    cat $DATA_DIR/000387.txt
                    echo
                done
            done
        done
    done
done

