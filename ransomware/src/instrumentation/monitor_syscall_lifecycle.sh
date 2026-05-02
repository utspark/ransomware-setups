#!/bin/bash

FTRACE_CMD="trace-cmd record -e syscalls -a"

TRIES=1
BASE_OUTDIR='../../output/syscall'
echo "Syscall Trace"

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
        for r in "${RECON_CMD[@]}"; do
            echo "Recon: $r"
            sudo $FTRACE_CMD &
            trace_pid=$!
            sleep 5
            ../python/reconnaissance/${r}.sh
            sudo kill -INT $trace_pid
            sleep 5
            sudo trace-cmd report > $OUT_DIR/${r}_${i}
            echo
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
    ../python/fd_target.py &
    PID=$!

    for i in $(seq 1 $TRIES); do
        for r in "${REMOTE[@]}"; do
            for t in "${THREADS[@]}"; do
                for c in "${COMPRESS[@]}"; do
                    echo "Exfil: Remote $r, threads: $t with $c compression"
                    sudo $FTRACE_CMD &
                    trace_pid=$!
                    sleep 5
                    ../python/exfiltration/exfiltrate.py -d $DATA_DIR -c $c -t $t -r $r -v $PID
                    sudo kill -INT $trace_pid
                    sleep 5
                    sudo trace-cmd report > $OUT_DIR/exfil_${c}_${t}_${r}_${i}
                    echo
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
    ../python/fd_target.py &
    PID=$!

    for i in $(seq 1 $TRIES); do
        for s in "${SYM[@]}"; do
            for k in "${KEYLEN[@]}"; do
                for w in "${WRMODE[@]}"; do
                    for e in "${EXTEND[@]}"; do
                        echo "Sym Cipher $s KeyLen $k WriteMode $w Ext $e"
                        sudo $FTRACE_CMD &
                        trace_pid=$!
                        sleep 5
                        ../python/execution/payload.py -d $DATA_DIR -sym $s -k $k -w $w -ext $e -v $PID
                        echo "Encryption Done"
                        sudo kill -INT $trace_pid
                        sleep 5
                        sudo trace-cmd report > $OUT_DIR/exec_${s}_${k}_${w}_${e}_${i}
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
fi
