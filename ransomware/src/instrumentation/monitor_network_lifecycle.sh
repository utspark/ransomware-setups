#!/bin/bash

TSHARK_CMD="tshark -i any -T fields -E header=y -E separator=, \
	    -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e udp.srcport -e udp.dstport \
	    -e frame.len -e _ws.col.Protocol -e _ws.col.Info -a duration:120"

TRIES=1
BASE_OUTDIR='../../output/netcall'
echo "Network Trace"

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
            sudo $TSHARK_CMD -a duration:60 > $OUT_DIR/${r}_${i} &
            trace_pid=$!
            sleep 0.5
            ../python/reconnaissance/${r}.sh
            sudo kill -INT $trace_pid
            sleep 1
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
    REMOTE=(sftp) # Options: sftp, aws

    OUT_DIR=$BASE_OUTDIR/out_exfil

    mkdir -p $OUT_DIR
    ../python/fd_target.py &
    PID=$!

    for i in $(seq 1 $TRIES); do
        for r in "${REMOTE[@]}"; do
            for t in "${THREADS[@]}"; do
                for c in "${COMPRESS[@]}"; do
                    echo "Exfil: Remote $r, threads: $t with $c compression"
                    sudo $TSHARK_CMD -a duration:120 > $OUT_DIR/exfil_${c}_${t}_${r}_${i} &
                    trace_pid=$!
                    sleep 0.5
                    ../python/exfiltration/exfiltrate.py -d $DATA_DIR -c $c -t $t -r $r -v $PID
                    sudo kill -INT $trace_pid
                    sleep 1
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
    SYM=(AES Salsa20) # Options: AES, Salsa20, ChaCha20
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
                        sudo $TSHARK_CMD -a duration:60 > $OUT_DIR/exec_${s}_${k}_${w}_${e}_${i} &
                        trace_pid=$!
                        sleep 0.5
                        ../python/execution/payload.py -d $DATA_DIR -sym $s -k $k -w $w -ext $e -v $PID
                        echo "Encryption Done"
                        sudo kill -INT $trace_pid
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
fi
