#!/bin/bash

TSHARK_CMD="tshark -i any \
	    -T fields \
	    -e frame.time \
	    -e ip.src \
        -e tcp.srcport \
	    -e ip.dst \
        -e tcp.dstport \
	    -e udp.srcport \
        -e udp.dstport \
	    -e frame.len \
	    -e _ws.col.Protocol \
        -e _ws.col.Info \
	    -E header=y \
	    -E separator=, "


if [[ $1 == "RECON" ]]; then
# Exploration Stage
RECON_CMD=(recon_mount recon_net recon_system)
BASE_OUTDIR='../../outputs/v4_results'
OUT_DIR=$BASE_OUTDIR/out_recon

mkdir -p $OUT_DIR
TRIES=5
for i in $(seq 1 $TRIES); do
    for r in "${RECON_CMD[@]}"; do
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
DATA_DIR='/mnt/home/000'
COMPRESS=(gzip zstd none)
THREADS=(1 8)
REMOTE=(sftp aws)

BASE_OUTDIR='../../outputs/v4_results'
OUT_DIR=$BASE_OUTDIR/out_exfil

mkdir -p $OUT_DIR
../python/fd_target.py &
PID=$!

TRIES=5
for i in $(seq 1 $TRIES); do
    for r in "${REMOTE[@]}"; do
        for t in "${THREADS[@]}"; do
            for c in "${COMPRESS[@]}"; do
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
DATA_DIR='/mnt/home/000'
SYM=(AES Salsa20)
KEYLEN=(128 256)
WRMODE=(O WA)
EXTEND=(none default)

BASE_OUTDIR='../../outputs/v4_results'
OUT_DIR=$BASE_OUTDIR/out_exec

mkdir -p $OUT_DIR
../python/fd_target.py &
PID=$!

TRIES=2
for i in $(seq 1 $TRIES); do
    for s in "${SYM[@]}"; do
        for k in "${KEYLEN[@]}"; do
            for w in "${WRMODE[@]}"; do
                for e in "${EXTEND[@]}"; do
        	        sudo $TSHARK_CMD -a duration:60 > $OUT_DIR/exec_${s}_${k}_${w}_${e}_${i} &
                    trace_pid=$!
                    sleep 0.5
                    set -x
                    ../python/execution/payload.py -d $DATA_DIR -sym $s -k $k -w $w -ext $e -v $PID
                    set +x
                    sudo kill -INT $trace_pid
                    sleep 1
                    echo

                    ../python/execution/decryptor.py -d $DATA_DIR -sym $s -k $k -w $w -ext $e
                    cat $DATA_DIR/000387.txt
                    echo
                done
            done
        done
    done
done
fi
