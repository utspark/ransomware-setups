#!/bin/bash

OUTPUT_DIR=${1:-"./"}

# Synthesize results into metrics buckets
echo "Synthesizing results into metrics buckets..."

for path in "results"/*/*/*/; do
    # Strip the trailing slash
    path=${path%/}
    echo "Processing: $path"

    IFS='/' read -r prefix d0 d1 d2 <<< "$path"
    
    if [[ "$d2" == "hardware"* ]]; then
        target="$OUTPUT_DIR/current_data/hpc_bucket"
        mkdir -p "$target"

        cp "$path"/* "$target/"
    elif [[ "$d2" == "netcall"* ]]; then
        target="$OUTPUT_DIR/current_data/network_bucket"
        mkdir -p "$target"

        cp "$path"/* "$target/"
    elif [[ "$d2" == "syscall"* ]]; then
        target="$OUTPUT_DIR/current_data/syscall_bucket"
        mkdir -p "$target"

        python ../detector_framework/data_processing/strace_processor.py "$path"

        mv "$path"/*_ints.txt "$target/"
    fi
done

declare -A KEYWORDS=(["hpc"]="_hardware_" ["network"]="_netcall_" ["syscall"]="_syscall_")
REPLACEMENT="_"

for key in "${!KEYWORDS[@]}"; do
    word="${KEYWORDS[$key]}"
    for file in "$OUTPUT_DIR"/current_data/"$key"_bucket/*"$word"* ; do
        if [ -f "$file" ]; then
            new_name="${file//$word/$REPLACEMENT}"
            mv -- "$file" "$new_name"
            # echo "Renamed '$file' to '$new_name'"
        fi
    done
done

# Manually handle some naming inconsistencies in the syscall bucket
for file in "$OUTPUT_DIR"/current_data/syscall_bucket/* ; do
    if [[ "$file" == *"128t"* || "$file" == *"256t"* ]]; then
        dir="$(dirname "$file")"
        base="$(basename "$file")"
        new_base="${base/"t_"/"b_"}"
        new_name="${dir}/${new_base}"
        mv -- "$file" "$new_name"
        # echo "Renamed '$file' to '$new_name'"
    fi
done