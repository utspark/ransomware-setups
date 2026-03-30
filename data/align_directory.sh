#!/bin/bash

# Invert the directory structure for ransomware to match benign data
echo "Inverting directory structure for ransomware data..."

for path in "results"/*/*/*/*/; do
    # Strip the trailing slash
    path=${path%/}
    echo "Processing: $path"

    # Break the path into three variables: x/m/a
    IFS='/' read -r prefix d0 d1 d2 d3 <<< "$path"
    IFS='_' read -r p0 p1 p2 <<< "$d3"
    if [[ "$d0" == "ransomware_data" ]]; then
        # Create the new swapped target: a/m/x
        if [[ $d1 == *"ftrace"* ]]; then
            d1="syscall_output_parsed"
        elif [[ $d1 == *"perf"* ]]; then
            d1="hardware_output_parsed"
        elif [[ $d1 == *"net"* ]]; then
            d1="netcall_output_parsed"
        fi
        target="$prefix/$d0/$p1/$d1"
        mkdir -p "$target"

        # Move any files from the old folder to the new one
        # Then remove the old empty directory
        if [ -d "$path" ]; then
            mv "$path"/* "$target/" 2>/dev/null
            rmdir "$path"
        fi
    elif [[ "$d0" == "benignware_data" ]]; then
        if [[ $d3 != *"parsed" && $d3 != "hardware"* ]]; then
            d3="$d3"_parsed
        fi
        if [[ $d3 == "network"* ]]; then
            d3="${d3/network/netcall}"
        fi 
        target="$prefix/$d0/$d1/$d3"
        mkdir -p "$target"

        # Move any files from the old folder to the new one
        # Then remove the old empty directory
        if [ -d "$path" ]; then
            mv "$path"/* "$target/" 2>/dev/null
            rmdir "$path"
        fi
    fi
done

# Clean up any remaining empty directories
find results -type d -empty -delete
# Exception for idle containing extra raw data
rm -rf results/benignware_data/idle/hardware_output/

# Exception: Incorrectly named files in mediaserver and spec
PREFIX="mediaserver"
# Define the starting directory ('.' means current directory)
START_DIR="results/benignware_data"
for path in $START_DIR/$PREFIX/*/*; do

    # Extract the directory name and the base filename
    dir="$(dirname "$path")"
    base="$(basename "$path")"

    # Construct the new filename with the prefix and move the file
    newname="$dir/${PREFIX}_$base"
    mv $path $newname
done
PREFIX="spec"
for path in $START_DIR/$PREFIX/*/*; do
    # Extract the directory name and the base filename
    dir="$(dirname "$path")"
    base="$(basename "$path")"

    # Construct the new filename with the prefix and move the file
    if [[ "$base" != "$PREFIX"* ]]; then
        newname="${path/perf/$PREFIX}"
        mv $path $newname
    fi
done