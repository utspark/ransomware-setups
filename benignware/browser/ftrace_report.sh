#!/bin/bash

EXT="dat"
CMD="sudo trace-cmd report -i"

for file in *."$EXT"; do
    [ -f "$file" ] || continue
    echo "Processing $file"
    id="${file#trace_}"
    id="${id%.dat}"
    echo "Output to browser_syscall_$id"
    $CMD "$file" > output/browser_syscall_$id
done
