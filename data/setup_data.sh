#!/bin/bash

curl -L 'https://zenodo.org/records/18502469/files/dataset_results.tar.gz?download=1' -o results.tar.gz
tar -xvf results.tar.gz
rm results.tar.gz

# Recursively find all .tar.gz files and extract them into appropriately named directories
echo "Scanning for .tar.gz files..."
find . -type f -name ".*" -delete

find . -name "*.tar.gz" -type f | while read -r file; do
    # Get the directory containing the file
    dir=$(dirname "$file")
    # Get the basename without the .tar.gz extension
    basename=$(basename "$file" .tar.gz)
    # Create the target directory
    target_dir="$dir/$basename"
    
    echo "Extracting: $file → $target_dir"
    
    # Create the directory and extract
    mkdir -p "$target_dir"
    tar -xzf "$file" -C "$target_dir"
    
    echo "✓ Successfully extracted $file"
done

# Remove hidden files that may have been extracted
find . -type f -name ".*" -delete
echo "All tar.gz files have been processed!"

source bash/align_directory.sh
source bash/process_results.sh

