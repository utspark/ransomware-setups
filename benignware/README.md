# Run Benign Workloads

This directory contains 5 benign workloads and a script to collect idle system stats. Each benign workload is unique and has a setup script that installs/downloads dependencies. We discuss the benchmarks next.

## Browser
This workload starts a chromium browser and simulates various functions by automated clicks
1. Streaming: Plays a few Youtube videos for 15 secs
2. Browsing: Opens and clicks google and wikepedia links
3. Download: Downloads 100MB or 1GB files from a https server
4. Compute: Opens a WASM runtime that does crypto computations such as AES RSA etc.

This has a `browser_setup.sh` that needs to be run before running the workload.

## Compression
This workload uses different compression techniques to compress a NFS mount path. We test 5 compression engines: 7zip Bzip2 gzip zStd and Zip

This has a `compression_setup.sh` that needs to be run before running the workload.

## Filebench (Fbench)
This is a file operations benchmark (https://github.com/filebench/filebench). We utilize 5 of their workloads to use in our experiments: fileserver, oltp, randomrw, varmail and videoserver.
To ensure successful runs, we change the default parameters for these workloads and have it in a patch file that needs to be applied. The filebench is a git submodule that can be pulled by running `git submodule update --init --recursive`.

This has a `filebench_setup.sh` that needs to be run to apply the patch before running the workload.

## Media Server
This is a photoprism media server that serves a few benchmarck videos and images. When the application starts, we collect the indexing and viewing apis.
Next we use a 2-server system, where one of the servers (node-1 in our case), runs `wrk` and calls the indexing APIs, and then opens videos and downloads images. As the indexing process runs, the application generates thumbnails.
We simulate real work by using the load generator to make frequent calls to the photoprism application.

This has a `mediaserver_setup.sh` that needs to be run tbefore running the workload. We also need `wrk` to be installed on the "client" machine.
Depending on specific node setups, the hosts in each `run_workload` files might need to be updated.

## CPU 2017
We also run standard CPU 2017 benchmarks. This requires a license cpu2017 package to be installed within `perf/` folder. Because of licensing issues we have not included the cpu2017 package here, but rely on the user's ability to obtain the licenses.

## Running the workloads
Each benign application (except for Idle and MediaServer) have 3 `run_workload` scripts. Idle and MediaServer have just 1.

The `run_workload.sh` runs all the workloads with all the different modes and collects HW, System and Network events in `/output/` folders. This creates 1 syscall, netcall and hardware output file per benchmark option where each file contains all the metrics. We provide this as the base option to segregate the data-collection and the ML-pipeline for independent execution and verification.

The `run_workload_timed.sh` is more or less same as the above option, apart from the fact that it also times the total runtime of the benign workload into `latency_overhead.log` with and without each of the tracers. This allows us to evaluate the overhead of using tracing on each application. The `analyze_overheads.py` script collects all such logs and generates the overheads plot.

The `run_workload_streaming.sh` is the most deployment friendly option which creates a 1GB in-memory disk and collects all metrics at a 100ms granularity. The entire script streams the statistics, that is processed by a `mawk` script into files. It also generates a `metrics.log` file that informs the amount of events processed in every 100ms sample and the time it took to process them. We use `analyze_all_metrics.py <METRIC>` to get detailed view of the overheads per metric. or we can use `analyze_combined_metrics.py` to get the plots in our paper of the overheads across all metrics and all benchmarks.