# Ransomware Setups

This repository contains the code for a lifecycle aware ransomware detector project. There are 3 distinct phases for an end-to-end run of this project

## Ransomware data collection

`ransomware/` folder contains the code to emulate ransomware lifecycles and collect the behavioral data for the same. More in README.md within this directory.

## Benigneare data collection

`benignware/` contains a few benign workloads that we use to test our detector accuracy. This also needs to run with data collection with steps in the README.md within benignware subfolder.

## ML Pipeline

`detector_framework` outlines the detector design and the steps to consume the above data and provide detector accuracy results are outlined in the README.md within this directory.

### Note

Not all files and folders are used, and clean up work in ongoing.

## Environment Setup

NOTE: Our experiments utilize a 3-node setup on Cloudlab. Using cloudlab allows a SSO login across the three nodes where the storage are shared i.e. file updates from one node is visible across the other node. If this is not the case, then the scripts will change significantly and we would recommend using the pre-collected data to test the ML pipeline only

We expect each node to run `./node-setup.sh` followed by specific scripts below

1. node-0: It is treated as the compromised client end point and hence needs to be setup using `nfs/setup-nfs-client.sh`
2. node-1: It is treated as a remote storage server and needs to be setup using `nfs/setup-nfs-server.sh`
3. node-2: It is treated as attacker controlled SFTP server and needs to be setup using `nfs/setup-attacker-server.sh`

Apart from the ransomware, node-0 is used for photoprism server (media server bengign workload), and node-1 is used as workload generator client.
