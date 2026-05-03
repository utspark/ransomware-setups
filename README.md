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
