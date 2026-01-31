# Detector Framework

Welcome to the **Detector Framework documentation**.

## Key Features

*   Data Processing
*   Local Detector
*   Global Detector
*   Cross-Layer Detector

## Quick Start

### 1.) Correct syscall data if necessary
1. Move to `detector_framework/data_processing/` and set `DATA_DIR` variable of `strace_processor.py` file to directory holding raw ftrace files.
2. Execute `strace_processor.py` and it will output new ftrace files with "_ints.txt" extension. Place output files into `detector_framework/../data/syscall_bucket/`

### 2.) Ensure data is placed in the correct directory

    detector_framework/data/hpc_bucket/
    detector_framework/data/network_bucket/
    detector_framework/data/syscall_bucket/

### 3.) Analyze Local Detectors [Optional]
1. Execute `local_detector_analysis.py`

Here is some sample Python code:

```Python
print("hello world")
```

project-name/
├── src/              # Source code
├── tests/            # Unit tests
├── docs/             # Documentation
├── examples/         # Usage examples
├── requirements.txt  # Python dependencies
└── README.md        # This file
