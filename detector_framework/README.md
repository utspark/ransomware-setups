# Detector Framework

Welcome to the **Detector Framework documentation**.

## Key Features

*   Data Processing
*   Local Detector
*   Global Detector
*   Cross-Layer Detector

## Quick Start

### 1.) Process Dataset and Correct syscall data if necessary
1. To download and setup the dataset execute `setup_data.sh` under `data/` directory.
2. [Optional] Move to `detector_framework/data_processing/` and execute `python strace_processor.py <PATH>` with the path to the file holding raw ftrace files. Do this if you need to process individually collected new syscall traces.
3. Execute `process_results.sh` to create appropriate `_bucket` folders under `detector_framework/data`.
4. If you face python module errors, import appropriate modules using `pip install` or run the `requirements.txt` file on the top level folder. Min python > 3.10.

```Bash
cd data/
./setup_data.sh
./process_results.sh
cd -
```

### 2.) Ensure data is placed in the correct directory

    detector_framework/data/hpc_bucket/
    detector_framework/data/network_bucket/
    detector_framework/data/syscall_bucket/

### 3.) Analyze Local Detectors [Optional]
1. Execute `local_detector_analysis.py` from the top level folder.

```Python
pip install -r requirements.txt
python -m detector_framework.local_detector.local_detector_run
```

project-name/
├── src/              # Source code
├── tests/            # Unit tests
├── docs/             # Documentation
├── examples/         # Usage examples
├── requirements.txt  # Python dependencies
└── README.md        # This file
