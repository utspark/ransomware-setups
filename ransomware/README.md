# Ransomware Simulator

This is a academic ransomware emulator that provides a first step into emulation of tools and techniques used by ransomware families to allow a safe behavioral analysis. This is very loosely based on CryptSky[https://github.com/deadPix3l/CryptSky/tree/master] but been modified heavily to add more functionality and lifecycle-ness for ransomware programs.

This emulation depends on PyCryptodome and a few other python utilities that can be installed by running `pip install -r requirements.txt`

The ransomware has three distinct lifecycle stages modeled for reconnaisance, exfiltration and execution.

## Reconnaissance

In recon stage, the attack models looking for network, system and storage for the victim machine.

1. `recon_net.sh`: Network looks into IP addresses, local network range, scans available IPs using nmap, open TCP and UDP ports and other information using ngrok, netstat, arp and firewall status.
2. `recon_system.sh`: It find the system information like OS, kernel version, hardware architectures, PCIe devices, hardware acceleration, installed and running packages and services.
3. `recon_mount.sh`: This script scans mount points for connected drives, looks for the files and directories in them and also looks into recently used/modified files to find latest sensitive files and avoid honeypot files.

## Exfiltration

In exfiltrate stage, the attack attempts to copy "sensitive data" out of the client server to  attacker controlled storages. In doing so they may or maynot compress this data before copy. We use `rclone` as the copy-out tool since it is the predominant tool used by real ransomware campaigns.

We allow multiple modes in exfiltration based on our studies:
1. Remote Store: AWS-S3 Buckets or SFTP Server
2. Compress Engines: Gzip, zStd or None
3. Parallel compress and copy threads: T (tested with 1 and 8)

For rclone to SFTP server, we need an attacker controlled server node which is also running a `rclone` server side program that can be initialized by running `nfs/setup-attacker-server.sh`. This sets up a server with the client-side configuration already setup via `nfs/rclone_conf` that is copied appropriately by `nfs/setup-nfs-client.sh`.

For rclone to use AWS S3, one would need to setup an S3 bucket to allow anonymous push and configure `rclone_conf` with the S3 before running `nfs/setup-nfs-client.sh` or set it up via `rclone config` command. Out of abundance of caution regarding the risk of publishing anonymous buckets, we do not provide this option and let the user handle it.

## Execution

We have a execute engine that can encrypt all the files using a user configured algorithm with various key length sizes. It uses x25519 to generate new AES keys for each file and encrypt them. It also appends the encrypted keys at the end of each file and uses them during decryption process. Optionally, it can also append an extention to each encrypted file.

To write encrypted blocks back to the file we have 3 write modes: Overwrite (O), encrypts blocks and overwrites them as we read the file; Write-After (WA) deletes the original file and writes it to a new file with same name after the delete; Write-Before (WB) writes the encrypted block to a new file with same name before it deletes the original file.

The encryption login takes the following parameters:
```
-d, --decrypt : Run decryption stage
-sym, --symmetric   : Crypto algorithms to use, Options [AES, Salsa20, ChaCha20]
-m, --mode    : AES mode to use, to be used with -a AES. Options [ECB, CBC, CTR, OFB, CFB]
-asym, --asymmetric : Key Generation Algorigthm x25519
-k, --key-leng : Symmetric key length. options [128, 256]
-w, --write   : Write method. options [O, WA, WB]
-d, --dir     : Path to the directory to encrypt
-e, --extension : Add custom (.oransom) extension to encrypted files
```

command to generate base x25519 key to be used in payload.py and decryptor.py
```
openssl genpkey -algorithm X25519 -out x25519_priv.pem
openssl pkey -in x25519_priv.pem -pubout -out x25519_pub.pem
```
Hexvalues:
`EMBEDDED_PRIV = openssl pkey -in x25519_priv.pem -outform DER | tail -c 32 | hexdump -ve '1/1 "%.2x"'`
`EMBEDDED_PUB = openssl pkey -in x25519_priv.pem -pubout -outform DER | tail -c 32 | hexdump -ve '1/1 "%.2x"'`

## Run ransomware workloads for data-collection

Each ransomware stage can have different phases, corresponding to tactics employed by attackers; e.g. exfiltration can have compression phase different from copy out phase. To separate out our dataset, we employ a method for the ransomware process to inspect an external process file-descriptors and use obscure syscall to write data at phase transitions. These syscalls are used post-data-collection to separate out different phases. Similarly, for network event, we send a predefined network packet and for hardware counters, we simply insert a phase marker in the output files.

To utilize the syscall phase transition markers, we use the `./marker.py` from within the ransomware, while the `fd_target.py` is the external process being written to. This requires us to disable kernel yama ptrace_scope restrictions using 
`sudo sysctl -w kernel.yama.ptrace_scope=0`. This is only required for data-collection and training the models.

Finally, we have 3 run scripts in `/ransomware/src/instrumentation` that call the ransomware phase modeling scripts in `/ransomware/src/python`: `monitor_network_lifecycle.sh`, `monitor_syscall_lifecycle.sh` and `monitor_hardware_lifecycle.sh`. Each of these require which phase we want to collect the data for (RECON, EXFIL or EXEC) as an argument.
To run all phases for all sources:
```
$ ./monitor_syscall_lifecycle.sh RECON >> logs 2>&1
$ ./monitor_syscall_lifecycle.sh EXFIL >> logs 2>&1
$ ./monitor_syscall_lifecycle.sh EXEC >> logs 2>&1
$ ./monitor_network_lifecycle.sh RECON >> logs 2>&1
$ ./monitor_network_lifecycle.sh EXFIL >> logs 2>&1
$ ./monitor_network_lifecycle.sh EXEC >> logs 2>&1
$ ./monitor_hardware_lifecycle.sh RECON >> logs 2>&1
$ ./monitor_hardware_lifecycle.sh EXFIL >> logs 2>&1
$ ./monitor_hardware_lifecycle.sh EXEC >> logs 2>&1
```

## Post process data for ML pipeline

`ransomware/plots` has scripts that processes these data into different ransomware lifecycle stage phases and puts them in a format that is ingestable by the ML pipeline.

Currently, the post processor is in a python notebook format with different cells processing network, syscall and hardware metrics appropriately in `ransomware_split_phases.ipynb`.

Finally, the parsed outputs need to be moved to `data/results` for ML inference scripts.
The format is not automated and requires manual renaming of folder structures. `output/syscall` folders are moved into `data/results/ransomware_data/ftrace_results`. Similarly, netcall and hardware are moved to `net_results` and `perf_results` respectively. Finally, we only move the `_parsed` directories for `out_exec` and `out_exfil` while we move the non parsed folder for `out_recon`