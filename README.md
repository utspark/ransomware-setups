# Ransomware Setups

## 1. NFS Server Setup
The NFS setup requires a 2-node deployment: a server and a client machine. The scripts to setup both nodes are outlined in `nfs/setup-nfs-server.sh` and `nfs/setup-nfs-client.sh`. Our deployment assumes that the client and server have a hostname node-0.xyz and node-1.xyz respectively. Please update both scripts with appropriate hostnames.
The server setup script creates a `shared` folder in the home directory and populates it with a Linux system basic file system, and populates some data in `shared/home` directory. Please edit the data-path in the server script to populate the shared directory with your data.

The shared drive is available to the client node at `/mnt` path. Our setup assumes a unified login and hence has the same user-id/group-id combination across both nodes. If this is not the case, please update the user/group for the shared drive to the client user/group for successful read/write of files from client using the following command on the server.
`sudo chown <client user id>:<client group id> -R $HOME/shared`

## 2. Database Microservice Setup

Database microservice is a 3 container setup with a NodeJS API server, a memcached and a PostgreSQL database.
`db-app` folder covers all the necessary setup steps. DB App is populated using TPC-H data and relies on tpch-dbgen project submodule. Hence it is necessary to clone this repository with all its submodules for the following steps.

Steps:
1. `sudo apt update && sudo apt install -y npm docker containerd.io`
2. `docker compose up --build`
3. Populate the DB:
```
cd tpch/tpch-dbgen;
make;
./dbgen -s 1;
mv *.tbl ../
cd -;
cd tpch/
./load\_tpch.sh;
cd -;
```
5. Run `curl http://localhost:3000/tpch/3`
