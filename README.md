# Ransomware Setups

## 1. NFS Server Setup
1. Install the NFS server package on storage server: `sudo apt install nfs-kernel-server`
2. Export directory:
```
sudo mkdir -p /srv/nfs/shared
sudo chown nobody:nogroup /srv/nfs/shared
```
3. Add to /etc/exports: `/srv/nfs/shared <client-ip>(rw,sync,no_subtree_check)`
4. Restart service: `sudo systemctl restart nfs-kernel-server`
5. Install nfs-client on client server: `sudo apt install nfs-common`
6. Mount exported directory: `sudo mount <server-ip>:/srv/nfs/shared /mnt`

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
