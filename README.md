# Ransomware Setups

## 1. NFS Server Setup


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
