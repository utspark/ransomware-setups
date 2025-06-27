#!/bin/bash

# Set up container and database details
CONTAINER=db-app-ransom-db-1
DB=app_db
USER=postgres
REMOTE_PATH=/tmp/tpch_data

echo "📦 Copying .tbl files into container..."
docker exec "$CONTAINER" mkdir -p "$REMOTE_PATH"
for tbl in customer lineitem nation orders partsupp part region supplier; do
  docker cp "./${tbl}.tbl" "$CONTAINER:$REMOTE_PATH/${tbl}.tbl"
done

echo "🧱 Creating tables in PostgreSQL..."
docker exec -i "$CONTAINER" psql -U "$USER" -d "$DB" <<EOF

DROP TABLE IF EXISTS lineitem, orders, customer, partsupp, part, supplier, nation, region CASCADE;

CREATE TABLE customer (
  c_custkey     INTEGER PRIMARY KEY,
  c_name        TEXT,
  c_address     TEXT,
  c_nationkey   INTEGER,
  c_phone       TEXT,
  c_acctbal     DECIMAL,
  c_mktsegment  TEXT,
  c_comment     TEXT
);

CREATE TABLE lineitem (
  l_orderkey    INTEGER,
  l_partkey     INTEGER,
  l_suppkey     INTEGER,
  l_linenumber  INTEGER,
  l_quantity    DECIMAL,
  l_extendedprice DECIMAL,
  l_discount    DECIMAL,
  l_tax         DECIMAL,
  l_returnflag  TEXT,
  l_linestatus  TEXT,
  l_shipdate    DATE,
  l_commitdate  DATE,
  l_receiptdate DATE,
  l_shipinstruct TEXT,
  l_shipmode     TEXT,
  l_comment      TEXT
);

CREATE TABLE nation (
  n_nationkey  INTEGER PRIMARY KEY,
  n_name       TEXT,
  n_regionkey  INTEGER,
  n_comment    TEXT
);

CREATE TABLE orders (
  o_orderkey       INTEGER PRIMARY KEY,
  o_custkey        INTEGER,
  o_orderstatus    TEXT,
  o_totalprice     DECIMAL,
  o_orderdate      DATE,
  o_orderpriority  TEXT,
  o_clerk          TEXT,
  o_shippriority   INTEGER,
  o_comment        TEXT
);

CREATE TABLE partsupp (
  ps_partkey     INTEGER,
  ps_suppkey     INTEGER,
  ps_availqty    INTEGER,
  ps_supplycost  DECIMAL,
  ps_comment     TEXT
);

CREATE TABLE part (
  p_partkey     INTEGER PRIMARY KEY,
  p_name        TEXT,
  p_mfgr        TEXT,
  p_brand       TEXT,
  p_type        TEXT,
  p_size        INTEGER,
  p_container   TEXT,
  p_retailprice DECIMAL,
  p_comment     TEXT
);

CREATE TABLE region (
  r_regionkey  INTEGER PRIMARY KEY,
  r_name       TEXT,
  r_comment    TEXT
);

CREATE TABLE supplier (
  s_suppkey   INTEGER PRIMARY KEY,
  s_name      TEXT,
  s_address   TEXT,
  s_nationkey INTEGER,
  s_phone     TEXT,
  s_acctbal   DECIMAL,
  s_comment   TEXT
);
EOF

echo "📥 Importing data into PostgreSQL..."
docker exec -i "$CONTAINER" psql -U "$USER" -d "$DB" <<EOF
COPY customer  FROM '$REMOTE_PATH/customer.tbl'  WITH (FORMAT csv, DELIMITER '|');
COPY lineitem  FROM '$REMOTE_PATH/lineitem.tbl'  WITH (FORMAT csv, DELIMITER '|');
COPY nation    FROM '$REMOTE_PATH/nation.tbl'    WITH (FORMAT csv, DELIMITER '|');
COPY orders    FROM '$REMOTE_PATH/orders.tbl'    WITH (FORMAT csv, DELIMITER '|');
COPY partsupp  FROM '$REMOTE_PATH/partsupp.tbl'  WITH (FORMAT csv, DELIMITER '|');
COPY part      FROM '$REMOTE_PATH/part.tbl'      WITH (FORMAT csv, DELIMITER '|');
COPY region    FROM '$REMOTE_PATH/region.tbl'    WITH (FORMAT csv, DELIMITER '|');
COPY supplier  FROM '$REMOTE_PATH/supplier.tbl'  WITH (FORMAT csv, DELIMITER '|');
EOF

echo "✅ Done. Example: Check row count with"
echo "docker exec -it $CONTAINER psql -U $USER -d $DB -c 'SELECT COUNT(*) FROM customer;'"

