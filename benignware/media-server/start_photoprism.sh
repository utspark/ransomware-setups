#!/bin/bash

echo "" > token
photoprism start > logs 2>&1 &
sleep 10
./get_api.py -l > token

echo "Photoprism started and logged in"