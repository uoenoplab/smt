#!/bin/bash

./simple_client --proto smt -a noble1 -p 2000 -l 1420 -n 1
./simple_client --proto smt -a noble1 -p 2000 -l $((1420-13-16)) -n 1
./simple_client --proto smt -a noble1 -p 2000 -l $((1500-20-56-13-16)) -n 1
./simple_client --proto smt -a noble1 -p 2000 -l $((1500-20-56-13)) -n 1
./simple_client --proto smt -a noble1 -p 2000 -l $((1500-20-56-13-10)) -n 1
./simple_client --proto smt -a noble1 -p 2000 -l $((64)) -n 1

