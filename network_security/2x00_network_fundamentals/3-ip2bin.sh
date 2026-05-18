#!/bin/bash
IFS=. read a b c d <<< "$1"; printf "%08d %08d %08d %08d\n" $(echo "obase=2;$a;$b;$c;$d" | bc)