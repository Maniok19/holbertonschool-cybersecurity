#!/bin/bash
lsof -i :"$1" -sTCP:LISTEN | awk '{print $1}' | ps -o user= | awk 'NR>2{print $0}' -p