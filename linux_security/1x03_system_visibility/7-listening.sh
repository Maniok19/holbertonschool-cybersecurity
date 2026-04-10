#!/bin/bash
ss -lnt4 | awk 'NR>1{print $4}' |awk -F: '{print $NF}' | sort -n