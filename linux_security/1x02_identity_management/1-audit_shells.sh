#!/bin/bash
awk -F: '$3 < 1000 && $1 != "root" && $7 ~ /(bash|sh)$/ {print $1}' $1