#!/bin/bash
awk -F: '$3 < 1000 && $1 != "root" {
if ($7 ~ /sh/ || $7 ~ /bash/)
    print $1
}' $1