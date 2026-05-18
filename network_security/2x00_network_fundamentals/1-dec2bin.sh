#!/bin/bash
echo "obase=2; $1" | bc | xargs printf "%08d"
