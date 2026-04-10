#!/bin/bash
ps | awk '{print $1" "$4}'
# -eo