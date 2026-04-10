#!/bin/bash
ps -eo pid,command | awk '{print $1" "$2}'
