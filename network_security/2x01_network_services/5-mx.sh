#!/bin/bash
dig +short "$1" MX | sort -n | awk '{print $1 " " $2}' | sed 's/\.$//'
