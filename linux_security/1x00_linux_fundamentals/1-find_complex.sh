#!/bin/bash
find "$1" -type f -size +1M -mtime -7 ! -name "*.gz" 2>dev/null