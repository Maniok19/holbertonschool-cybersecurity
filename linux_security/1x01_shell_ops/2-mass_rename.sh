#!/bin/bash
find $1 -maxdepth 1 -name '*.log' -type f | xargs -I {} mv {} {}.old