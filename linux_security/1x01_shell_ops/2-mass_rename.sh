#!/bin/bash
find $1 -name '*.log' -type f | xargs -I {} mv {} {}.old