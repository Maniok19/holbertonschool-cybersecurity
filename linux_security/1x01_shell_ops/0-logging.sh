#!/bin/bash
exec 2>&1>&2>$1 ; echo "Starting Task" ; echo "Doing Work" ; echo "Error: Work Failed"